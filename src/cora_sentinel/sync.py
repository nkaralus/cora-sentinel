#!/usr/bin/env python3
"""
cora_sentinel.sync - pull the community lists from cora-security, signed offline. Stdlib only.

THE RULE: a list reaches the daemon only if the owner's offline minisign key signed the manifest
that hashes it. The signature IS the approval, so this does `cora-blocklist accept`'s job for the
community lists, and writes into the same store, pinned the same way. `cora-sentinel --blocklist-store`
still verifies every active file against its pin at start and on every SIGHUP.

    ref ──► commit sha (40 hex) ──► every URL below is pinned to THAT commit (one consistent snapshot)
    MANIFEST.json + MANIFEST.json.minisig
        signature: pinned key id, BOTH signatures, trusted comment names this repo and this file
        timestamp in the trusted comment must be NEWER than the last applied one  (no replay)
    each list: fetched, sha256 == manifest, parses, within caps
    delta caps vs what is active now                                         (a signed mistake is still held)
    ──► journal ──► last-good/ snapshot ──► active files ──► lock.json (THE commit point) ──► verify ──► reload

Nothing is written until every byte of the new set has been fetched and checked, so a network drop
mid-pull changes nothing. A crash after the journal is written is undone at the next run (restore
last-good). `cora-sync rollback` puts last-good back and refuses that signature from then on.

CLI: `cora-blocklist sync` and `cora-blocklist sync-rollback`.

Exit codes: 0 in sync (applied or unchanged), 10 held for review (delta caps), 11 awaiting a valid
signature for the current manifest (normal right after compile, until the owner signs), 1 error.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cora_sentinel import blocklist_store as bs
from cora_sentinel import minisign

EXIT_OK, EXIT_ERROR, EXIT_HELD, EXIT_UNSIGNED = 0, 1, 10, 11
SOURCE_TAG = "cora-sync"
MANIFEST_SCHEMA = "cora.security.blocklist-manifest/v1"
MANIFEST_MAX = 1024 * 1024
SIG_MAX = 4096
REF_MAX = 64 * 1024
LIST_FILE_RE = re.compile(r"([a-z0-9][a-z0-9_-]{0,39})\.txt", re.ASCII)
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
TRUSTED_RE = re.compile(r"cora-manifest repo:(\S+) file:MANIFEST\.json timestamp:(\d+)")
# delta caps (a signed update can still be a mistake: hold it for a human)
MIN_BASE = 20          # percentage rules only once a list has this many entries (a 1-entry list would always trip)
LARGE_CHANGE_PCT = 50
MAX_ADDED = 500        # absolute: no single pull adds more than this to one list

Fetch = Callable[..., bytes]


class SyncError(Exception):
    def __init__(self, msg: str, code: int = EXIT_ERROR):
        super().__init__(msg)
        self.code = code


@dataclass
class Candidate:
    commit: str
    timestamp: int
    generated_from: str
    manifest_sha: str
    files: Dict[str, bytes]                       # store name -> exact bytes
    urls: Dict[str, str]
    entries: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------- inputs

def load_pubkey(path: Path) -> minisign.PublicKey:
    try:
        st = path.lstat()
    except FileNotFoundError:
        raise SyncError(f"{path}: pinned public key not found (copy it from the signing machine)") from None
    if stat.S_ISLNK(st.st_mode):
        raise SyncError(f"{path}: is a symlink, refusing")
    if st.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
        raise SyncError(f"{path}: group/world-writable, refusing (chmod 644)")
    if hasattr(os, "geteuid") and os.geteuid() == 0 and st.st_uid != 0:
        raise SyncError(f"{path}: must be owned by root")
    try:
        return minisign.load_public_key(path.read_text())
    except minisign.MinisignError as e:
        raise SyncError(f"{path}: {e}") from None


def resolve_commit(repo: str, ref: str, fetch: Fetch) -> str:
    if bs.COMMIT_RE.fullmatch(ref):
        return ref
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", ref) or ".." in ref:
        raise SyncError(f"bad ref {ref!r}")
    raw = fetch(f"https://api.github.com/repos/{repo}/git/ref/heads/{ref}", REF_MAX)
    try:
        sha = json.loads(raw)["object"]["sha"]
    except (ValueError, KeyError, TypeError):
        raise SyncError("could not read the commit for that ref from the GitHub API") from None
    if not isinstance(sha, str) or not bs.COMMIT_RE.fullmatch(sha):
        raise SyncError("GitHub API returned something that is not a commit sha")
    return sha


def parse_manifest(raw: bytes) -> dict:
    try:
        m = json.loads(raw)
    except ValueError:
        raise SyncError("MANIFEST.json is not JSON") from None
    if not isinstance(m, dict) or m.get("schema") != MANIFEST_SCHEMA or not isinstance(m.get("lists"), dict):
        raise SyncError("MANIFEST.json has an unexpected shape")
    if not isinstance(m.get("generated_from"), str):
        raise SyncError("MANIFEST.json: generated_from missing")
    for fname, meta in m["lists"].items():
        if not LIST_FILE_RE.fullmatch(fname):
            raise SyncError(f"MANIFEST.json: refusing list file name {fname!r}")
        if not isinstance(meta, dict) or not isinstance(meta.get("sha256"), str) \
                or not bs.SHA_RE.fullmatch(meta["sha256"]):
            raise SyncError(f"MANIFEST.json: {fname} has no valid sha256")
    return m


def check_signature(pub: minisign.PublicKey, manifest_raw: bytes, sig_raw: bytes, repo: str) -> int:
    try:
        sig_text = sig_raw.decode("ascii")
    except UnicodeDecodeError:
        raise SyncError("signature file is not ASCII") from None
    try:
        v = minisign.verify(pub, manifest_raw, sig_text)
    except minisign.MinisignError as e:
        if "does not match the message" in str(e):
            # the usual case right after compile: the manifest moved, the owner has not signed it yet
            raise SyncError(f"awaiting a signature for this manifest ({e})", EXIT_UNSIGNED) from None
        raise SyncError(f"bad signature: {e}") from None
    m = TRUSTED_RE.fullmatch(v.trusted_comment)
    if not m:
        raise SyncError(f"trusted comment is not a cora-manifest comment: {v.trusted_comment!r}")
    if m.group(1) != repo:
        raise SyncError(f"signature is for repo {m.group(1)!r}, not {repo!r}")
    return int(m.group(2))


def fetch_candidate(repo: str, ref: str, pub: minisign.PublicKey, fetch: Fetch) -> Candidate:
    """Everything in memory, everything checked. Raises before anything touches disk."""
    if not REPO_RE.fullmatch(repo):
        raise SyncError(f"bad repo {repo!r}")
    commit = resolve_commit(repo, ref, fetch)
    base = f"https://raw.githubusercontent.com/{repo}/{commit}/blocklists"
    manifest_raw = fetch(f"{base}/MANIFEST.json", MANIFEST_MAX)
    try:
        sig_raw = fetch(f"{base}/MANIFEST.json.minisig", SIG_MAX)
    except bs.FetchError as e:
        if "HTTP 404" in str(e):
            raise SyncError("no MANIFEST.json.minisig at this commit yet", EXIT_UNSIGNED) from None
        raise
    timestamp = check_signature(pub, manifest_raw, sig_raw, repo)
    manifest = parse_manifest(manifest_raw)
    files, urls, entries = {}, {}, {}
    for fname, meta in sorted(manifest["lists"].items()):
        url = f"{base}/{fname}"
        data = fetch(url, bs.DEFAULT_MAX_BYTES)
        if bs.sha256(data) != meta["sha256"]:
            raise SyncError(f"{fname}: sha256 does not match the signed manifest (tampered or mixed snapshot)")
        text = bs.validate_text(data)
        n = len(bs._parse(text)[0])
        if n > bs.MAX_ENTRIES:
            raise SyncError(f"{fname}: more than {bs.MAX_ENTRIES} entries")
        name = LIST_FILE_RE.fullmatch(fname).group(1)
        files[name], urls[name], entries[name] = data, url, n
    return Candidate(commit, timestamp, manifest["generated_from"], bs.sha256(manifest_raw), files, urls, entries)


# ---------------------------------------------------------------- decisions

def sync_state(lock: dict) -> dict:
    return lock.get("cora_sync") or {}


def owned(lock: dict) -> Dict[str, dict]:
    return {n: p for n, p in lock["lists"].items() if p.get("source") == SOURCE_TAG}


def check_replay(state: dict, c: Candidate) -> bool:
    """True if there is nothing new. Raises on a replayed or refused signature."""
    last = int(state.get("timestamp", 0))
    if c.timestamp in state.get("refused_timestamps", []):
        raise SyncError(f"signature timestamp {c.timestamp} was rolled back by the operator; waiting for a newer one")
    if c.timestamp == last and c.manifest_sha == state.get("manifest_sha"):
        return True
    if c.timestamp <= last:
        raise SyncError(f"replay refused: signed at {c.timestamp}, but {last} is already applied")
    if state.get("generated_from", "") not in ("", "none") and c.generated_from != "none" \
            and c.generated_from < state["generated_from"]:
        raise SyncError(f"replay refused: generated_from {c.generated_from} is older than "
                        f"{state['generated_from']}")
    return False


def delta_flags(old: Optional[str], new: Optional[str]) -> List[str]:
    if new is None:
        return ["REMOVED"] if old is not None else []
    d = bs.analyze(old, new)
    flags = [f for f in d.flags if f in {"EMPTIED", "LAN", "REJECTS UP", "TOO MANY ENTRIES"}]
    if old is not None and d.old_entries >= MIN_BASE:
        if (len(d.added) + len(d.removed)) * 100 > LARGE_CHANGE_PCT * d.old_entries:
            flags.append("LARGE CHANGE")
        if d.new_entries and d.new_entries * 2 <= d.old_entries:
            flags.append("SHRINK")
    if len(d.added) > MAX_ADDED:
        flags.append(f"BURST (+{len(d.added)})")
    return flags


def plan(store: bs.Store, c: Candidate) -> Dict[str, List[str]]:
    lock = store.lock()
    mine = owned(lock)
    for name in c.files:
        if name in lock["lists"] and name not in mine:
            raise SyncError(f"{name}: a list with this name is already pinned by `cora-blocklist`; rename one")
    flags = {}
    for name in sorted(set(c.files) | set(mine)):
        act = store.path("active", name)
        old = act.read_text() if act.exists() and name in mine else None
        new = bs.validate_text(c.files[name]) if name in c.files else None
        f = delta_flags(old, new)
        if f:
            flags[name] = f
    return flags


# ---------------------------------------------------------------- applying

def _journal(store: bs.Store) -> Path:
    return store.staging / "cora-sync.journal.json"


def _last_good(store: bs.Store) -> Path:
    return store.root / "last-good"


def snapshot_last_good(store: bs.Store) -> None:
    lg, tmp = _last_good(store), store.root / ".last-good.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(mode=0o700)
    lock = store.lock()
    for name in owned(lock):
        src = store.path("active", name)
        if src.exists():
            shutil.copy2(src, tmp / src.name)
    bs.atomic_write(tmp / "lock.json", (json.dumps(lock, indent=2, sort_keys=True) + "\n").encode())
    shutil.rmtree(lg, ignore_errors=True)
    os.replace(tmp, lg)


def restore_last_good(store: bs.Store) -> None:
    lg = _last_good(store)
    if not (lg / "lock.json").exists():
        raise SyncError("no last-good snapshot to restore")
    old_lock = json.loads((lg / "lock.json").read_text())
    cur = store.lock()
    for name in owned(cur):                                   # lists the bad set introduced
        if name not in old_lock["lists"]:
            with contextlib.suppress(OSError):
                os.unlink(store.path("active", name))
    for name in owned(old_lock):
        bs.atomic_write(store.path("active", name), (lg / f"{name}.txt").read_bytes())
    # keep pins other tools wrote since; replace only ours, and the sync state
    merged = dict(cur)
    merged["lists"] = {n: p for n, p in cur["lists"].items() if p.get("source") != SOURCE_TAG}
    merged["lists"].update(owned(old_lock))
    merged["cora_sync"] = dict(old_lock.get("cora_sync") or {},
                               refused_timestamps=sync_state(cur).get("refused_timestamps", []))
    store.save_lock(merged)


def recover(store: bs.Store, log: Callable[[str], None]) -> None:
    """Called first on every run: finish nothing half-done. A committed journal is cleared;
    an uncommitted one means a crash between files and lock: put last-good back."""
    j = _journal(store)
    if not j.exists():
        return
    want = json.loads(j.read_text()).get("files", {})
    pins = store.lock()["lists"]
    if all(pins.get(n, {}).get("sha256") == h for n, h in want.items()):
        log("recover: previous apply had committed; clearing its journal")
    else:
        log("recover: previous apply was interrupted before commit; restoring last-good")
        restore_last_good(store)
    j.unlink()


def apply(store: bs.Store, c: Candidate, today: Optional[str] = None) -> None:
    lock = store.lock()
    mine = owned(lock)
    bs.atomic_write(_journal(store), (json.dumps(
        {"commit": c.commit, "files": {n: bs.sha256(d) for n, d in c.files.items()}}) + "\n").encode())
    snapshot_last_good(store)
    for name, data in c.files.items():                        # 1. files (daemon would refuse these: no pins yet)
        bs.atomic_write(store.path("active", name), data)
    for name in set(mine) - set(c.files):                     #    lists the signed manifest dropped
        with contextlib.suppress(OSError):
            os.unlink(store.path("active", name))
        lock["lists"].pop(name, None)
    approved = today or datetime.now(timezone.utc).date().isoformat()
    for name, data in c.files.items():
        lock["lists"][name] = {"url": c.urls[name], "sha256": bs.sha256(data), "bytes": len(data),
                               "entries": c.entries[name], "approved": approved, "source": SOURCE_TAG}
    prev = sync_state(lock)
    lock["cora_sync"] = {"commit": c.commit, "timestamp": c.timestamp, "generated_from": c.generated_from,
                         "manifest_sha": c.manifest_sha,
                         "refused_timestamps": prev.get("refused_timestamps", [])}
    store.save_lock(lock)                                     # 2. THE commit point (one rename)
    problems = bs.verify(store)                               # 3. what the daemon will check, checked now
    if problems:
        restore_last_good(store)
        _journal(store).unlink()
        raise SyncError("post-apply verification failed, restored last-good: " + "; ".join(problems))
    _journal(store).unlink()


def reload_daemon(cmd: str, log: Callable[[str], None]) -> None:
    if not cmd:
        return
    try:
        r = subprocess.run(shlex.split(cmd), timeout=30, capture_output=True, text=True)
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"reload command failed ({e}); the daemon will load the new lists at its next start")
        return
    if r.returncode:
        log(f"reload command exited {r.returncode}: {r.stderr.strip()[:200]}; "
            "the daemon will load the new lists at its next start")


# ---------------------------------------------------------------- entry points

def run(store: bs.Store, repo: str, ref: str, pub: minisign.PublicKey, fetch: Optional[Fetch] = None,
        allow_large_change: bool = False, reload_cmd: str = "", dry_run: bool = False,
        log: Callable[[str], None] = lambda m: print(m, file=sys.stderr), today: Optional[str] = None) -> int:
    fetch = fetch or bs.fetch_url
    try:
        store.ensure()
        recover(store, log)
        c = fetch_candidate(repo, ref, pub, fetch)
        if check_replay(sync_state(store.lock()), c):
            log(f"unchanged: commit {c.commit[:12]}, signed {c.timestamp}")
            return EXIT_OK
        flags = plan(store, c)
        if flags and not allow_large_change:
            for name, f in flags.items():
                log(f"HELD {name}: {', '.join(f)}")
            log("held for review; rerun with --allow-large-change once you have read the change")
            return EXIT_HELD
        if dry_run:
            log(f"dry run: would apply commit {c.commit[:12]} ({', '.join(f'{n}={c.entries[n]}' for n in sorted(c.files))})")
            return EXIT_OK
        apply(store, c, today)
        log(f"applied commit {c.commit[:12]}, signed {c.timestamp}: "
            + ", ".join(f"{n}={c.entries[n]}" for n in sorted(c.files)))
        reload_daemon(reload_cmd, log)
        return EXIT_OK
    except SyncError as e:
        log(str(e))
        return e.code
    except bs.StoreError as e:                                # FetchError included: network, TLS, size, HTTP
        log(f"error, nothing changed: {e}")
        return EXIT_ERROR


def rollback(store: bs.Store, reload_cmd: str = "", log: Callable[[str], None] = print) -> int:
    try:
        state = sync_state(store.lock())
        restore_last_good(store)
        if state.get("timestamp"):
            lock = store.lock()
            s = lock.setdefault("cora_sync", {})
            s["refused_timestamps"] = sorted(set(s.get("refused_timestamps", [])) | {state["timestamp"]})
            store.save_lock(lock)
        log(f"rolled back; signature {state.get('timestamp')} will not be applied again")
        reload_daemon(reload_cmd, log)
        return EXIT_OK
    except (SyncError, bs.StoreError) as e:
        log(str(e))
        return EXIT_ERROR
