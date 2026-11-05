#!/usr/bin/env python3
"""
cora_sentinel.blocklist_store - pinned, reviewed blocklist updates. Stdlib only.

THE RULE: an upstream change never reaches the active list on its own.

    sources.json (you edit)          lock.json (pins; written only by `accept`)
          │                                  │
    pull ─┴─► fetch (https only, size/time limits) ─► validate ─► same sha256 as the pin?
                                                          │             yes: unchanged (active repaired if tampered)
                                                          └─ no ─► STAGED (never active)
    diff   ─► what would change: added / removed entries, and red flags
    accept ─► you retype the first 12 hex chars of the staged file's sha256 (so you approve exactly what
              you reviewed); then it becomes active and the pin moves. Red flags need --allow-large-change.
    verify ─► every active file must hash to its pin; the daemon refuses to start otherwise.

What this protects against: a silently changed or compromised upstream, a man in the middle (TLS is verified
and redirects may not leave https), a list that suddenly blocks your LAN or that is emptied (flagged), oversized
or never-ending responses (hard limits), and tampering with the files at rest (verify, and the daemon fails
closed). It does NOT protect against a change that looks reasonable and is not (that is the human review), a
malicious FIRST fetch (review it), or a compromised root (root can edit the lock). There are no signatures:
the standard library has no ed25519 or GPG.

Prefer URLs pinned to a commit SHA: https://raw.githubusercontent.com/OWNER/REPO/<40-hex>/path never changes
under you, so "updating" means bumping the commit in sources.json, which is itself a reviewed edit.

Exit codes of `pull`: 0 nothing to review, 10 changes are staged and await review, 1 an error occurred.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from cora_sentinel import __version__
from cora_sentinel.blocklist import Blocklist

NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}", re.ASCII)
SHA_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
HARD_MAX_BYTES = 50 * 1024 * 1024            # the parser's own per-file cap
MAX_LINES = 500_000
MAX_LINE_CHARS = 4096
MAX_ENTRIES = 200_000
FETCH_TIMEOUT_S = 20.0                       # per socket operation
TOTAL_DEADLINE_S = 60.0                      # for the whole download (a trickling server cannot hold us)
MAX_REDIRECTS = 3
STALE_DAYS = 30
LARGE_CHANGE_PCT = 50
SHA_MIN_PREFIX = 12
EXIT_OK, EXIT_ERROR, EXIT_STAGED = 0, 1, 10

# addresses a tracker/rogue list has no business blocking: your own network
LAN = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")]
BLOCKING_FLAGS = {"LARGE CHANGE", "SHRINK", "EMPTIED", "LAN", "REJECTS UP", "URL CHANGED"}


class StoreError(Exception):
    pass


class FetchError(StoreError):
    pass


# --------------------------------------------------------------------------
# sources, lock, store layout
# --------------------------------------------------------------------------
def default_dir() -> Path:
    env = os.environ.get("CORA_BLOCKLIST_DIR")
    if env:
        return Path(env)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/cora-sentinel/blocklists")
    return Path.home() / ".local" / "share" / "cora-sentinel" / "blocklists"


def mutable_ref_warning(url: str) -> Optional[str]:
    """A GitHub raw/blob URL whose ref is not a 40-hex commit can change under you."""
    p = urllib.parse.urlsplit(url)
    parts = [x for x in p.path.split("/") if x]
    ref = None
    if p.netloc == "raw.githubusercontent.com" and len(parts) >= 4:
        ref = parts[2]
    elif p.netloc == "github.com" and len(parts) >= 5 and parts[2] in ("raw", "blob"):
        ref = parts[3]
    if ref is not None and not COMMIT_RE.fullmatch(ref):
        return (f"{url} uses the mutable ref {ref!r}: the content can change without this URL changing. "
                f"Pin a 40-hex commit instead.")
    return None


def load_sources(path: Path) -> Dict[str, dict]:
    try:
        raw = json.loads(Path(path).read_text())
    except OSError as e:
        raise StoreError(f"cannot read {path}: {e.strerror}") from None
    except ValueError as e:
        raise StoreError(f"{path} is not valid JSON: {e}") from None
    if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("lists"), dict):
        raise StoreError(f"{path}: expected {{\"version\": 1, \"lists\": {{...}}}}")
    out: Dict[str, dict] = {}
    for name, spec in raw["lists"].items():
        if not NAME_RE.fullmatch(name):
            raise StoreError(f"list name {name!r}: must match {NAME_RE.pattern}")
        if not isinstance(spec, dict) or set(spec) - {"url", "max_bytes"} or "url" not in spec:
            raise StoreError(f"list {name!r}: allowed keys are url (required) and max_bytes")
        url = spec["url"]
        if not isinstance(url, str) or urllib.parse.urlsplit(url).scheme != "https":
            raise StoreError(f"list {name!r}: url must be https://")
        if any(c in url for c in "<> \t\r\n"):
            raise StoreError(f"list {name!r}: url still contains a placeholder or whitespace: {url!r}")
        mb = spec.get("max_bytes", DEFAULT_MAX_BYTES)
        if not isinstance(mb, int) or isinstance(mb, bool) or not 1 <= mb <= HARD_MAX_BYTES:
            raise StoreError(f"list {name!r}: max_bytes must be 1..{HARD_MAX_BYTES}")
        out[name] = {"url": url, "max_bytes": mb}
    return out


class Store:
    """<dir>/{sources.json, lock.json, active/, staging/}. Only `accept` writes lock.json and active/."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.active, self.staging = self.root / "active", self.root / "staging"
        self.lock_path, self.sources_path = self.root / "lock.json", self.root / "sources.json"

    def ensure(self) -> None:
        for d in (self.root, self.active, self.staging):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.check_perms()

    def check_perms(self) -> None:
        """A store another local user can write is a store they can poison: refuse it."""
        euid = os.geteuid() if hasattr(os, "geteuid") else -1
        for d in (self.root, self.active, self.staging):
            if not d.exists():
                continue
            if d.is_symlink():
                raise StoreError(f"{d} is a symlink: refusing")
            st = d.stat()
            if st.st_mode & stat.S_IWOTH:
                raise StoreError(f"{d} is world-writable: refusing (chmod 700)")
            if euid == 0 and (st.st_mode & stat.S_IWGRP or st.st_uid != 0):
                raise StoreError(f"{d} must be owned by root and not group-writable when run as root")

    def lock(self) -> dict:
        if not self.lock_path.exists():
            return {"version": 1, "lists": {}}
        try:
            d = json.loads(self.lock_path.read_text())
        except ValueError as e:
            raise StoreError(f"{self.lock_path} is corrupt: {e}") from None
        if not isinstance(d, dict) or d.get("version") != 1 or not isinstance(d.get("lists"), dict):
            raise StoreError(f"{self.lock_path} has an unexpected shape")
        return d

    def save_lock(self, lock: dict) -> None:
        atomic_write(self.lock_path, (json.dumps(lock, indent=2, sort_keys=True) + "\n").encode())

    def path(self, kind: str, name: str) -> Path:
        if not NAME_RE.fullmatch(name):
            raise StoreError(f"bad list name {name!r}")
        return (self.active if kind == "active" else self.staging) / f"{name}.txt"


def atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    """Write-then-rename, so a crash or a failed fetch never leaves a half-written file where a list was."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    with contextlib.suppress(OSError):
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# fetching: https only, bounded in size and in time
# --------------------------------------------------------------------------
class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError(f"refusing a redirect to a non-https URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url: str, max_bytes: int = DEFAULT_MAX_BYTES, timeout: float = FETCH_TIMEOUT_S,
              deadline_s: float = TOTAL_DEADLINE_S, context: Optional[ssl.SSLContext] = None) -> bytes:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise FetchError(f"{url}: only https is allowed")
    opener = urllib.request.build_opener(
        _HttpsOnlyRedirects, urllib.request.HTTPSHandler(context=context or ssl.create_default_context()))
    req = urllib.request.Request(url, headers={"User-Agent": f"cora-sentinel/{__version__}",
                                               "Accept": "text/plain, */*;q=0.1", "Accept-Encoding": "identity"})
    start, chunks, total = time.monotonic(), [], 0
    try:
        with opener.open(req, timeout=timeout) as r:
            if r.status != 200:
                raise FetchError(f"{url}: HTTP {r.status}")
            cl = r.headers.get("Content-Length")
            if cl and cl.isdigit() and int(cl) > max_bytes:
                raise FetchError(f"{url}: Content-Length {cl} exceeds the {max_bytes}-byte limit")
            while True:
                if time.monotonic() - start > deadline_s:
                    raise FetchError(f"{url}: exceeded the {deadline_s:.0f} s total deadline")
                chunk = r.read1(65536)          # one underlying read: a trickle cannot block this loop
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"{url}: exceeds the {max_bytes}-byte limit (aborted)")
                chunks.append(chunk)
    except FetchError:
        raise
    except urllib.error.HTTPError as e:                     # before URLError: it is a subclass of it
        raise FetchError(f"{url}: HTTP {e.code} {e.reason}") from None
    except (urllib.error.URLError, OSError, ssl.SSLError, http.client.HTTPException) as e:
        raise FetchError(f"{url}: {getattr(e, 'reason', e)}") from None
    return b"".join(chunks)


def validate_text(data: bytes) -> str:
    """What may be in a list. The hash is of the exact bytes; this only decides if they are acceptable."""
    if b"\0" in data:
        raise StoreError("contains a NUL byte: not a text list")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise StoreError("is not valid UTF-8") from None
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise StoreError(f"has {len(lines)} lines (limit {MAX_LINES})")
    if any(len(l) > MAX_LINE_CHARS for l in lines):
        raise StoreError(f"has a line longer than {MAX_LINE_CHARS} characters")
    return text


# --------------------------------------------------------------------------
# what would change, and what looks wrong
# --------------------------------------------------------------------------
@dataclass
class Diff:
    old_entries: int = 0
    new_entries: int = 0
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    rejects_old: int = 0
    rejects_new: int = 0
    flags: List[str] = field(default_factory=list)

    @property
    def blocking(self) -> List[str]:
        return [f for f in self.flags if f in BLOCKING_FLAGS]


def _parse(text: Optional[str]) -> Tuple[set, int]:
    if text is None:
        return set(), 0
    bl = Blocklist()
    for line in text.splitlines():
        bl.add_line(line, "x")
    doms, nets = bl.entries()
    return {f"domain:{d}" for d in doms} | {f"net:{n}" for n in nets}, sum(bl.rejects.values())


def analyze(old: Optional[str], new: str) -> Diff:
    o, ro = _parse(old)
    n, rn = _parse(new)
    d = Diff(len(o), len(n), sorted(n - o), sorted(o - n), ro, rn)
    if old is None:
        d.flags.append("NEW LIST")
    else:
        changed = len(d.added) + len(d.removed)
        if o and changed * 100 > LARGE_CHANGE_PCT * len(o):
            d.flags.append("LARGE CHANGE")
        if o and len(n) == 0:
            d.flags.append("EMPTIED")                 # an emptied list silently disables detection
        elif o and len(n) * 2 <= len(o):
            d.flags.append("SHRINK")
        if rn > ro + 10 and rn >= 2 * max(ro, 1):
            d.flags.append("REJECTS UP")               # a list full of malformed or over-broad entries
    for e in d.added:
        if e.startswith("net:") and any(ipaddress.ip_network(e[4:], strict=False).overlaps(l) for l in LAN):
            d.flags.append("LAN")                     # a list that starts blocking your own network
            break
    if len(n) > MAX_ENTRIES:
        d.flags.append("TOO MANY ENTRIES")
    return d


# --------------------------------------------------------------------------
# the operations
# --------------------------------------------------------------------------
@dataclass
class Result:
    name: str
    status: str            # unchanged | repaired | staged | error
    detail: str = ""


def pull(store: Store, sources: Dict[str, dict], fetch: Optional[Callable] = None,
         only: Optional[str] = None, context: Optional[ssl.SSLContext] = None) -> List[Result]:
    fetch = fetch or fetch_url                       # looked up at call time, so it can be substituted
    store.ensure()
    lock = store.lock()
    results: List[Result] = []
    for name, spec in sources.items():
        if only and name != only:
            continue
        try:
            kw = {"context": context} if context is not None else {}
            data = fetch(spec["url"], spec["max_bytes"], **kw)
            text = validate_text(data)
            h = sha256(data)
            if len(_parse(text)[0]) > MAX_ENTRIES:
                raise StoreError(f"has more than {MAX_ENTRIES} entries")
            pin = lock["lists"].get(name)
            if pin and pin["sha256"] == h and pin["url"] == spec["url"]:
                act = store.path("active", name)
                if act.exists() and sha256(act.read_bytes()) == h:
                    results.append(Result(name, "unchanged", f"matches the pin {h[:12]}"))
                else:
                    atomic_write(act, data)           # the upstream bytes ARE the approved bytes: safe to restore
                    results.append(Result(name, "repaired", "active file did not match its pin; restored"))
                continue
            atomic_write(store.path("staging", name), data)
            meta = {"url": spec["url"], "sha256": h, "bytes": len(data),
                    "fetched": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            atomic_write(store.staging / f"{name}.json", (json.dumps(meta, indent=2) + "\n").encode())
            why = "new list" if not pin else ("URL changed" if pin["url"] != spec["url"] else "content changed")
            results.append(Result(name, "staged", f"{why}; sha256 {h[:12]}"))
        except StoreError as e:
            results.append(Result(name, "error", str(e)))
    return results


def _staged(store: Store, name: str) -> Tuple[bytes, dict]:
    p, m = store.path("staging", name), store.staging / f"{name}.json"
    if not p.exists() or not m.exists():
        raise StoreError(f"nothing is staged for {name!r}")
    return p.read_bytes(), json.loads(m.read_text())


def review(store: Store, name: str) -> Tuple[Diff, dict, str]:
    data, meta = _staged(store, name)
    if sha256(data) != meta["sha256"]:
        raise StoreError(f"the staged file for {name!r} does not match its recorded hash: discard and pull again")
    act = store.path("active", name)
    old = act.read_text() if act.exists() else None
    d = analyze(old, validate_text(data))
    pin = store.lock()["lists"].get(name)
    if pin and pin["url"] != meta["url"]:
        d.flags.append("URL CHANGED")
    return d, meta, meta["sha256"]


def accept(store: Store, name: str, sha_prefix: str, allow_large_change: bool = False,
           today: Optional[str] = None) -> None:
    d, meta, full = review(store, name)
    prefix = sha_prefix.lower()
    if len(prefix) < SHA_MIN_PREFIX or not full.startswith(prefix):
        raise StoreError(f"the sha256 you gave does not match the staged file ({full[:SHA_MIN_PREFIX]}...): "
                         f"it changed since you reviewed it, or you mistyped it")
    if d.blocking and not allow_large_change:
        raise StoreError(f"refusing: {', '.join(d.blocking)}. Review with `cora-blocklist diff {name}`; "
                         f"if it is right, pass --allow-large-change")
    data, _ = _staged(store, name)
    atomic_write(store.path("active", name), data)           # 1. the file ...
    lock = store.lock()
    lock["lists"][name] = {"url": meta["url"], "sha256": full, "bytes": meta["bytes"],
                           "entries": d.new_entries,
                           "approved": today or datetime.now(timezone.utc).date().isoformat()}
    store.save_lock(lock)                                     # 2. ... then the pin ...
    for p in (store.path("staging", name), store.staging / f"{name}.json"):
        with contextlib.suppress(OSError):                    # 3. ... then the staging (a crash before this
            os.unlink(p)                                      #    leaves the work re-runnable, not lost)


def verify(store: Store) -> List[str]:
    """Problems that make the active lists untrustworthy. Empty means every active file hashes to its pin."""
    problems: List[str] = []
    try:
        store.check_perms()
    except StoreError as e:
        problems.append(str(e))
    lock = store.lock()
    for name, pin in sorted(lock["lists"].items()):
        p = store.path("active", name)
        if not p.exists():
            problems.append(f"{name}: pinned but the active file is missing")
        elif sha256(p.read_bytes()) != pin["sha256"]:
            problems.append(f"{name}: the active file does not match its pin (modified after approval?)")
    if store.active.exists():
        for f in sorted(store.active.glob("*.txt")):
            if f.stem not in lock["lists"]:
                problems.append(f"{f.stem}: an active file with no pin")
    return problems


def load_verified(root: Path, into: Blocklist) -> List[str]:
    """For the daemon: refuse (StoreError) unless every active list is exactly what was approved.
    Returns warnings (stale lists), which are not fatal."""
    store = Store(root)
    if not store.root.exists():
        raise StoreError(f"blocklist store {root} does not exist")
    problems = verify(store)
    if problems:
        raise StoreError("blocklist store failed verification, refusing to run on lists nobody approved:\n  "
                         + "\n  ".join(problems))
    warnings = []
    today = datetime.now(timezone.utc).date()
    for name, pin in sorted(store.lock()["lists"].items()):
        into.load_file(store.path("active", name), name)
        try:
            age = (today - datetime.fromisoformat(pin["approved"]).date()).days
            if age > STALE_DAYS:
                warnings.append(f"{name}: approved {age} days ago (more than {STALE_DAYS}); run `cora-blocklist pull`")
        except (KeyError, ValueError):
            pass
    return warnings


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _print_diff(name: str, d: Diff, meta: dict) -> None:
    print(f"{name}: {d.old_entries} -> {d.new_entries} entries  (+{len(d.added)} / -{len(d.removed)})"
          f"   rejected lines {d.rejects_old} -> {d.rejects_new}   sha256 {meta['sha256'][:SHA_MIN_PREFIX]}")
    if d.flags:
        print(f"  FLAGS: {', '.join(d.flags)}" + ("   (blocks accept without --allow-large-change)" if d.blocking else ""))
    for label, items in (("added", d.added), ("removed", d.removed)):
        for e in items[:10]:
            print(f"  {'+' if label == 'added' else '-'} {e}")
        if len(items) > 10:
            print(f"  ... {len(items) - 10} more {label}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="cora-blocklist", description="pinned, reviewed blocklist updates")
    ap.add_argument("--dir", type=Path, default=None, help=f"store directory (default {default_dir()})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pull", help="fetch every source; stage what changed (never touches active lists)")
    p.add_argument("--only")
    p.add_argument("--sources", type=Path)
    sub.add_parser("status", help="pinned, active, and staged state of every list")
    d = sub.add_parser("diff", help="review a staged update")
    d.add_argument("name", nargs="?")
    a = sub.add_parser("accept", help="approve a staged update (retype the first 12 hex of its sha256)")
    a.add_argument("name")
    a.add_argument("--sha256", required=True)
    a.add_argument("--allow-large-change", action="store_true")
    sub.add_parser("verify", help="check every active list against its pin")
    args = ap.parse_args(argv)

    store = Store(args.dir or default_dir())
    try:
        if args.cmd == "pull":
            sources = load_sources(args.sources or store.sources_path)
            for n, s in sources.items():
                w = mutable_ref_warning(s["url"])
                if w:
                    print(f"warning: {w}", file=sys.stderr)
            results = pull(store, sources, only=args.only)
            for r in results:
                print(f"{r.name:<24} {r.status.upper():<10} {r.detail}")
            if any(r.status == "error" for r in results):
                return EXIT_ERROR
            if any(r.status == "staged" for r in results):
                print("\nchanges are STAGED, not active. Review: cora-blocklist diff   Approve: "
                      "cora-blocklist accept NAME --sha256 <first 12 hex>")
                return EXIT_STAGED
            return EXIT_OK
        if args.cmd == "diff":
            names = [args.name] if args.name else sorted(f.stem for f in store.staging.glob("*.txt")) if store.staging.exists() else []
            if not names:
                print("nothing is staged")
                return EXIT_OK
            for n in names:
                diff, meta, _ = review(store, n)
                _print_diff(n, diff, meta)
            return EXIT_OK
        if args.cmd == "accept":
            accept(store, args.name, args.sha256, args.allow_large_change)
            print(f"{args.name}: accepted and pinned. Restart cora-sentinel to use it.")
            return EXIT_OK
        if args.cmd == "verify":
            problems = verify(store)
            for pr in problems:
                print(f"PROBLEM: {pr}")
            print("OK: every active list matches its pin" if not problems else "")
            return EXIT_ERROR if problems else EXIT_OK
        if args.cmd == "status":
            lock = store.lock()
            today = datetime.now(timezone.utc).date()
            for name in sorted(set(lock["lists"]) | {f.stem for f in store.staging.glob("*.txt")} if store.staging.exists() else lock["lists"]):
                pin = lock["lists"].get(name)
                staged = store.path("staging", name).exists()
                line = f"{name:<24} "
                if pin:
                    age = (today - datetime.fromisoformat(pin["approved"]).date()).days
                    ok = store.path("active", name).exists() and sha256(store.path("active", name).read_bytes()) == pin["sha256"]
                    line += f"pinned {pin['sha256'][:12]}  {pin['entries']} entries  approved {age}d ago" \
                            f"{'  STALE' if age > STALE_DAYS else ''}  {'ok' if ok else 'ACTIVE FILE DOES NOT MATCH PIN'}"
                else:
                    line += "not pinned"
                print(line + ("   [update STAGED]" if staged else ""))
            return EXIT_OK
    except StoreError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
