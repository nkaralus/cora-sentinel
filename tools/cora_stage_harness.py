#!/usr/bin/env python3
"""
cora_stage_harness - the back half of cora-exec's front door: a bridge Ticket becomes a staged, verified copy of the
live tree, and (only when asked) one atomic symlink swap commits it. Track D step 2.

    BASE/
      live -> .cascade/versions/<vid>        relative symlink: the ONLY mutable thing outside .cascade/
      .cascade/
        versions/v0/ ... versions/t-<id>/    complete trees, state_registry.json inside each; immutable once committed
        journal.jsonl                        write-ahead, fsynced, one JSON object per line, all tickets
        locks/subnet-<cidr>.lock, tree.lock  flock: subnet first, tree second, never the other way round
        logs/<id>.log                        the verifier's output
        HALTED                               present = every ticket refused until a person removes it

  RECEIVED ─► STAGED ─► APPLIED ─► POSTCHECKED ─┬─► PARKED ──(approve)──► COMMITTED
     copy live      registry       registry        │   (stage-only:
     version        set_bounds,    invariants,     │    the default)
     → t-<id>       file hook      unshare -n      └─► COMMITTED   (auto-commit, opt-in per subnet)
                                   verifier
  Any failure ─► ROLLED_BACK. A rollback whose result is not exactly the tree the journal says is live ─► HALTED.

Why a symlink swap: state_registry.json lives INSIDE each version, so one os.replace() of `live` commits the project
files and the registry revision together; there is no window where one is new and the other old, and nothing like
cascade-godot's COMMITTED_REGISTRY_ERROR. What cascade-godot taught and this keeps: the fsynced JSONL write-ahead
journal that tolerates a torn last line, flock locks released by the kernel when a holder dies, every unfinished
ticket rolled back before new input, decisions made from content hashes rather than from what the journal claims.

Rules
  TOCTOU      the harness reads the registry itself (live/state_registry.json); registry.revision must equal the
              ticket's registry_rev when STAGED and again, under the tree lock, right before the swap: else STALE_REV
  drift       before a swap, `live` must still be the version the ticket was staged from and its manifest unchanged,
              and the staged tree must be exactly what was verified: else DRIFT
  rollback    if `live` points at this ticket's version it is pointed back; then the live tree's SHA-256 manifest
              must be exactly what the journal says that version holds. If not: ROLLBACK_MISMATCH, HALTED, and the
              harness refuses everything (all instances, all subnets) until a person inspects it and deletes
              .cascade/HALTED. (Another subnet may legitimately have committed meanwhile, so "what the journal says"
              is that version's recorded digest, not this ticket's starting point.)
  recovery    on start, every non-terminal ticket whose subnet lock is free (its owner died: flock is released by
              the kernel) is rolled back. A PARKED ticket is kept if its version exists and its manifest matches.
  limits      one ticket in flight per subnet (flock, non-blocking: SUBNET_BUSY); one PARKED per subnet (SUBNET_BUSY
              until approved or discarded); dedup key (subnet, digest, registry_rev): the same text on a new revision
              is allowed; a ticket older than its ttl_s at admission is TICKET_EXPIRED (the TTL bounds mint-to-
              admission; once parked, STALE_REV and DRIFT are what protect it)
  verify      the configured command runs in the staged tree in a new network namespace (loopback only), inside a
              transient systemd scope with MemoryMax (default 2G, no swap), with a scrubbed environment and a wall
              timeout that kills the whole scope (every process in its cgroup, also ones that left the process group).
              The namespace comes from bwrap when it is installed (whole filesystem read-only, the stage too; private
              /tmp), else from unshare -n (loopback raised by `ip link set lo up`). Measured on Ubuntu 26.04 / kernel
              7.0 with kernel.apparmor_restrict_unprivileged_userns=1: unprivileged `unshare -n` and `unshare -U -r -n`
              are refused, `bwrap --unshare-net` is allowed (AppArmor profile bwrap-userns-restrict); root can use
              either. The scope is `systemd-run --scope` (root) or `systemd-run --user --scope` (needs the memory
              controller delegated to user@UID.service, the default). If the scope or the namespace cannot be made,
              that is VERIFY_FAIL: the verifier never runs unsandboxed or uncapped.
  tripwire    the staged tree is hashed (content, links, modes) right before the verifier starts and right after it
              ends; any difference is VERIFY_FAIL "staged tree modified by verifier", whatever the exit status.

Codes: STALE_REV DUP_TICKET STAGE_IO APPLY_FAIL POSTCHECK_FAIL VERIFY_FAIL VERIFY_TIMEOUT COMMIT_FAIL ROLLBACK_MISMATCH
DRIFT, and SUBNET_BUSY HALTED TICKET_EXPIRED NOT_BOOTSTRAPPED BAD_TICKET NOT_PARKED DISCARDED RECOVERED.

    python tools/cora_stage_harness.py bootstrap BASE          one time, offline: BASE/live (a directory) -> v0
    python tools/cora_stage_harness.py status BASE
    python tools/cora_stage_harness.py submit BASE [--auto-commit CIDR] -- VERIFY_CMD...   < model_output.txt
    python tools/cora_stage_harness.py approve|discard BASE TICKET_ID
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

import fcntl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cora_exec_bridge import AABB, Bridge, Registry, Ticket  # noqa: E402

STATES = ["RECEIVED", "STAGED", "APPLIED", "POSTCHECKED", "PARKED", "COMMITTED", "ROLLED_BACK", "HALTED"]
TERMINAL = frozenset({"COMMITTED", "ROLLED_BACK", "HALTED"})
REGISTRY_FILE = "state_registry.json"
LIVE = "live"
STATE_DIR = ".cascade"
VERSIONS = "versions"
VERIFY_TIMEOUT_S = 120.0
LOG_TAIL = 2000
VERIFY_MEMORY_MAX = "2G"
VERIFY_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/tmp"}
SCOPE_ENV = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")   # systemd-run --user needs them; the verifier does not get them
STAGE = "{stage}"                                        # replaced by the staged directory in sandbox argv
_LO_UP = ["sh", "-c", 'ip link set lo up && exec "$@"', "cora-verify"]


def default_sandbox() -> List[str]:
    """A new network namespace with only loopback: bwrap if installed (and the filesystem read-only), else unshare."""
    if shutil.which("bwrap"):
        return ["bwrap", "--unshare-net", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                "--tmpfs", "/tmp", "--tmpfs", "/run",             # /run: no session bus, no systemd sockets
                "--ro-bind", STAGE, STAGE, "--chdir", STAGE, "--"]
    if os.geteuid() == 0:
        return ["unshare", "--net", "--", *_LO_UP]
    return ["unshare", "--user", "--map-root-user", "--net", "--", *_LO_UP]


def scope_argv(unit: str, memory_max: str) -> List[str]:
    """A transient systemd scope with a hard memory cap and no swap; the command runs as this same process (exec)."""
    user = [] if os.geteuid() == 0 else ["--user"]
    return ["systemd-run", *user, "--scope", "--quiet", "--collect", f"--unit={unit}",
            "-p", f"MemoryMax={memory_max}", "-p", "MemorySwapMax=0", "--"]


def kill_scope(unit: str) -> None:
    user = [] if os.geteuid() == 0 else ["--user"]
    try:
        subprocess.run(["systemctl", *user, "kill", "--signal=SIGKILL", f"{unit}.scope"], capture_output=True, timeout=10,
                       env={**VERIFY_ENV, **{k: os.environ[k] for k in SCOPE_ENV if k in os.environ}})
    except (OSError, subprocess.TimeoutExpired):
        pass


@dataclass(frozen=True)
class Result:
    ok: bool
    code: str
    ticket_id: Optional[str] = None
    state: Optional[str] = None
    detail: str = ""


class Fail(Exception):
    """A coded failure inside a ticket's run: always ends in a rollback."""
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


class Busy(Exception):
    pass


# ---------------------------------------------------------------------------------------------- files and hashes
def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(top: Path) -> Dict[str, str]:
    """Every entry under `top`: file -> 'sha256:mode', symlink -> 'link:<target>', directory -> 'dir:mode'.
    Never follows links."""
    out: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        d = Path(dirpath)
        for name in dirnames + filenames:
            p = d / name
            rel = p.relative_to(top).as_posix()
            st = os.lstat(p)
            mode = f"{stat.S_IMODE(st.st_mode):o}"
            if stat.S_ISLNK(st.st_mode):
                out[rel] = "link:" + os.readlink(p)
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = f"dir:{mode}"
            elif stat.S_ISREG(st.st_mode):
                out[rel] = f"{sha256_file(p)}:{mode}"
            else:
                out[rel] = f"special:{stat.S_IFMT(st.st_mode):o}"
    return out


def digest(m: Mapping[str, str]) -> str:
    return hashlib.sha256(json.dumps(m, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fsync_dir(p: Path) -> None:
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_tree(top: Path) -> None:
    for dirpath, _, filenames in os.walk(top, followlinks=False):
        for name in filenames:
            p = Path(dirpath) / name
            if not os.path.islink(p):
                fd = os.open(p, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        fsync_dir(Path(dirpath))


class Journal:
    """Append-only and fsynced; a torn LAST line (a crash mid-append) is ignored, a bad line anywhere else is not."""

    def __init__(self, path: Path):
        self.path = path

    def append(self, rec: Dict[str, Any]) -> None:
        rec = {**rec, "ts": time.time()}
        line = (json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n").encode()
        new = not self.path.exists()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        if new:
            fsync_dir(self.path.parent)

    def read(self) -> List[Dict[str, Any]]:
        try:
            parts = self.path.read_bytes().split(b"\n")
        except FileNotFoundError:
            return []
        out = []
        for i, line in enumerate(parts):
            if not line:
                continue
            try:
                rec = json.loads(line)
                if type(rec) is not dict or rec.get("t") not in STATES or type(rec.get("id")) is not str:
                    raise ValueError
            except ValueError:
                if i == len(parts) - 1:
                    break                                # torn final append
                raise RuntimeError(f"{self.path}: line {i + 1} is corrupt; refusing to guess")
            out.append(rec)
        return out


# ---------------------------------------------------------------------------------------------- bootstrap
def bootstrap(base: "str | os.PathLike") -> str:
    """One time, offline: BASE/live (a directory holding state_registry.json) becomes .cascade/versions/v0 and
    BASE/live a relative symlink to it. Safe to re-run, including after a crash between its two steps."""
    base = Path(base)
    live, v0 = base / LIVE, base / STATE_DIR / VERSIONS / "v0"
    if live.is_symlink():
        return f"already bootstrapped: {LIVE} -> {os.readlink(live)}"
    if not live.exists() and v0.is_dir():
        pass                                             # crashed after the rename: finish the symlink
    elif live.is_dir():
        if v0.exists():
            raise FileExistsError(f"{v0} exists and {live} is a directory: resolve by hand")
        Registry.load(live / REGISTRY_FILE)              # refuses a tree without a valid subnetbus registry
        v0.parent.mkdir(parents=True, exist_ok=True)
        os.rename(live, v0)
        fsync_dir(v0.parent)
    else:
        raise FileNotFoundError(f"{live}: nothing to bootstrap")
    os.symlink(f"{STATE_DIR}/{VERSIONS}/v0", live)
    fsync_dir(base)
    return f"bootstrapped: {LIVE} -> {STATE_DIR}/{VERSIONS}/v0"


# ---------------------------------------------------------------------------------------------- the harness
class Harness:
    def __init__(self, base: "str | os.PathLike", verify_cmd: Optional[Sequence[str]] = None, *,
                 auto_commit: Iterable[str] = (), verify_timeout_s: float = VERIFY_TIMEOUT_S,
                 sandbox: Optional[Sequence[str]] = None, allow_unsandboxed_for_tests: bool = False,
                 memory_max: Optional[str] = VERIFY_MEMORY_MAX,
                 apply_files: Optional[Callable[[Path, Mapping[str, Any]], Iterable[str]]] = None,
                 fault: Optional[Callable[[str], None]] = None):
        self.base = Path(base).resolve()
        self.state = self.base / STATE_DIR
        self.versions = self.state / VERSIONS
        self.journal = Journal(self.state / "journal.jsonl")
        self.verify_cmd = list(verify_cmd) if verify_cmd else None
        self.auto_commit = frozenset(auto_commit)
        self.verify_timeout_s = verify_timeout_s
        if sandbox is not None and not list(sandbox) and not allow_unsandboxed_for_tests:
            raise ValueError("verification never runs unsandboxed (allow_unsandboxed_for_tests is for tests only)")
        self.sandbox = default_sandbox() if sandbox is None else list(sandbox)
        if memory_max is None and not allow_unsandboxed_for_tests:
            raise ValueError("verification never runs without a memory cap (allow_unsandboxed_for_tests is for tests only)")
        self.memory_max = memory_max
        self.apply_files = apply_files                   # harness code: (stage_dir, action) -> rel paths it wrote
        self.fault = fault
        self.recovered: List[Result] = []
        if self.bootstrapped():
            for d in ("locks", "logs"):
                (self.state / d).mkdir(exist_ok=True)
            self.recovered = self.recover()

    # ------------------------------------------------------------------ public
    def bootstrapped(self) -> bool:
        return (self.base / LIVE).is_symlink() and self.versions.is_dir()

    def halted(self) -> Optional[dict]:
        """None, or what the marker says. ANY marker file means halted, whatever (if anything) it contains."""
        try:
            info = json.loads((self.state / "HALTED").read_text())
        except FileNotFoundError:
            return None
        except ValueError:
            info = None
        return info if isinstance(info, dict) and info else {"reason": "HALTED marker present"}

    def live_registry(self) -> Registry:
        return Registry.load(self.base / LIVE / REGISTRY_FILE)

    def mint(self, raw: Any, expect: Optional[Dict[str, Any]] = None):
        """The bridge, against the registry the harness reads itself. (verdict, ticket | None)."""
        return Bridge(self.live_registry()).mint(raw, expect)

    def submit(self, ticket: Any, intent: Optional[Mapping[str, Any]] = None) -> Result:
        """`intent` (the operator's op, target, ref, side, phrase) is journaled as data beside the ticket; it is never
        read back as an instruction."""
        if not isinstance(ticket, Ticket) or type(ticket.action.get("subnet")) is not str:
            return Result(False, "BAD_TICKET", detail="only a Ticket minted by cora_exec_bridge")
        if not self.bootstrapped():
            return Result(False, "NOT_BOOTSTRAPPED", ticket.id, detail=f"run: cora_stage_harness.py bootstrap {self.base}")
        if not self.verify_cmd:
            return Result(False, "VERIFY_FAIL", ticket.id, detail="no verify command configured")
        subnet = ticket.action["subnet"]
        try:
            with self._subnet_lock(subnet):
                with self._tree_lock():
                    refused = self._admit(ticket, subnet)
                    if refused is not None:
                        return refused
                    base_vid = self._live_vid()
                    rec = {"t": "RECEIVED", "id": ticket.id, "ticket": ticket.to_dict(), "subnet": subnet,
                           "base": base_vid, "pre": digest(manifest(self.versions / base_vid)), "vid": f"t-{ticket.id}"}
                    if intent is not None:
                        rec["intent"] = json.loads(json.dumps(dict(intent), default=str))   # plain data, nothing else
                    self.journal.append(rec)
                self._f("after_received")
                return self._run(rec)
        except Busy:
            return Result(False, "SUBNET_BUSY", ticket.id, detail=f"another ticket for {subnet} is in flight")

    def approve(self, ticket_id: str) -> Result:
        return self._resolve(ticket_id, commit=True)

    def discard(self, ticket_id: str) -> Result:
        return self._resolve(ticket_id, commit=False)

    def status(self) -> dict:
        idx = self._index()
        return {"halted": self.halted(), "live": self._live_vid() if self.bootstrapped() else None,
                "tickets": {i: t["state"] for i, t in idx.items()},
                "parked": {t["subnet"]: i for i, t in idx.items() if t["state"] == "PARKED"},
                "reserved": self.reserved() if self.bootstrapped() else []}

    def record(self, ticket_id: str) -> Optional[dict]:
        """What the journal holds for one ticket (its RECEIVED record, current state, digests), as a copy; None if unknown."""
        t = self._index().get(ticket_id)
        return json.loads(json.dumps(t, default=list)) if t is not None else None

    def reserved(self) -> List[dict]:
        """Live nodes with no bounds yet (placeholders for create), with how long ago the journal committed their
        reservation; None for one that predates the journal (e.g. bootstrapped into v0)."""
        since = {t["ticket"]["action"].get("target"): t.get("committed_ts") for t in self._index().values()
                 if t["state"] == "COMMITTED" and t["ticket"]["action"].get("op") == "reserve"}
        now = time.time()
        return [{"name": n.name, "ip": n.ip, "kind": n.kind, "subnet": n.subnet,
                 "age_s": round(now - since[n.name], 1) if since.get(n.name) else None}
                for n in sorted(self.live_registry().nodes(), key=lambda n: n.name) if n.bounds is None]

    def recover(self) -> List[Result]:
        """Roll back every non-terminal ticket whose owner is gone; keep PARKED ones that are intact."""
        out: List[Result] = []
        if self.halted():
            return out
        for p in self.base.glob(".live.tmp-*"):          # a swap that died between symlink() and replace()
            p.unlink(missing_ok=True)
        for tid, t in self._index().items():
            if t["state"] in TERMINAL:
                continue
            try:
                with self._subnet_lock(t["subnet"]):
                    with self._tree_lock():
                        cur = self._index().get(tid, {}).get("state")
                        if cur in TERMINAL or self.halted():
                            continue
                        if cur == "PARKED":
                            vdir = self.versions / t["vid"]
                            if vdir.is_dir() and digest(manifest(vdir)) == t.get("new"):
                                continue
                            out.append(self._rollback_locked(t, "DRIFT", "parked version missing or modified"))
                        else:
                            out.append(self._rollback_locked(t, "RECOVERED", f"crashed in {cur}"))
            except Busy:
                continue                                 # its owner is alive and holds the subnet
        return out

    # ------------------------------------------------------------------ admission
    def _admit(self, ticket: Ticket, subnet: str) -> Optional[Result]:
        if self.halted():
            return Result(False, "HALTED", ticket.id, detail="the harness is HALTED: inspect, then remove .cascade/HALTED")
        if ticket.expired():
            return Result(False, "TICKET_EXPIRED", ticket.id, detail=f"older than its ttl_s ({ticket.ttl_s})")
        idx = self._index()
        key = (subnet, ticket.digest, ticket.registry_rev)
        if ticket.id in idx or any(t["key"] == key for t in idx.values()):
            return Result(False, "DUP_TICKET", ticket.id, detail="this ticket, or this text on this revision, was already received")
        parked = [i for i, t in idx.items() if t["subnet"] == subnet and t["state"] == "PARKED"]
        if parked:
            return Result(False, "SUBNET_BUSY", ticket.id, detail=f"{parked[0]} is parked for {subnet}: approve or discard it")
        return None

    # ------------------------------------------------------------------ a ticket's run (subnet lock held)
    def _run(self, rec: dict) -> Result:
        t = self._view(rec)
        stage, base_dir = self.versions / t["vid"], self.versions / t["base"]
        try:
            phase = "STAGE_IO"
            try:
                shutil.copytree(base_dir, stage, symlinks=True)
                self._f("stage")
                fsync_tree(stage)
                fsync_dir(self.versions)
            except OSError as e:
                raise Fail("STAGE_IO", f"{e.__class__.__name__}: {e}")
            with self._tree_lock():
                self._check_halted()
                self._check_rev(t)
                self.journal.append({"t": "STAGED", "id": t["id"]})
            self._f("after_staged")

            phase = "APPLY_FAIL"
            declared = self._apply(stage, t)
            self.journal.append({"t": "APPLIED", "id": t["id"]})
            self._f("after_applied")

            phase = "POSTCHECK_FAIL"
            self._postcheck(base_dir, stage, t, declared)
            phase = "VERIFY_FAIL"
            new = self._verify(stage, t)
            self.journal.append({"t": "POSTCHECKED", "id": t["id"], "new": new})
            self._f("after_postchecked")
            t["new"] = new

            if t["subnet"] in self.auto_commit:
                with self._tree_lock():
                    return self._commit_or_rollback_locked(t)
            self.journal.append({"t": "PARKED", "id": t["id"], "new": new})
            self._f("after_parked")
            return Result(True, "PARKED", t["id"], "PARKED", f"staged as {t['vid']}; approve to commit")
        except Fail as e:
            return self._rollback(t, e.code, e.detail)
        except Exception as e:                           # anything unexpected still rolls back, coded by its phase
            return self._rollback(t, phase, f"{e.__class__.__name__}: {e}"[:300])

    def _apply(self, stage: Path, t: dict) -> List[str]:
        a = t["ticket"]["action"]
        try:
            reg = Registry.load(stage / REGISTRY_FILE)
            if a.get("op") == "reserve":
                reg.allocate(a["target"], a["subnet"], kind=a["kind"])          # an IP, no bounds: the placeholder
            else:
                reg.set_bounds(a["target"], AABB(a["x"], a["y"], a["w"], a["h"]))   # re-runs the placement gates
            self._f("apply")
            declared = [str(p) for p in (self.apply_files(stage, a) if self.apply_files else ())]
            reg.save(stage / REGISTRY_FILE)
            fsync_tree(stage)
        except Exception as e:
            raise Fail("APPLY_FAIL", f"{getattr(e, 'code', e.__class__.__name__)}: {getattr(e, 'detail', e)}"[:300])
        return declared

    def _postcheck(self, base_dir: Path, stage: Path, t: dict, declared: List[str]) -> None:
        a = t["ticket"]["action"]
        try:
            old, new = Registry.load(base_dir / REGISTRY_FILE), Registry.load(stage / REGISTRY_FILE)
            self._f("postcheck")
        except Exception as e:
            raise Fail("POSTCHECK_FAIL", f"registry unreadable: {e}"[:300])
        problems = new.validate()
        if new.revision != t["ticket"]["registry_rev"] + 1:
            problems.append(f"revision {new.revision}, expected {t['ticket']['registry_rev'] + 1}")
        node = new.get(a["target"])
        if a.get("op") == "reserve":
            if old.get(a["target"]) is not None:
                problems.append(f"{a['target']} existed before the reservation")
            if node is None or node.bounds is not None or node.kind != a["kind"] or node.subnet != a["subnet"]:
                problems.append(f"{a['target']} is not an unplaced {a['kind']} in {a['subnet']}")
        elif node is None or node.bounds != AABB(a["x"], a["y"], a["w"], a["h"]):
            problems.append(f"{a['target']} does not have the ticket's bounds")
        od, nd = old.to_dict(), new.to_dict()
        if od["subnets"] != nd["subnets"]:
            problems.append("subnets changed")
        if {k: v for k, v in od["nodes"].items() if k != a["target"]} != {k: v for k, v in nd["nodes"].items() if k != a["target"]}:
            problems.append("a node other than the target changed")
        mo, mn = manifest(base_dir), manifest(stage)
        changed = {k for k in mo.keys() | mn.keys() if mo.get(k) != mn.get(k)}
        undeclared = sorted(changed - {REGISTRY_FILE} - set(declared))
        if undeclared:
            problems.append(f"undeclared changes: {', '.join(undeclared[:5])}")
        if problems:
            raise Fail("POSTCHECK_FAIL", "; ".join(problems)[:300])

    def _verify(self, stage: Path, t: dict) -> str:
        """Run the verifier sandboxed in the stage. Returns the stage's manifest digest (what will be committed)."""
        log = self.state / "logs" / f"{t['id']}.log"
        log.parent.mkdir(exist_ok=True)
        unit = f"cora-verify-{t['id'][:8]}-{uuid.uuid4().hex[:6]}"
        env = dict(VERIFY_ENV)
        scope = []
        if self.memory_max:
            env.update({k: os.environ[k] for k in SCOPE_ENV if k in os.environ})
            scope = [*scope_argv(unit, self.memory_max), "env", "-i", *[f"{k}={v}" for k, v in VERIFY_ENV.items()]]
        argv = [*scope, *[a.replace(STAGE, str(stage)) for a in self.sandbox], *self.verify_cmd]
        before = manifest(stage)                         # tripwire, immediately before
        with open(log, "wb") as out:
            try:
                proc = subprocess.Popen(argv, cwd=stage, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                        env=env, start_new_session=True)
            except OSError as e:
                raise Fail("VERIFY_FAIL", f"could not start the sandboxed verifier: {e}")
            timed_out = False
            try:
                rc = proc.wait(timeout=self.verify_timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                if scope:
                    kill_scope(unit)                     # the whole cgroup, also processes that left the group
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
        after = manifest(stage)                          # tripwire, immediately after
        if after != before:
            changed = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
            raise Fail("VERIFY_FAIL", f"staged tree modified by verifier: {', '.join(changed[:5])}")
        if timed_out:
            raise Fail("VERIFY_TIMEOUT", f"over {self.verify_timeout_s:g}s; {'scope and ' if scope else ''}process group killed")
        tail = log.read_bytes()[-LOG_TAIL:].decode("utf-8", "replace")
        if rc != 0:
            raise Fail("VERIFY_FAIL", f"exit {rc}" + (" (killed: memory cap?)" if rc in (-9, 137) else "")
                       + f": {tail.strip()[-300:]}")
        return digest(after)

    # ------------------------------------------------------------------ commit / resolve (tree lock held where named)
    def _commit_locked(self, t: dict) -> Result:
        self._check_halted()
        self._check_rev(t)
        if self._live_vid() != t["base"]:
            raise Fail("DRIFT", f"live is {self._live_vid()}, the ticket was staged from {t['base']}")
        if digest(manifest(self.versions / t["base"])) != t["pre"]:
            raise Fail("DRIFT", f"live version {t['base']} was modified since the ticket was staged")
        if digest(manifest(self.versions / t["vid"])) != t["new"]:
            raise Fail("DRIFT", f"staged version {t['vid']} is not what was verified")
        self._f("before_swap")
        try:
            self._swap(t["vid"])
            self._f("commit")
        except OSError as e:
            raise Fail("COMMIT_FAIL", f"{e.__class__.__name__}: {e}")
        self._f("after_swap")
        self.journal.append({"t": "COMMITTED", "id": t["id"]})
        return Result(True, "COMMITTED", t["id"], "COMMITTED", f"live -> {t['vid']}")

    def _commit_or_rollback_locked(self, t: dict) -> Result:
        try:
            return self._commit_locked(t)
        except Fail as e:
            return self._rollback_locked(t, e.code, e.detail)
        except Exception as e:
            return self._rollback_locked(t, "COMMIT_FAIL", f"{e.__class__.__name__}: {e}"[:300])

    def _resolve(self, ticket_id: str, commit: bool) -> Result:
        if not self.bootstrapped():
            return Result(False, "NOT_BOOTSTRAPPED", ticket_id)
        t = self._index().get(ticket_id)
        if t is None or t["state"] != "PARKED":
            return Result(False, "NOT_PARKED", ticket_id, t and t["state"], "only a PARKED ticket can be approved or discarded")
        try:
            with self._subnet_lock(t["subnet"]):
                with self._tree_lock():
                    if self.halted():
                        return Result(False, "HALTED", ticket_id, "PARKED", "the harness is HALTED")
                    t = self._index().get(ticket_id)
                    if t is None or t["state"] != "PARKED":
                        return Result(False, "NOT_PARKED", ticket_id, t and t["state"])
                    if not commit:
                        return self._rollback_locked(t, "DISCARDED", "discarded by the operator")
                    return self._commit_or_rollback_locked(t)
        except Busy:
            return Result(False, "SUBNET_BUSY", ticket_id, "PARKED", "a ticket for this subnet is in flight")

    # ------------------------------------------------------------------ rollback
    def _rollback(self, t: dict, code: str, detail: str) -> Result:
        with self._tree_lock():
            return self._rollback_locked(t, code, detail)

    def _rollback_locked(self, t: dict, code: str, detail: str) -> Result:
        try:
            live = self._live_vid()
            if live == t["vid"]:
                self._swap(t["base"])
                live = self._live_vid()
            self._f("rollback_after_swapback")
            expected = self._expected_digests().get(live)
            actual = digest(manifest(self.versions / live))
            if expected is None or actual != expected:   # an uncommitted version (ours) has no expected digest
                return self._halt(t, f"after rolling back ({code}) live is {live}: manifest "
                                     f"{'unknown to the journal' if expected is None else 'does not match'}")
        except Exception as e:                           # cannot even establish what is live: that is a halt too
            return self._halt(t, f"rollback ({code}) failed: {e.__class__.__name__}: {e}")
        stage = self.versions / t["vid"]
        if t["vid"].startswith("t-") and stage.is_dir():
            shutil.rmtree(stage, ignore_errors=True)
        self.journal.append({"t": "ROLLED_BACK", "id": t["id"], "code": code, "detail": detail[:300]})
        return Result(False, code, t["id"], "ROLLED_BACK", detail)

    def _halt(self, t: dict, detail: str) -> Result:
        marker = self.state / "HALTED"
        tmp = self.state / f".HALTED.{os.getpid()}.tmp"
        tmp.write_text(json.dumps({"ticket": t["id"], "code": "ROLLBACK_MISMATCH", "detail": detail, "ts": time.time()}))
        os.replace(tmp, marker)
        fsync_dir(self.state)
        self.journal.append({"t": "HALTED", "id": t["id"], "code": "ROLLBACK_MISMATCH", "detail": detail[:300]})
        return Result(False, "ROLLBACK_MISMATCH", t["id"], "HALTED", detail)

    # ------------------------------------------------------------------ plumbing
    def _f(self, name: str) -> None:
        if self.fault:
            self.fault(name)

    def _check_halted(self) -> None:
        if self.halted():
            raise Fail("HALTED", "the harness was HALTED while this ticket was in flight")

    def _check_rev(self, t: dict) -> None:
        rev = self.live_registry().revision
        if rev != t["ticket"]["registry_rev"]:
            raise Fail("STALE_REV", f"registry is at revision {rev}, the ticket was minted at {t['ticket']['registry_rev']}")

    def _live_vid(self) -> str:
        target = os.readlink(self.base / LIVE)
        prefix = f"{STATE_DIR}/{VERSIONS}/"
        if not target.startswith(prefix) or "/" in target[len(prefix):]:
            raise RuntimeError(f"{LIVE} -> {target}: not a version this harness made")
        return target[len(prefix):]

    def _swap(self, vid: str) -> None:
        tmp = self.base / f".live.tmp-{uuid.uuid4().hex[:8]}"
        os.symlink(f"{STATE_DIR}/{VERSIONS}/{vid}", tmp)
        try:
            os.replace(tmp, self.base / LIVE)            # atomic: readers see the old tree or the new, never a mix
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        fsync_dir(self.base)

    def _index(self) -> Dict[str, dict]:
        idx: Dict[str, dict] = {}
        for r in self.journal.read():
            if r["t"] == "RECEIVED":
                tk = r["ticket"]
                idx[r["id"]] = {**r, "state": "RECEIVED", "key": (r["subnet"], tk["digest"], tk["registry_rev"])}
            elif r["id"] in idx:
                idx[r["id"]]["state"] = r["t"]
                if "new" in r:
                    idx[r["id"]]["new"] = r["new"]
                if r["t"] == "COMMITTED":
                    idx[r["id"]]["committed_ts"] = r.get("ts")
        return idx

    def _view(self, rec: dict) -> dict:
        t = dict(rec)
        Ticket.from_dict(t["ticket"])                    # shape check
        return t

    def _expected_digests(self) -> Dict[str, str]:
        """What each version holds, by the journal: a ticket's starting point (pre), and every committed version."""
        out: Dict[str, str] = {}
        for t in self._index().values():
            out.setdefault(t["base"], t["pre"])
            if t["state"] == "COMMITTED":
                out[t["vid"]] = t["new"]
        return out

    @contextmanager
    def _subnet_lock(self, subnet: str) -> Iterator[None]:
        with self._flock(self.state / "locks" / f"subnet-{subnet.replace('/', '_')}.lock", block=False):
            yield

    @contextmanager
    def _tree_lock(self) -> Iterator[None]:
        with self._flock(self.state / "locks" / "tree.lock", block=True):
            yield

    @contextmanager
    def _flock(self, path: Path, block: bool) -> Iterator[None]:
        path.parent.mkdir(exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if block else fcntl.LOCK_NB))
            except BlockingIOError:
                raise Busy(path.name) from None
            yield
        finally:
            os.close(fd)                                 # closing releases the lock, and so does dying


# ---------------------------------------------------------------------------------------------- CLI
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="cora_stage_harness.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("bootstrap", "status"):
        sub.add_parser(name).add_argument("base")
    p = sub.add_parser("submit")
    p.add_argument("base")
    p.add_argument("--auto-commit", action="append", default=[], metavar="CIDR")
    p.add_argument("--timeout", type=float, default=VERIFY_TIMEOUT_S)
    p.add_argument("verify_cmd", nargs=argparse.REMAINDER)
    for name in ("approve", "discard"):
        p = sub.add_parser(name)
        p.add_argument("base")
        p.add_argument("ticket")
    a = ap.parse_args(argv)
    if a.cmd == "bootstrap":
        print(bootstrap(a.base))
        return 0
    if a.cmd == "status":
        print(json.dumps(Harness(a.base).status(), indent=2, default=str))
        return 0
    if a.cmd == "submit":
        cmd = a.verify_cmd[1:] if a.verify_cmd[:1] == ["--"] else a.verify_cmd
        h = Harness(a.base, cmd, auto_commit=a.auto_commit, verify_timeout_s=a.timeout)
        verdict, ticket = h.mint(sys.stdin.read().rstrip("\n"))
        r = h.submit(ticket) if ticket else Result(False, verdict.code, detail=verdict.detail)
    else:
        h = Harness(a.base)
        r = h.approve(a.ticket) if a.cmd == "approve" else h.discard(a.ticket)
    print(json.dumps(asdict(r)))
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
