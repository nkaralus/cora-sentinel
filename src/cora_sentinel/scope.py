"""
cora_sentinel.scope - ephemeral per-launch cgroup scopes, made by the daemon for unprivileged launchers. Stdlib only.

An unprivileged `cora-run` cannot create a cgroup under the root-owned task tree or move itself into one. The daemon
(root) does it on request over the status socket, which tells it the caller's pid and uid (SO_PEERCRED):

    name = scopes.create_scope("steam-570", uid=1000, memory_max="8G", memory_high="7G")
    scopes.enter(name, pid=<the caller's own pid, from SO_PEERCRED>, uid=1000)
    ...                                          # the caller then execs the game, which stays in the scope
    scopes.reap()                                # on the daemon's tick: empty scopes go away

Rules, each one a test:
  * A scope's name is "<app>-<6 hex>", never reused: a relaunch gets a new cgroup, so nothing (an nft drop rule,
    a freeze, limits) is ever inherited from an earlier run.
  * No scope exists without its limits. They are written before anything enters; if the kernel refuses one (the memory
    controller not enabled on the root, say) the directory is removed and the request fails. A game silently started
    without its ceiling would be a lie about what is in force.
  * enter() is one-shot and owner-bound: only a scope this daemon created, only by the uid that created it, only once.
    Another member of the group cannot move into your game's scope, and nothing can be added to it later through here.
    The pid comes from the kernel (the socket layer passes SO_PEERCRED), never from the request.
  * A scope created and not entered within ENTER_TTL_S is reaped, so a crashed launcher leaks nothing.
  * reap() removes only scopes this daemon made (a registry persisted in the state dir, so a restart still cleans up
    its own), only when cgroup.events says "populated 0", children first. Anything else under the root is left alone.
  * At most MAX_SCOPES at once, so a group member cannot fill the tree.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cora_sentinel.cgroup import CgroupRoot, CgroupError

APP_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}", re.ASCII)       # + "-" + 6 hex = at most 39: inside NAME_RE's 40
MAX_SCOPES = 64
PROFILES = ("app", "agent")    # see Sentinel.app_allows; fixed at creation, never changed
ENTER_TTL_S = 30.0
MIN_MEMORY = 64 * 1024 * 1024                                    # below this a game dies at start; refuse instead
SIZE_RE = re.compile(r"(\d+)([KMGT]?)", re.ASCII)
UNITS = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}


class ScopeError(Exception):
    pass


class ScopeRegistryError(ScopeError):
    """scopes.json exists but cannot be read as a registry (bad JSON, not an object, permission denied, ...)."""


def parse_size(v) -> Optional[int]:
    """Bytes from an int or "512M" / "8G" (binary units). None stays None (no limit)."""
    if v is None:
        return None
    if isinstance(v, bool):
        raise ScopeError(f"not a size: {v!r}")
    if isinstance(v, int):
        n = v
    else:
        m = SIZE_RE.fullmatch(str(v).strip().upper())
        if not m:
            raise ScopeError(f"not a size: {v!r} (bytes, or a number with K, M, G or T)")
        n = int(m.group(1)) * UNITS[m.group(2)]
    if n < MIN_MEMORY:
        raise ScopeError(f"memory limit {n} bytes is below the {MIN_MEMORY >> 20} MiB floor")
    return n


class Scopes:
    def __init__(self, cg: CgroupRoot, state_path: Optional[str] = None,
                 clock: Callable[[], float] = time.time, token: Callable[[int], str] = secrets.token_hex):
        self.cg, self.clock, self.token = cg, clock, token
        self.state = Path(state_path) if state_path else None
        self.owned: Dict[str, dict] = {}            # name -> {"app", "uid", "created", "entered"}
        self.registry_error: Optional[str] = None   # why scopes.json is unreadable right now, or None
        self._stamp = None                          # (inode, size, mtime) of the file as last read or written
        try:
            self.owned = self._load()
        except ScopeRegistryError as e:
            self.registry_error = str(e)

    # ------------------------------------------------------------------ registry (survives a daemon restart)
    # Missing is a clean start. Anything else that is not a readable JSON object is ScopeRegistryError: the daemon
    # then shows the hub blind, suspends the reaper and refuses launches, and the file is never overwritten or
    # deleted (a person may want what is in it). It heals by itself: check() re-reads it on every snapshot.
    def _stat(self):
        try:
            st = os.stat(self.state)
        except FileNotFoundError:
            return None
        except OSError as e:
            return ("unstat-able", e.errno)
        return (st.st_ino, st.st_size, st.st_mtime_ns)

    def _read_once(self) -> Optional[dict]:
        try:
            text = self.state.read_text()
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            raise ScopeRegistryError(f"{self.state} is a directory") from None
        except OSError as e:
            raise ScopeRegistryError(f"{self.state}: {e.strerror or e}") from None
        except UnicodeDecodeError:
            raise ScopeRegistryError(f"{self.state}: not UTF-8 text") from None
        try:
            data = json.loads(text)
        except ValueError as e:
            raise ScopeRegistryError(f"{self.state}: not valid JSON ({getattr(e, 'msg', e)}"
                                     f"{f' at line {e.lineno} column {e.colno}' if hasattr(e, 'lineno') else ''})") from None
        if not isinstance(data, dict):
            raise ScopeRegistryError(f"{self.state}: not a JSON object (a {type(data).__name__})")
        return {k: v for k, v in data.items() if isinstance(v, dict) and re.fullmatch(rf"{APP_RE.pattern}-[0-9a-f]{{6}}", k)}

    def _load(self) -> Dict[str, dict]:
        if not self.state:
            return {}
        try:
            data = self._read_once()
        except ScopeRegistryError:
            data = self._read_once()             # one immediate re-read: a writer may have just replaced it
        self._stamp = self._stat()
        return data or {}

    def check(self) -> Optional[str]:
        """Re-read scopes.json if it changed since it was last read or written, or while it is unreadable. Returns
        why it is unreadable, or None. A valid change made by someone else is adopted; while it is unreadable, the
        last good registry stays in memory (so profiles stay right) but nothing is written over the file."""
        if not self.state:
            return None
        if self.registry_error is None and self._stat() == self._stamp:
            return None
        try:
            data = self._load()
        except ScopeRegistryError as e:
            self.registry_error = str(e)
            return self.registry_error
        self.owned, self.registry_error = data, None
        return None

    def _require_registry(self) -> None:
        err = self.check()
        if err:
            raise ScopeRegistryError(f"scope registry unreadable: {err}")

    def _save(self) -> None:
        """Atomic: a temp file in the same directory, fsync, rename, fsync the directory. Refuses to replace a file
        that changed since it was last read and is not a readable registry now."""
        if not self.state:
            return
        if self._stat() != self._stamp:
            try:
                self._read_once()
            except ScopeRegistryError as e:
                self.registry_error = str(e)
                raise
        d = self.state.parent
        fd, tmp = tempfile.mkstemp(dir=d, prefix=f".{self.state.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(self.owned, sort_keys=True))
                f.flush()
                os.fchmod(f.fileno(), 0o600)
                os.fsync(f.fileno())
            os.replace(tmp, self.state)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        self._stamp = self._stat()

    # ------------------------------------------------------------------ create
    def create_scope(self, app: str, uid: int, memory_max=None, memory_high=None, psi_memory: Optional[str] = None,
                     profile: str = "app") -> str:
        if not isinstance(app, str) or not APP_RE.fullmatch(app):
            raise ScopeError(f"bad app name {app!r}: lowercase letters, digits, '-' and '_', at most 32")
        if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0:
            raise ScopeError("uid must come from SO_PEERCRED")
        if profile not in PROFILES:
            raise ScopeError(f"unknown profile {profile!r}: {', '.join(PROFILES)}")
        self._require_registry()
        mx, hi = parse_size(memory_max), parse_size(memory_high)
        if mx is not None and hi is not None and hi > mx:
            raise ScopeError(f"memory_high ({hi}) above memory_max ({mx}): the soft limit must not exceed the hard one")
        self.reap()                                  # count what is really live before refusing for the cap
        if len(self.owned) >= MAX_SCOPES:
            raise ScopeError(f"{MAX_SCOPES} scopes already exist")
        for _ in range(8):
            name = f"{app}-{self.token(3)}"
            try:
                d = self.cg._dir(name)
                d.mkdir()                            # NOT exist_ok: an existing directory is never adopted
                break
            except FileExistsError:
                continue
            except CgroupError as e:
                raise ScopeError(str(e)) from None
        else:
            raise ScopeError("could not find a free scope name")
        try:
            # high first: the kernel accepts either order, but a reader never sees a hard cap with no soft one
            for fname, val in (("memory.high", hi), ("memory.max", mx)):
                if val is not None:
                    (d / fname).write_text(str(val))
                    got = (d / fname).read_text().strip()
                    if got != str(val):
                        raise OSError(f"{fname} reads back {got!r}, not {val}")
        except OSError as e:
            try:
                d.rmdir()
            except OSError:
                pass
            raise ScopeError(f"could not set the limits ({e}); is the memory controller enabled on "
                             f"{self.cg.root}? The scope was removed, nothing started without its ceiling") from None
        self.owned[name] = {"app": app, "uid": uid, "created": self.clock(), "entered": False,
                            "memory_max": mx, "memory_high": hi, "psi_memory": psi_memory, "profile": profile}
        self._save()
        return name

    # ------------------------------------------------------------------ enter
    def enter(self, name: str, pid: int, uid: int) -> None:
        self._require_registry()
        rec = self.owned.get(name)
        if rec is None:
            raise ScopeError(f"{name!r} is not a scope this daemon created")
        if rec["uid"] != uid:
            raise ScopeError(f"{name!r} belongs to another user")
        if rec["entered"]:
            raise ScopeError(f"{name!r} was already entered: a scope takes one launcher, once")
        if self.clock() - rec["created"] > ENTER_TTL_S:
            raise ScopeError(f"{name!r} expired: enter within {ENTER_TTL_S:.0f} s of creating it")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
            raise ScopeError("pid must come from SO_PEERCRED")
        try:
            (self.cg._dir(name) / "cgroup.procs").write_text(str(pid))
        except (OSError, CgroupError) as e:
            raise ScopeError(f"could not move pid {pid} into {name}: {e}") from None
        rec["entered"] = True
        self._save()

    # ------------------------------------------------------------------ reap
    @staticmethod
    def _populated(d: Path) -> Optional[bool]:
        try:
            for line in (d / "cgroup.events").read_text().splitlines():
                k, _, v = line.partition(" ")
                if k == "populated":
                    return v.strip() == "1"
        except OSError:
            pass
        return None                                  # unknown: treat as in use

    @staticmethod
    def _rmtree_cgroup(d: Path) -> None:
        """rmdir children first (a launcher's workers may have made sub-cgroups). Bounded; never follows symlinks."""
        stack, order = [d], []
        while stack and len(order) < 1024:
            cur = stack.pop()
            order.append(cur)
            try:
                with os.scandir(cur) as it:
                    stack += [Path(e.path) for e in it if e.is_dir(follow_symlinks=False)]
            except OSError:
                pass
        for p in reversed(order):
            p.rmdir()

    def reap(self) -> List[str]:
        if self.check():
            return []                                # suspended: never reap from a registry we cannot read
        gone = []
        now = self.clock()
        for name, rec in list(self.owned.items()):
            try:
                d = self.cg._dir(name)
            except CgroupError:
                del self.owned[name]
                continue
            if not d.is_dir():
                gone.append(name)
                del self.owned[name]
                continue
            pop = self._populated(d)
            if pop is None or pop:
                continue
            if not rec["entered"] and now - rec["created"] <= ENTER_TTL_S:
                continue                             # still waiting for its launcher
            try:
                self._rmtree_cgroup(d)
            except OSError:
                continue                             # busy (a process arrived, or a child is populated): next tick
            gone.append(name)
            del self.owned[name]
        if gone:
            self._save()
        return gone

    def profile(self, name: Optional[str]) -> str:
        """"app" or "agent" for a scope this daemon made; "agent" for anything else (root-launched tasks).
        A registry entry from before profiles existed was an --app launch: "app". Called from the detector threads:
        one dict lookup, no lock (a dict read is atomic in CPython)."""
        rec = self.owned.get(name) if name else None
        return "agent" if rec is None else rec.get("profile", "app")

    def describe(self, name: str) -> Optional[dict]:
        if self.registry_error is not None:
            return None                              # the hub must not claim launch provenance it cannot read
        rec = self.owned.get(name)
        return dict(rec, name=name) if rec else None
