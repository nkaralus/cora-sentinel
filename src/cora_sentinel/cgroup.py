#!/usr/bin/env python3
"""
cora_sentinel.cgroup - per-task containment on cgroup v2. Standalone, stdlib only.

A task is a directory under one delegated root:  <root>/<name>/
  membership : cgroup.procs        (children inherit; no argv marker needed)
  SUSPEND    : cgroup.freeze = 1   (whole tree, reversible)
  TERMINATE  : cgroup.kill   = 1   (SIGKILL to the whole tree, kernel 5.14+)
  THROTTLE   : cpu.max + memory.high, falling back to nice +10 on every pid

freeze and kill are core files: no controller needed. Only THROTTLE's primary
path needs the cpu/memory controllers delegated to this root.

  cora-cgroup list | status NAME | thaw NAME     (root: $CORA_CGROUP_ROOT)
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_ROOT = "/sys/fs/cgroup/cora"
DEFAULT_MOUNT = "/sys/fs/cgroup"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}", re.ASCII)


class CgroupError(Exception):
    pass


class CgroupRoot:
    def __init__(self, path: str = DEFAULT_ROOT, mount: str = DEFAULT_MOUNT):
        self.root = Path(path)
        self.mount = Path(mount)

    # ---- setup ------------------------------------------------------------
    def ensure(self, controllers=("cpu", "memory")) -> List[str]:
        """Create the root, enable what controllers we can. Returns enabled ones."""
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            avail = (self.root / "cgroup.controllers").read_text().split()
        except OSError:
            avail = []
        enabled = []
        for c in controllers:
            if c in avail:
                try:
                    (self.root / "cgroup.subtree_control").write_text(f"+{c}")
                    enabled.append(c)
                except OSError:
                    pass
        return enabled

    # ---- names and paths --------------------------------------------------
    def _dir(self, name: str) -> Path:
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise CgroupError(f"bad cgroup name: {name!r}")
        p = self.root / name
        if os.path.realpath(p.parent) != os.path.realpath(self.root):
            raise CgroupError("path escapes root")
        return p

    def create(self, name: str) -> Path:
        p = self._dir(name)
        p.mkdir(exist_ok=True)
        return p

    def cgroup_id(self, name: str) -> Optional[int]:
        """The kernel's identity of this task's cgroup: the inode number of its directory (the cgroup id on cgroup v2), or None if it
        does not exist. A cgroup that is removed and created again under the same name gets a NEW one, so this tells "the same task"
        from "a later task that reused the name"."""
        try:
            return os.stat(self._dir(name)).st_ino
        except (OSError, CgroupError):
            return None

    def names(self) -> List[str]:
        try:
            return sorted(d.name for d in self.root.iterdir()
                          if d.is_dir() and NAME_RE.fullmatch(d.name))
        except OSError:
            return []

    # ---- membership -------------------------------------------------------
    def pids(self, name: str) -> List[int]:
        try:
            return [int(x) for x in (self._dir(name) / "cgroup.procs").read_text().split()]
        except OSError:
            return []

    def discover(self) -> Dict[int, str]:
        out: Dict[int, str] = {}
        for n in self.names():
            for pid in self.pids(n):
                out[pid] = n
        return out

    def _read_proc_cgroup(self, pid: int) -> Optional[str]:
        try:
            for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
                if line.startswith("0::"):
                    return line[3:]
        except OSError:
            pass
        return None

    def cgroup_of(self, pid: int) -> Optional[str]:
        """Task name the kernel says this pid is in right now, else None."""
        cur = self._read_proc_cgroup(pid)
        if cur is None:
            return None
        rel = "/" + os.path.relpath(self.root, self.mount).strip("/")
        if not cur.startswith(rel + "/"):
            return None
        name = cur[len(rel) + 1:]
        return name if NAME_RE.fullmatch(name) else None  # nested deeper -> not a task root

    # ---- actions ----------------------------------------------------------
    def _write(self, name: str, fname: str, val: str) -> None:
        (self._dir(name) / fname).write_text(val)

    def freeze(self, name: str) -> None:
        self._write(name, "cgroup.freeze", "1")

    def thaw(self, name: str) -> None:
        self._write(name, "cgroup.freeze", "0")

    def freeze_requested(self, name: str) -> bool:
        """True if a freeze has been ASKED for. Freezing is asynchronous: this flips at once, while
        is_frozen() (the actual state) lags until every process has stopped. Use this, not
        is_frozen(), to decide whether something still needs thawing."""
        try:
            return (self._dir(name) / "cgroup.freeze").read_text().strip() == "1"
        except OSError:
            return False

    def is_frozen(self, name: str) -> bool:
        try:
            return "frozen 1" in (self._dir(name) / "cgroup.events").read_text()
        except OSError:
            return False

    def kill(self, name: str) -> None:
        self._write(name, "cgroup.kill", "1")

    def throttle(self, name: str, cpu_pct: int = 20) -> List[str]:
        """Apply limits. Returns the knobs that took effect."""
        applied: List[str] = []
        try:
            self._write(name, "cpu.max", f"{cpu_pct * 1000} 100000")
            applied.append(f"cpu.max={cpu_pct}%")
        except OSError:
            pass
        try:  # cap growth where it is: no new memory without reclaim pressure
            cur = (self._dir(name) / "memory.current").read_text().strip()
            self._write(name, "memory.high", cur)
            applied.append("memory.high=current")
        except OSError:
            pass
        if not applied:  # controllers not delegated: degrade, don't pretend
            for pid in self.pids(name):
                try:
                    os.setpriority(os.PRIO_PROCESS, pid, 10)
                except OSError:
                    continue
            applied.append("nice+10(fallback)")
        return applied

    def reset_limits(self, name: str) -> List[str]:
        """Undo throttle()'s cgroup limits. (A nice+10 fallback is not undone.)"""
        undone: List[str] = []
        for fname, default in (("cpu.max", "max 100000"), ("memory.high", "max")):
            p = self._dir(name) / fname
            try:
                cur = p.read_text().strip()
                if cur.split()[0] != "max":
                    p.write_text(default)
                    undone.append(f"{fname}-reset")
            except (OSError, IndexError):
                continue
        return undone


def main() -> int:
    root = CgroupRoot(os.environ.get("CORA_CGROUP_ROOT", DEFAULT_ROOT),
                      os.environ.get("CORA_CGROUP_MOUNT", DEFAULT_MOUNT))
    a = sys.argv[1:]
    if a[:1] == ["list"]:
        for n in root.names():
            print(f"{n:<24} pids={root.pids(n)} frozen={root.is_frozen(n)} freeze_requested={root.freeze_requested(n)}")
        return 0
    if len(a) == 2 and a[0] == "status":
        print(f"pids={root.pids(a[1])} frozen={root.is_frozen(a[1])}")
        return 0
    if len(a) == 2 and a[0] == "thaw":
        root.thaw(a[1])
        print(f"thawed {a[1]}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
