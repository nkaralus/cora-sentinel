"""Filesystem guard (GI_3, filesystem half) and lexical path checks (GI_2).

Two layers:
  lexical_segments(p)  pure string check, no disk access. Used by GI_2.
  PathGuard.check(p, op)  resolves against a project root and refuses symlinks,
                          mountpoints, cross-device paths, root escapes, and
                          project roots that are filesystem roots or system dirs.

The guard is ADVISORY about the instant it ran. The harness must still open files
with no-follow semantics and re-check the registry revision before committing.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List, Optional

from .errors import PathError, show

__all__ = ["lexical_segments", "PathGuard", "active_mountpoints",
           "READ_OPS", "WRITE_OPS", "DESTRUCTIVE_OPS"]

READ_OPS = frozenset({"read", "stat", "list"})
WRITE_OPS = frozenset({"write", "create", "overwrite", "chmod"})
DESTRUCTIVE_OPS = frozenset({"delete", "rmdir", "move"})

MAX_PATH_CHARS = 1024
MAX_DEPTH = 32
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,254}", re.ASCII)
_RESERVED = frozenset({"con", "prn", "aux", "nul"}
                      | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)})
_SCHEMES = ("res://",)


def lexical_segments(p: object) -> List[str]:
    """Validate a project-relative path and return its segments. Raises PathError."""
    if type(p) is not str:
        raise PathError("PATH_TYPE", "path must be str")
    if not p:
        raise PathError("PATH_EMPTY")
    if len(p) > MAX_PATH_CHARS:
        raise PathError("PATH_TOO_LONG")
    if not p.isascii():
        raise PathError("PATH_NON_ASCII", show(p))
    if not p.isprintable():
        raise PathError("PATH_CONTROL_CHAR", show(p))
    for s in _SCHEMES:
        if p.startswith(s):
            p = p[len(s):]
            break
    if ":" in p:
        raise PathError("PATH_SCHEME", f"drive letters, URIs and ADS are not allowed: {show(p)}")
    if "\\" in p:
        raise PathError("PATH_BACKSLASH", show(p))
    if p.startswith("/"):
        raise PathError("PATH_ABSOLUTE", show(p))
    segs = p.split("/")
    if len(segs) > MAX_DEPTH:
        raise PathError("PATH_TOO_DEEP")
    for seg in segs:
        if seg == "..":
            raise PathError("PATH_TRAVERSAL", show(p))
        if not _SEGMENT.fullmatch(seg) or seg.endswith("."):
            raise PathError("PATH_SEGMENT", f"bad segment {show(seg)}")
        if seg.split(".", 1)[0].casefold() in _RESERVED:
            raise PathError("PATH_RESERVED_NAME", show(seg))
    return segs


def _unescape(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def active_mountpoints(mountinfo: str = "/proc/self/mountinfo") -> frozenset:
    """Mount points of this process (Linux). Empty elsewhere; PathGuard then relies on
    os.path.ismount and st_dev comparison per component."""
    try:
        text = Path(mountinfo).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    out = set()
    for line in text.splitlines():
        parts = line.split(" ")
        if len(parts) > 4:
            out.add(_unescape(parts[4]))
    return frozenset(out)


_PROTECTED_EXACT = {"/", "/home", "/root", "/var", "/tmp", "/mnt", "/media", "/opt", "/srv"}
_PROTECTED_TREES = ("/proc", "/sys", "/dev", "/boot", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/usr")


class PathGuard:
    def __init__(self, root: "str | os.PathLike", *, mountpoints: Optional[Iterable[str]] = None,
                 allow_symlinks: bool = False):
        r = Path(root)
        if not r.is_absolute():
            raise PathError("ROOT_NOT_ABSOLUTE", show(str(root)))
        real = Path(os.path.realpath(r))
        if not real.is_dir():
            raise PathError("ROOT_MISSING", show(str(real)))
        if real == Path(real.anchor) or real.parent == real:
            raise PathError("ROOT_IS_FS_ROOT", show(str(real)))
        s = str(real)
        if s in _PROTECTED_EXACT or real == Path.home() \
                or any(s == t or s.startswith(t + "/") for t in _PROTECTED_TREES):
            raise PathError("ROOT_PROTECTED", show(s))
        sysroot = os.environ.get("SystemRoot")
        if sysroot and (real == Path(sysroot) or Path(sysroot) in real.parents):
            raise PathError("ROOT_PROTECTED", show(s))
        self.root = real
        self.allow_symlinks = allow_symlinks
        mounts = active_mountpoints() if mountpoints is None else mountpoints
        self._mounts = frozenset(os.path.realpath(m) for m in mounts)
        self._root_dev = os.stat(real).st_dev

    def _mount_inside(self, s: str) -> Optional[str]:
        pre = s.rstrip(os.sep) + os.sep
        return next((m for m in self._mounts if m.startswith(pre)), None)

    def check(self, rel: object, op: object) -> Path:
        """Return the resolved path if `op` on `rel` is safe. Raises PathError."""
        if op not in READ_OPS | WRITE_OPS | DESTRUCTIVE_OPS:
            raise PathError("UNKNOWN_FS_OP", show(op))
        cur = self.root
        for seg in lexical_segments(rel):
            cur = cur / seg
            s = str(cur)
            if s in self._mounts or os.path.ismount(s):
                raise PathError("MOUNTPOINT", show(s))
            if os.path.islink(s) and not self.allow_symlinks:
                raise PathError("SYMLINK", show(s))
            try:
                st = os.lstat(s)
            except FileNotFoundError:
                continue
            except OSError as e:
                raise PathError("FS_ERROR", type(e).__name__) from None
            if st.st_dev != self._root_dev:
                raise PathError("CROSS_DEVICE", show(s))
        real = Path(os.path.realpath(cur))
        if real == self.root or not real.is_relative_to(self.root):
            raise PathError("ESCAPES_ROOT", show(str(real)))
        if op in DESTRUCTIVE_OPS and real.is_dir():
            inner = self._mount_inside(str(real))
            if inner:
                raise PathError("MOUNTPOINT_INSIDE", show(inner))
        if op in WRITE_OPS and real.is_file() and os.lstat(real).st_nlink > 1:
            raise PathError("HARDLINKED", show(str(real)))
        return real
