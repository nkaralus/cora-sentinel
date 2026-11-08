"""Vendored third-party code. Nothing in here is edited by hand.

`subnetbus` is a verbatim copy of github.com/nkaralus/engine-telemetry-bus at one pinned commit. It is the safety gate
(GI_1-GI_3) the verdict code asks before it acts, so the copy that ships is the copy the tests ran against, and anything
that changes it is visible: `subnetbus/VENDOR.lock` records the upstream commit and the sha256 of every file, `verify()`
recomputes them (cora-selfcheck and the daemon's start-up line call it), and `tools/vendor_bus.py` is the only thing that
rewrites the tree. Imports always come from here, even if another `subnetbus` is installed.

`mule` is a verbatim copy of github.com/nkaralus/mule-protocol, the same way (`mule/VENDOR.lock`,
`tools/vendor_bus.py --lib mule`): the raw-text validator in front of the gate (tools/cora_exec_bridge.py).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Optional

LOCK_NAME = "VENDOR.lock"
HERE = Path(__file__).resolve().parent / "subnetbus"
MULE = Path(__file__).resolve().parent / "mule"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_lock(root: Optional[Path] = None) -> dict:
    return json.loads(((Path(root) if root else HERE) / LOCK_NAME).read_text())


def verify(root: Optional[Path] = None) -> List[str]:
    """What is wrong with the vendored copy, as readable strings; [] means it is byte-for-byte what VENDOR.lock says."""
    d = Path(root) if root else HERE
    try:
        lock = read_lock(d)
        want = lock["files"]
    except (OSError, ValueError, KeyError) as e:
        return [f"{LOCK_NAME} unreadable: {e.__class__.__name__}: {e}"]
    problems: List[str] = []
    for name, digest in sorted(want.items()):
        p = d / name
        if not p.is_file():
            problems.append(f"missing: {name}")
        elif sha256_file(p) != digest:
            problems.append(f"modified: {name}")
    for p in sorted(d.rglob("*")):
        rel = p.relative_to(d).as_posix()
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc" and rel not in want and rel != LOCK_NAME:
            problems.append(f"unexpected file: {rel}")
    return problems


def describe(root: Optional[Path] = None) -> str:
    """One short line for logs: where it came from and whether it is intact."""
    try:
        lock = read_lock(root)
    except (OSError, ValueError):
        return f"vendored {Path(root).name if root else 'subnetbus'}: NO LOCK FILE"
    bad = verify(root)
    return (f"vendored {lock.get('name', 'subnetbus')} {lock.get('version', '?')} @ {str(lock.get('commit', '?'))[:7]} "
            + ("verified" if not bad else f"MODIFIED ({len(bad)} problem(s): {'; '.join(bad[:3])})"))
