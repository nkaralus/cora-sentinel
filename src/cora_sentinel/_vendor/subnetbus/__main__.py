"""CLI.  python -m subnetbus <command> FILE ...   Exit: 0 ok, 1 rejected, 2 error."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import AABB, Action, BusError, PathGuard, Registry, check_all


def _box(s: str) -> AABB:
    try:
        x, y, w, h = (float(v) for v in s.split(","))
    except ValueError:
        raise BusError("BAD_BOUNDS", "use x,y,w,h") from None
    return AABB(x, y, w, h)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="subnetbus")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init");        s.add_argument("file")
    s = sub.add_parser("add-subnet");  s.add_argument("file"); s.add_argument("cidr")
    s.add_argument("--label", default=""); s.add_argument("--reserved-below", type=int, default=10)
    s.add_argument("--world")
    s = sub.add_parser("alloc");       s.add_argument("file"); s.add_argument("name"); s.add_argument("subnet")
    s.add_argument("--ip"); s.add_argument("--kind", default="scene_node"); s.add_argument("--bounds")
    s.add_argument("--no-solid", action="store_true"); s.add_argument("--path")
    s = sub.add_parser("release");     s.add_argument("file"); s.add_argument("name")
    s = sub.add_parser("show");        s.add_argument("file")
    s = sub.add_parser("validate");    s.add_argument("file")
    s = sub.add_parser("check");       s.add_argument("file"); s.add_argument("--task", required=True)
    s.add_argument("--bounds"); s.add_argument("--path", action="append", default=[])
    s.add_argument("--ref", action="append", default=[]); s.add_argument("--fs-op"); s.add_argument("--fs-root")
    a = p.parse_args(argv)
    try:
        if a.cmd == "init":
            Registry().save(a.file)
            return 0
        reg = Registry.load(a.file)
        if a.cmd == "add-subnet":
            reg.add_subnet(a.cidr, label=a.label, reserved_below=a.reserved_below,
                           world=_box(a.world) if a.world else None)
        elif a.cmd == "alloc":
            n = reg.allocate(a.name, a.subnet, kind=a.kind, ip=a.ip, bounds=_box(a.bounds) if a.bounds else None,
                             solid=not a.no_solid, path=a.path)
            print(f"{n.name} {n.ip}")
        elif a.cmd == "release":
            reg.release(a.name)
        elif a.cmd == "show":
            print(json.dumps(reg.to_dict(), indent=2))
            return 0
        elif a.cmd == "validate":
            errs = reg.validate()
            print("\n".join(errs) if errs else "OK")
            return 1 if errs else 0
        elif a.cmd == "check":
            guard = PathGuard(a.fs_root) if a.fs_root else None
            act = Action(refs=tuple(a.ref), paths=tuple(a.path), fs_op=a.fs_op,
                         proposed_bounds=_box(a.bounds) if a.bounds else None)
            v = check_all(reg, json.loads(a.task), act, fs_guard=guard)
            print(json.dumps({"ok": v.ok, "revision": v.revision,
                              "results": [r.__dict__ for r in v.results]}))
            return 0 if v.ok else 1
        if a.cmd in ("add-subnet", "alloc", "release"):
            reg.save(a.file)
        return 0
    except (BusError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
