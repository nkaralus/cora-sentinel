"""Gate Invariants. Pure functions: (registry, task, action) -> GateResult. Fail closed.

  GI_1  boundary    target, ref, subnet and every extra ref exist in the registry
  GI_2  isolation   nothing leaves the declared subnet; paths contain no traversal
  GI_3  safety      pre-commit AABB overlap guard + filesystem guard

`task` is any mapping with str fields subnet, target, ref (a validated Mule block fits).
`action` carries facts the HARNESS extracted. Never feed it raw model text.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from .errors import BusError, PathError, show
from .fsguard import PathGuard, lexical_segments
from .geometry import AABB
from .registry import Registry

__all__ = ["Action", "GateResult", "Verdict", "gi_1", "gi_2", "gi_3", "check_all"]


@dataclass(frozen=True)
class Action:
    refs: Tuple[str, ...] = ()                 # extra node names / IPs the operation touches
    paths: Tuple[str, ...] = ()                # project-relative paths the operation touches
    fs_op: Optional[str] = None                # read/write/delete/... applied to `paths`
    proposed_bounds: Optional[AABB] = None     # where the target will be after the operation

    def __post_init__(self):
        object.__setattr__(self, "refs", tuple(self.refs))
        object.__setattr__(self, "paths", tuple(self.paths))
        if not all(type(r) is str for r in self.refs) or not all(type(p) is str for p in self.paths):
            raise TypeError("refs and paths must be strings")
        if self.proposed_bounds is not None and not isinstance(self.proposed_bounds, AABB):
            raise TypeError("proposed_bounds must be an AABB")


@dataclass(frozen=True)
class GateResult:
    """No __bool__ on purpose: `if verdict.failed:` must mean "something failed". Test `.ok`."""
    gate: str
    ok: bool
    code: str = "OK"
    detail: str = ""


@dataclass(frozen=True)
class Verdict:
    ok: bool
    results: Tuple[GateResult, ...]
    revision: int

    @property
    def failed(self) -> Optional[GateResult]:
        return next((r for r in self.results if not r.ok), None)

    def still_valid(self, reg: Registry) -> bool:
        """TOCTOU check: call right before committing. False if the registry changed."""
        return self.ok and reg.revision == self.revision


def _ok(g: str) -> GateResult:
    return GateResult(g, True)


def _no(g: str, code: str, detail: str = "") -> GateResult:
    return GateResult(g, False, code, detail)


def _fields(task: Any) -> Optional[Tuple[str, str, str]]:
    if not isinstance(task, Mapping):
        return None
    vals = tuple(task.get(k) for k in ("subnet", "target", "ref"))
    return vals if all(type(v) is str for v in vals) else None


def gi_1(reg: Registry, task: Mapping, action: Action = Action()) -> GateResult:
    f = _fields(task)
    if f is None:
        return _no("GI_1", "MALFORMED_TASK", "subnet, target and ref must be strings")
    subnet, target, ref = f
    if reg.subnet(subnet) is None:
        return _no("GI_1", "UNKNOWN_SUBNET", show(subnet))
    node = reg.get(target)
    if node is None:
        return _no("GI_1", "UNKNOWN_TARGET", show(target))
    if node.ip != ref:
        return _no("GI_1", "REF_MISMATCH", f"{target} is bound to {node.ip}, task says {show(ref)}")
    for r in action.refs:
        if reg.resolve(r) is None:
            return _no("GI_1", "UNKNOWN_REF", show(r))
    return _ok("GI_1")


def gi_2(reg: Registry, task: Mapping, action: Action = Action()) -> GateResult:
    f = _fields(task)
    node = reg.get(f[1]) if f else None
    if f is None or node is None:
        return _no("GI_2", "UNRESOLVED_TASK", "run GI_1 first")
    subnet = f[0]
    if node.subnet != subnet:
        return _no("GI_2", "CROSS_SUBNET_TARGET", f"{node.name} lives in {node.subnet}, task says {subnet}")
    for r in action.refs:
        other = reg.resolve(r)
        if other is None:
            return _no("GI_2", "UNRESOLVED_REF", show(r))
        if other.subnet != subnet:
            return _no("GI_2", "CROSS_SUBNET_REF", f"{other.name} lives in {other.subnet}")
    for p in action.paths:
        try:
            lexical_segments(p)
        except PathError as e:
            return _no("GI_2", e.code, e.detail)
    return _ok("GI_2")


def gi_3(reg: Registry, task: Mapping, action: Action = Action(), *,
         fs_guard: Optional[PathGuard] = None) -> GateResult:
    f = _fields(task)
    node = reg.get(f[1]) if f else None
    if f is None or node is None:
        return _no("GI_3", "UNRESOLVED_TASK", "run GI_1 first")
    if action.proposed_bounds is not None:
        problems = reg.placement_problems(node.subnet, action.proposed_bounds,
                                          ignore=node.name, solid=node.solid)
        if problems:
            return _no("GI_3", problems[0][0], problems[0][1])
    if action.paths:
        if fs_guard is None:
            return _no("GI_3", "NO_FS_GUARD", "paths supplied but no PathGuard configured")
        if action.fs_op is None:
            return _no("GI_3", "NO_FS_OP", "paths supplied without fs_op")
        for p in action.paths:
            try:
                fs_guard.check(p, action.fs_op)
            except BusError as e:
                return _no("GI_3", e.code, e.detail)
    return _ok("GI_3")


def check_all(reg: Registry, task: Mapping, action: Optional[Action] = None, *,
              fs_guard: Optional[PathGuard] = None, fail_fast: bool = True) -> Verdict:
    action = action or Action()
    results = []
    for gate in (lambda: gi_1(reg, task, action), lambda: gi_2(reg, task, action),
                 lambda: gi_3(reg, task, action, fs_guard=fs_guard)):
        r = gate()
        results.append(r)
        if not r.ok and fail_fast:
            break
    return Verdict(all(r.ok for r in results), tuple(results), reg.revision)
