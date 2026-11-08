#!/usr/bin/env python3
"""
cora_exec_bridge - the front half of cora-exec: raw model text in, a Verdict out. Validation only: nothing here
executes, stages, or launches anything.

    raw text ─► mule-protocol ─► cora policy ─► subnetbus.check_all() ─► lifecycle ─► Verdict(ok, code, detail)
                (syntax)         (v1 scope)     (registry, isolation,     (create vs
                                                 geometry)                 set/place)

The model is constrained by grammar/cora_action.gbnf (layer 1), but nothing here trusts that it was:

  mule-protocol   MuleValidator.validate_raw with the packaged spec (1.1.0), allowed_ops {create, set, place}, the
                  standard exclusions required, and x/y/w/h as integer extension slots. It REJECTS (never strips)
                  markdown fences, preamble or trailing text, <think> blocks, control characters, backslashes,
                  duplicate keys, extra keys, floats, NaN, bool-as-int, ref outside subnet, oversize input.
  policy          v1 opens only 10.2.0.0/16 (mule accepts any /24 inside 10.0.0.0/8); time_slot must be
                  SLOT_3_EXECUTE.
  subnetbus       check_all(registry, block, Action(proposed_bounds=AABB(x, y, w, h))): GI_1 target, subnet and
                  ref exist and agree, GI_2 nothing crosses the subnet, GI_3 the bounds stay inside the subnet's
                  world and overlap no solid node.
  lifecycle       "create" needs a node the harness RESERVED (allocated, no bounds yet: the IP the model must echo
                  as ref comes from that reservation); "set" and "place" need a node that already has bounds. To the
                  gates, set and place are the same claim: the target ends up at (x, y, w, h).

process() never raises (KeyboardInterrupt aside): any fault is a failed Verdict with code INTERNAL. The registry
is the caller's, in memory; demo_registry() builds the one the CLI and tests use.

mint() is process() plus, on OK, the immutable Ticket the staging harness (tools/cora_stage_harness.py) consumes:
{id: uuid4, digest: sha256 of the raw text, action: the validated block, registry_rev: the revision it was checked
against, minted_ts: {mono, wall}, ttl_s: 60}.

    python tools/cora_exec_bridge.py < model_output.txt        # verdict as JSON; exit 0 ok, 1 rejected
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

from cora_sentinel._vendor.mule import MuleValidator, load_spec         # vendored and pinned, like the bus
from cora_sentinel._vendor.subnetbus import AABB, Action, BusError, Registry, check_all

OPS = frozenset({"create", "set", "place"})
NAMESPACE = ipaddress.ip_network("10.2.0.0/16")          # v1: every other subnet is closed
TIME_SLOT = "SLOT_3_EXECUTE"
MULE_SPEC_VERSION = "1.1.0"                               # the slots this bridge and the grammar were written for
TICKET_TTL_S = 60
COORD_MAX = 999_999
SIZE_MAX = 99_999
EXTENSIONS = {"x": {"type": "integer", "minimum": -COORD_MAX, "maximum": COORD_MAX},
              "y": {"type": "integer", "minimum": -COORD_MAX, "maximum": COORD_MAX},
              "w": {"type": "integer", "minimum": 1, "maximum": SIZE_MAX},
              "h": {"type": "integer", "minimum": 1, "maximum": SIZE_MAX}}


@dataclass(frozen=True)
class Verdict:
    ok: bool
    code: str
    detail: str = ""


def _no(code: str, detail: str = "") -> Verdict:
    return Verdict(False, code, detail)


def _freeze(v: Any) -> Any:
    if isinstance(v, (list, tuple)):
        return tuple(_freeze(x) for x in v)
    if isinstance(v, Mapping):
        return MappingProxyType({k: _freeze(x) for k, x in v.items()})
    return v


def _thaw(v: Any) -> Any:
    if isinstance(v, tuple):
        return [_thaw(x) for x in v]
    if isinstance(v, Mapping):
        return {k: _thaw(x) for k, x in v.items()}
    return v


@dataclass(frozen=True)
class Ticket:
    """Minted only by Bridge.mint() for an OK verdict. Read-only all the way down (the action is a mapping proxy)."""
    id: str
    digest: str
    action: Mapping[str, Any]
    registry_rev: int
    minted_ts: Mapping[str, float]
    ttl_s: int = TICKET_TTL_S

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "digest": self.digest, "action": _thaw(self.action), "registry_rev": self.registry_rev,
                "minted_ts": dict(self.minted_ts), "ttl_s": self.ttl_s}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Ticket":
        """For journal replay. Raises ValueError on anything that is not a ticket's shape."""
        if not isinstance(d, Mapping) or set(d) != {"id", "digest", "action", "registry_rev", "minted_ts", "ttl_s"}:
            raise ValueError("not a ticket")
        if (type(d["id"]) is not str or type(d["digest"]) is not str or len(d["digest"]) != 64
                or not isinstance(d["action"], Mapping) or type(d["registry_rev"]) is not int
                or type(d["ttl_s"]) is not int or not isinstance(d["minted_ts"], Mapping)):
            raise ValueError("not a ticket")
        return cls(d["id"], d["digest"], _freeze(d["action"]), d["registry_rev"],
                   MappingProxyType(dict(d["minted_ts"])), d["ttl_s"])

    def expired(self, now_mono: Optional[float] = None, now_wall: Optional[float] = None) -> bool:
        """Past its TTL by EITHER clock. The monotonic clock restarts at boot, so a negative age also counts."""
        age_m = (time.monotonic() if now_mono is None else now_mono) - self.minted_ts["mono"]
        age_w = (time.time() if now_wall is None else now_wall) - self.minted_ts["wall"]
        return not (0 <= age_m <= self.ttl_s) or age_w > self.ttl_s


def make_validator() -> "MuleValidator":
    return MuleValidator(extensions=EXTENSIONS, allowed_ops=set(OPS), require_standard_exclusions=True)


class Bridge:
    def __init__(self, registry: Registry):
        self.registry = registry
        self._mule = None

    def _validator(self):
        if self._mule is None:
            got = load_spec().get("schema_version")
            if got != MULE_SPEC_VERSION:
                raise LookupError(f"mule spec {got!r}, this bridge was written for {MULE_SPEC_VERSION}")
            self._mule = make_validator()
        return self._mule

    def process(self, raw: Any, expect: Optional[Dict[str, Any]] = None) -> Verdict:
        """Validate one raw model output. `expect` pins slots to harness values (e.g. {"ref": reserved_ip})."""
        return self.mint(raw, expect)[0]

    def mint(self, raw: Any, expect: Optional[Dict[str, Any]] = None) -> Tuple[Verdict, Optional[Ticket]]:
        """(verdict, ticket): the ticket only for an OK verdict, else None. Never raises."""
        try:
            verdict, block, rev = self._process(raw, expect)
            if not verdict.ok:
                return verdict, None
            return verdict, Ticket(str(uuid.uuid4()), hashlib.sha256(raw.encode("ascii")).hexdigest(), _freeze(block),
                                   rev, MappingProxyType({"mono": time.monotonic(), "wall": time.time()}))
        except Exception as e:                            # fail closed, never out of here
            return _no("INTERNAL", f"{e.__class__.__name__}: {e}"[:200]), None

    def _process(self, raw: Any, expect: Optional[Dict[str, Any]]) -> Tuple[Verdict, Optional[dict], Optional[int]]:
        def no(code, detail=""):
            return _no(code, detail), None, None
        try:
            mule = self._validator()
        except LookupError as e:
            return no("MULE_UNAVAILABLE", str(e))
        ok, block, errors = mule.validate_raw(raw, expect={"time_slot": TIME_SLOT, **(expect or {})})
        if not ok:
            return no("MULE_REJECT", "; ".join(errors))

        if not ipaddress.ip_network(block["subnet"]).subnet_of(NAMESPACE):
            return no("SUBNET_CLOSED", f"{block['subnet']} is outside {NAMESPACE}, the only range open in v1")
        try:
            bounds = AABB(block["x"], block["y"], block["w"], block["h"])
        except BusError as e:
            return no("BAD_PARAMS", f"{e.code}: {e.detail}")

        if not isinstance(self.registry, Registry):
            return no("NO_REGISTRY", "no subnetbus Registry to check against")
        verdict = check_all(self.registry, block, Action(proposed_bounds=bounds))
        if not verdict.ok:
            f = verdict.failed
            return no(f"{f.gate}:{f.code}", f.detail)

        node = self.registry.get(block["target"])
        if block["op"] == "create" and node.bounds is not None:
            return no("CREATE_ALREADY_PLACED", f"{node.name} already exists with bounds: use set or place")
        if block["op"] in ("set", "place") and node.bounds is None:
            return no("NOT_PLACED", f"{node.name} is only reserved: create it first")
        return (Verdict(True, "OK", f"{block['op']} {block['target']} ({block['ref']}) in {block['subnet']} at "
                                    f"x={block['x']} y={block['y']} w={block['w']} h={block['h']}, "
                                    f"registry revision {verdict.revision}"), block, verdict.revision)


def process(raw: Any, registry: Registry, expect: Optional[Dict[str, Any]] = None) -> Verdict:
    return Bridge(registry).process(raw, expect)


def demo_registry() -> Registry:
    """10.2.1.0/24 with a 1000x1000 world: %Crate and %Wall placed, %Spawn reserved. 10.2.2.0/24 holds %Other."""
    reg = Registry()
    reg.add_subnet("10.2.1.0/24", label="arena", world=AABB(0, 0, 1000, 1000))
    reg.add_subnet("10.2.2.0/24", label="lobby")
    reg.allocate("%Crate", "10.2.1.0/24", bounds=AABB(100, 100, 50, 50))        # 10.2.1.10
    reg.allocate("%Wall", "10.2.1.0/24", bounds=AABB(300, 100, 20, 200))        # 10.2.1.11
    reg.allocate("%Spawn", "10.2.1.0/24")                                        # 10.2.1.12, reserved
    reg.allocate("%Other", "10.2.2.0/24", bounds=AABB(0, 0, 10, 10))            # 10.2.2.10
    return reg


def main() -> int:
    v = process(sys.stdin.read().rstrip("\n"), demo_registry())
    print(json.dumps(asdict(v)))
    return 0 if v.ok else 1


if __name__ == "__main__":
    sys.exit(main())
