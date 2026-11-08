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

    python tools/cora_exec_bridge.py < model_output.txt        # verdict as JSON; exit 0 ok, 1 rejected
"""
from __future__ import annotations

import ipaddress
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from cora_sentinel._vendor.subnetbus import AABB, Action, BusError, Registry, check_all

MULE_ERROR = None
try:
    from mule import MuleValidator, load_spec
except ImportError as e:                                  # not a dependency of cora-sentinel: a dev install
    MULE_ERROR = e

OPS = frozenset({"create", "set", "place"})
NAMESPACE = ipaddress.ip_network("10.2.0.0/16")          # v1: every other subnet is closed
TIME_SLOT = "SLOT_3_EXECUTE"
MULE_SPEC_VERSION = "1.1.0"                               # the slots this bridge and the grammar were written for
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


def make_validator() -> "MuleValidator":
    return MuleValidator(extensions=EXTENSIONS, allowed_ops=set(OPS), require_standard_exclusions=True)


class Bridge:
    def __init__(self, registry: Registry):
        self.registry = registry
        self._mule = None

    def _validator(self):
        if self._mule is None:
            if MULE_ERROR is not None:
                raise LookupError(f"mule-protocol is not importable ({MULE_ERROR}): pip install -e ~/mule-protocol")
            got = load_spec().get("schema_version")
            if got != MULE_SPEC_VERSION:
                raise LookupError(f"mule spec {got!r}, this bridge was written for {MULE_SPEC_VERSION}")
            self._mule = make_validator()
        return self._mule

    def process(self, raw: Any, expect: Optional[Dict[str, Any]] = None) -> Verdict:
        """Validate one raw model output. `expect` pins slots to harness values (e.g. {"ref": reserved_ip})."""
        try:
            return self._process(raw, expect)
        except Exception as e:                            # fail closed, never out of here
            return _no("INTERNAL", f"{e.__class__.__name__}: {e}"[:200])

    def _process(self, raw: Any, expect: Optional[Dict[str, Any]]) -> Verdict:
        try:
            mule = self._validator()
        except LookupError as e:
            return _no("MULE_UNAVAILABLE", str(e))
        ok, block, errors = mule.validate_raw(raw, expect={"time_slot": TIME_SLOT, **(expect or {})})
        if not ok:
            return _no("MULE_REJECT", "; ".join(errors))

        if not ipaddress.ip_network(block["subnet"]).subnet_of(NAMESPACE):
            return _no("SUBNET_CLOSED", f"{block['subnet']} is outside {NAMESPACE}, the only range open in v1")
        try:
            bounds = AABB(block["x"], block["y"], block["w"], block["h"])
        except BusError as e:
            return _no("BAD_PARAMS", f"{e.code}: {e.detail}")

        if not isinstance(self.registry, Registry):
            return _no("NO_REGISTRY", "no subnetbus Registry to check against")
        verdict = check_all(self.registry, block, Action(proposed_bounds=bounds))
        if not verdict.ok:
            f = verdict.failed
            return _no(f"{f.gate}:{f.code}", f.detail)

        node = self.registry.get(block["target"])
        if block["op"] == "create" and node.bounds is not None:
            return _no("CREATE_ALREADY_PLACED", f"{node.name} already exists with bounds: use set or place")
        if block["op"] in ("set", "place") and node.bounds is None:
            return _no("NOT_PLACED", f"{node.name} is only reserved: create it first")
        return Verdict(True, "OK", f"{block['op']} {block['target']} ({block['ref']}) in {block['subnet']} at "
                                   f"x={block['x']} y={block['y']} w={block['w']} h={block['h']}, "
                                   f"registry revision {verdict.revision}")


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
