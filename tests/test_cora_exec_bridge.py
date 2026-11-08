"""tools/cora_exec_bridge.py: raw model text -> mule-protocol -> policy -> subnetbus.check_all() -> Verdict.

Real mule-protocol and subnetbus throughout, both the vendored, pinned copies; nothing is mocked."""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from cora_sentinel._vendor.mule import load_spec

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("cora_exec_bridge", REPO / "tools" / "cora_exec_bridge.py")
bridge = importlib.util.module_from_spec(_spec)
sys.modules["cora_exec_bridge"] = bridge                  # dataclasses look their module up while it executes
_spec.loader.exec_module(bridge)

EXCLUDE = ["untyped_variables", "relative_paths_up_tree", "cross_subnet_queries", "freeform_code_blocks",
           "synthetic_transactions"]


def block(**over):
    b = {"frame_id": "0x00a1", "time_slot": "SLOT_3_EXECUTE", "subnet": "10.2.1.0/24", "op": "place",
         "target": "%Crate", "ref": "10.2.1.10", "exclude": EXCLUDE, "x": 500, "y": 500, "w": 50, "h": 50}
    b.update(over)
    return json.dumps(b, separators=(",", ":"))


@pytest.fixture
def reg():
    return bridge.demo_registry()


def run(raw, reg, **kw):
    return bridge.process(raw, reg, **kw)


def mule_accepts(raw):
    ok, _, errs = bridge.make_validator().validate_raw(raw, expect={"time_slot": bridge.TIME_SLOT})
    return ok, errs


# ---------------------------------------------------------------- mule-protocol: rejected, never repaired
@pytest.mark.parametrize("raw, why", [
    ("```json" + block() + "```", "markdown fence"),
    ("```json\n" + block() + "\n```", "control character"),          # the usual multi-line fence: the newline first
    ("Sure! Here is the action: " + block(), "must start with '{'"),
    (block() + " Let me know if you need more.", "must start with '{'"),
    ("<think>place it</think>" + block(), "must start with '{'"),
    (" " + block(), "must start with '{'"),                             # no edge-whitespace tolerance either
])
def test_fences_preambles_and_trailing_text_are_rejected(reg, raw, why):
    v = run(raw, reg)
    assert (v.ok, v.code) == (False, "MULE_REJECT")
    assert why in v.detail


def test_duplicate_keys_are_rejected_even_when_both_copies_agree(reg):
    raw = block()[:-1] + ',"op":"place"}'
    v = run(raw, reg)
    assert (v.code, "duplicate key 'op'" in v.detail) == ("MULE_REJECT", True)


@pytest.mark.parametrize("over, why", [
    ({"op": "delete"}, "not in allowed_ops"),
    ({"op": "release"}, "not in allowed_ops"),
    ({"w": 0}, "w: below minimum"),
    ({"h": 0}, "h: below minimum"),
    ({"w": bridge.SIZE_MAX + 1}, "w: above maximum"),
    ({"h": bridge.SIZE_MAX + 1}, "h: above maximum"),
    ({"x": -bridge.COORD_MAX - 1}, "x: below minimum"),
    ({"y": -bridge.COORD_MAX - 1}, "y: below minimum"),
    ({"x": bridge.COORD_MAX + 1}, "x: above maximum"),
    ({"y": bridge.COORD_MAX + 1}, "y: above maximum"),
    ({"x": 1.5}, "float"),
    ({"w": True}, "w: must be integer"),
    ({"y": "10"}, "y: must be integer"),
    ({"exclude": EXCLUDE[:4]}, "missing standard exclusions"),
    ({"time_slot": "SLOT_4_JUDGE"}, "time_slot' must equal harness value"),
    ({"target": "10.2.1.10"}, "target:"),                              # the old grammar's IP-as-target
    ({"ref": "10.2.9.10"}, "outside subnet"),
    ({"params": {}}, "unexpected key"),
])
def test_ops_and_param_boundaries(reg, over, why):
    v = run(block(**over), reg)
    assert v.code == "MULE_REJECT", v
    assert why in v.detail


# ---------------------------------------------------------------- v1 scope: only 10.2.0.0/16 is open
@pytest.mark.parametrize("subnet", ["10.1.0.0/16", "10.2.0.0/16"])
def test_a_sixteen_is_not_a_subnet(reg, subnet):
    v = run(block(subnet=subnet), reg)
    assert (v.code, "is not a valid ipv4_net24" in v.detail) == ("MULE_REJECT", True)


def test_10_1_is_closed_by_policy_even_where_the_bus_would_pass_it(reg):
    reg.add_subnet("10.1.5.0/24", world=bridge.AABB(0, 0, 1000, 1000))
    reg.allocate("%Legacy", "10.1.5.0/24", bounds=bridge.AABB(0, 0, 10, 10))      # 10.1.5.10
    raw = block(subnet="10.1.5.0/24", target="%Legacy", ref="10.1.5.10")
    assert mule_accepts(raw) == (True, [])
    task = json.loads(raw)
    assert bridge.check_all(reg, task, bridge.Action(proposed_bounds=bridge.AABB(500, 500, 50, 50))).ok
    v = run(raw, reg)
    assert (v.ok, v.code) == (False, "SUBNET_CLOSED")


# ---------------------------------------------------------------- valid ops reach subnetbus and pass
@pytest.fixture
def spy(monkeypatch):
    calls = []
    real = bridge.check_all

    def check_all(reg, task, action=None, **kw):
        out = real(reg, task, action, **kw)
        calls.append((task, action, out))
        return out
    monkeypatch.setattr(bridge, "check_all", check_all)
    return calls


@pytest.mark.parametrize("raw", [
    block(op="create", target="%Spawn", ref="10.2.1.12", x=600, y=600, w=40, h=40),
    block(op="set", w=60, h=60, x=100, y=100),                         # resize where it stands
    block(op="place", x=500, y=500),
    block(op="place", x=250, y=100, w=50, h=50),                       # touching %Wall's left edge is not overlap
])
def test_valid_create_set_place_pass_through_subnetbus(reg, spy, raw):
    v = run(raw, reg)
    assert (v.ok, v.code) == (True, "OK"), v
    assert len(spy) == 1
    task, action, verdict = spy[0]
    assert verdict.ok and [r.gate for r in verdict.results] == ["GI_1", "GI_2", "GI_3"]
    b = json.loads(raw)
    assert task["target"] == b["target"] and action.proposed_bounds == bridge.AABB(b["x"], b["y"], b["w"], b["h"])


def test_rejected_by_mule_never_reaches_subnetbus(reg, spy):
    assert run("```" + block() + "```", reg).code == "MULE_REJECT"
    assert run(block(subnet="10.1.5.0/24", ref="10.1.5.10"), reg).code == "SUBNET_CLOSED"
    assert spy == []


def test_expect_pins_ref_to_the_reservation(reg):
    raw = block(op="create", target="%Spawn", ref="10.2.1.12")
    assert run(raw, reg, expect={"ref": "10.2.1.12"}).ok
    v = run(raw, reg, expect={"ref": "10.2.1.13"})
    assert v.code == "MULE_REJECT" and "must equal harness value" in v.detail


# ---------------------------------------------------------------- subnetbus rejects what the local schema passed
@pytest.mark.parametrize("over, code", [
    ({"x": 310, "y": 150}, "GI_3:SOLID_OVERLAP"),                      # on top of %Wall
    ({"x": 990, "y": 500}, "GI_3:OUT_OF_WORLD"),                       # sticks out of the 1000x1000 world
    ({"x": -1, "y": 0}, "GI_3:OUT_OF_WORLD"),
    ({"ref": "10.2.1.11"}, "GI_1:REF_MISMATCH"),                       # %Wall's IP on %Crate
    ({"target": "%Ghost"}, "GI_1:UNKNOWN_TARGET"),
    ({"subnet": "10.2.9.0/24", "ref": "10.2.9.10"}, "GI_1:UNKNOWN_SUBNET"),
    ({"target": "%Other", "ref": "10.2.1.10"}, "GI_1:REF_MISMATCH"),   # a node of another subnet, claimed here
])
def test_subnetbus_rejects_geometry_and_containment_the_schema_passed(reg, over, code):
    raw = block(**over)
    assert mule_accepts(raw) == (True, []), "must pass the local schema, or this proves nothing about the bus"
    v = run(raw, reg)
    assert (v.ok, v.code) == (False, code), v


def test_a_rejection_changes_nothing(reg):
    before = (reg.revision, reg.fingerprint())
    run(block(x=310, y=150), reg)
    run(block(x=500, y=500), reg)
    assert (reg.revision, reg.fingerprint()) == before                 # validation only: no staging, no commit


# ---------------------------------------------------------------- lifecycle
def test_create_needs_a_reservation_and_place_needs_a_placed_node(reg):
    assert run(block(op="create"), reg).code == "CREATE_ALREADY_PLACED"
    assert run(block(op="place", target="%Spawn", ref="10.2.1.12"), reg).code == "NOT_PLACED"
    assert run(block(op="set", target="%Spawn", ref="10.2.1.12"), reg).code == "NOT_PLACED"


# ---------------------------------------------------------------- never raises
@pytest.mark.parametrize("raw", [None, 42, b"{}", ["{}"], "", "{", "[" * 5000, "{" * 5000 + "}" * 5000,
                                 "x" * 100_000, "{\"\\u0000\":1}", "{}", block()[:-1]])
def test_process_never_raises_on_junk(reg, raw):
    v = run(raw, reg)
    assert isinstance(v, bridge.Verdict) and not v.ok


def test_process_never_raises_without_a_registry():
    v = bridge.process(block(), None)
    assert (v.ok, v.code) == (False, "NO_REGISTRY")


def test_a_fault_inside_the_pipeline_is_a_failed_verdict(reg, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("nft on fire")
    monkeypatch.setattr(bridge, "check_all", boom)
    v = run(block(), reg)
    assert (v.ok, v.code) == (False, "INTERNAL") and "nft on fire" in v.detail


def test_wrong_mule_spec_fails_closed(reg, monkeypatch):
    monkeypatch.setattr(bridge, "load_spec", lambda: {"schema_version": "9.0.0"})
    v = run(block(), reg)
    assert (v.ok, v.code) == (False, "MULE_UNAVAILABLE") and "9.0.0" in v.detail


# ---------------------------------------------------------------- the grammar agrees with the bridge
GBNF = (REPO / "grammar" / "cora_action.gbnf").read_text()


def rule(name):
    m = re.search(rf"^{name}\s+::=\s+(.+)$", GBNF, re.M)
    assert m, f"no rule {name}"
    return m.group(1)


def test_grammar_emits_exactly_the_mule_slots_in_one_fixed_order():
    keys = re.findall(r'\\"([a-z_]+)\\":', rule("root"))
    assert keys == list(load_spec()["slots"]) + list(bridge.EXTENSIONS)


def test_grammar_constants_match_the_bridge_and_mule():
    assert json.loads(json.loads('"' + rule("exclude")[1:-1] + '"')) == load_spec()["standard_exclusions"]
    assert set(re.findall(r'\\"([a-z]+)\\"', rule("op"))) == bridge.OPS
    assert f'\\"time_slot\\":\\"{bridge.TIME_SLOT}\\"' in rule("root")
    assert rule("subnet") == '"\\"10.2." octet ".0/24\\""'
    assert rule("coord") == '"-"? ([0-9] | [1-9] [0-9]{0,5})' and bridge.COORD_MAX == 999_999
    assert rule("size") == "[1-9] [0-9]{0,4}" and bridge.SIZE_MAX == 99_999


def test_the_bridge_uses_the_vendored_mule_whatever_else_is_installed():
    assert bridge.MuleValidator.__module__ == "cora_sentinel._vendor.mule.validator"
    assert bridge.load_spec.__module__ == "cora_sentinel._vendor.mule"
