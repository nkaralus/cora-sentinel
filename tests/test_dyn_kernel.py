"""0.6.0 on a real kernel: the dynamic policy's decisions really cut (and stop cutting) real traffic.

The lab is test_floor_gate's (two namespaces, a throwaway table). The target must be a GLOBAL address, because the policy
refuses private ones by design, so the server namespace also answers for 45.33.32.156 (a public address, aliased on its
veth and routed to from the client); the listener binds 0.0.0.0 so both it and the lab's private address work.
Skips without root, nft and `ip netns`. Run: sudo -E $(which python) -m pytest -q tests/test_dyn_kernel.py
"""
import time

import pytest

from cora_sentinel import dynpolicy
from cora_sentinel.dynpolicy import DynConfig, DynPolicy

from test_dynpolicy import mk
from test_floor_gate import PORT, S_IP, TABLE, Lab, kernel, ns_runner, sh

G = "45.33.32.156"
KEY = lambda port, proto="tcp": f"{G}|{proto}|{port}"            # noqa: E731


@pytest.fixture
def lab(tmp_path):
    lb = Lab(tmp_path, ports=(PORT, 80, 443, 8080, 9090), bind="0.0.0.0")
    sh("ip", "-n", lb.s, "addr", "add", f"{G}/32", "dev", lb.vs)
    sh("ip", "-n", lb.c, "route", "add", f"{G}/32", "via", S_IP)
    yield lb
    lb.close()


def setup(lab, tmp_path, mode="enforce", **cfg):
    floor = lab.floor(lab.c)
    pol = DynPolicy(mode, sets=floor, state_dir=str(tmp_path / "st"), log=lambda m: None,
                    cfg=DynConfig(write_per_min=1000, task_cap=1000, **cfg))
    return floor, pol


def hit(pol, task="t0", port=443, **kw):
    return pol.consider(*mk(task=task, ip=G, port=port, **kw))


@kernel
def test_the_lab_reaches_the_public_address(lab):
    assert lab.connect(3, 8080, ip=G) == 3                            # the control for everything below


@kernel
def test_a_model_isolate_cuts_the_flow_only_and_the_kernel_expires_it(lab, tmp_path):
    floor, pol = setup(lab, tmp_path, flow_base_s=3)
    assert hit(pol, port=8080)["result"] == "blocked"
    assert lab.connect(5, 8080, ip=G) == 0                            # the first packet to the flow is already dropped
    assert lab.connect(5, 9090, ip=G) == 5                            # the same address, another port: untouched
    assert lab.connect(5, 8080, ip=S_IP) == 5                         # the lab's other address: untouched
    assert floor.live_flows() == {KEY(8080)}                          # the real nft JSON round-trips into the ledger's key
    time.sleep(3.6)
    assert lab.connect(5, 8080, ip=G) == 5, "the kernel did not expire the element"


@kernel
def test_web_ports_stay_flow_only_even_with_several_tasks_and_a_repeat_offense_extends_the_ttl(lab, tmp_path):
    floor, pol = setup(lab, tmp_path, flow_base_s=2)
    t0 = time.time()
    assert hit(pol, "a", 443)["ttl_s"] == 2
    time.sleep(1.0)
    r = hit(pol, "b", 443)                                            # a new task on the active block: offense 2, ttl x4
    assert r["result"] == "refreshed" and r["ttl_s"] == 8 and r["kind"] == "flow"
    hit(pol, "c", 443)
    assert floor.status()["dyn4"] == 0, "a web address was promoted to a whole-address block"
    time.sleep(max(0.0, 3.0 - (time.time() - t0)))                    # past the ORIGINAL 2 s: only the refresh keeps it
    assert lab.connect(5, 443, ip=G) == 0, "the refreshed element expired at its old deadline"
    assert lab.connect(5, 80, ip=G) == 5                              # port 80 of the same address was never listed


@kernel
def test_two_distinct_tasks_on_non_web_ports_block_the_whole_address(lab, tmp_path):
    floor, pol = setup(lab, tmp_path)
    assert hit(pol, "a", 8080)["kind"] == "flow"
    assert hit(pol, "b", 9090)["result"] == "promoted"
    assert floor.live_ips() == {G}
    assert lab.connect(5, PORT, ip=G) == 0 and lab.connect(5, 80, ip=G) == 0     # every port of it, even ones nobody hit
    assert lab.connect(5, PORT, ip=S_IP) == 5                                    # but not the lab's other address


@kernel
def test_release_restores_traffic_at_once(lab, tmp_path):
    floor, pol = setup(lab, tmp_path)
    hit(pol, "a", 8080)
    assert lab.connect(5, 8080, ip=G) == 0
    assert dynpolicy.release_entries("a", str(tmp_path / "st"), floor) == [f"dyn-flow-unblocked:{KEY(8080)}"]
    assert lab.connect(5, 8080, ip=G) == 5 and floor.live_flows() == set()


@kernel
def test_an_operator_unblock_is_noticed_and_the_next_hit_blocks_again(lab, tmp_path):
    floor, pol = setup(lab, tmp_path)
    hit(pol, "a", 8080)
    assert floor.unblock_flow(G, "tcp", 8080) is True                 # cora-floor / a flush, behind the ledger's back
    assert lab.connect(3, 8080, ip=G) == 3
    assert pol.reconcile() == 1
    assert hit(pol, "a", 8080)["result"] == "blocked" and lab.connect(5, 8080, ip=G) == 0


@kernel
def test_shadow_decides_everything_and_changes_nothing(lab, tmp_path):
    floor, pol = setup(lab, tmp_path, mode="shadow")
    assert hit(pol, "a", 8080)["result"] == "would_block" and hit(pol, "b", 9090)["result"] == "would_promote"
    assert lab.connect(5, 8080, ip=G) == 5 and lab.connect(5, 9090, ip=G) == 5
    assert floor.live_flows() == set() and floor.live_ips() == set()
