"""The dynamic policy (model ISOLATE -> short-lived kernel drops) without a kernel: a fake nft, a fake clock, a real
ledger file. Real-packet versions are in test_dyn_kernel.py. Run: pytest -q tests/test_dynpolicy.py"""
import json

import pytest

from cora_sentinel import dynpolicy, nftsets
from cora_sentinel.daemon import build_payload, read_starttime
from cora_sentinel.dynpolicy import DynConfig, DynLedger, DynPolicy
from cora_sentinel.firewall import FirewallError, release_task
from cora_sentinel.nftsets import FloorSync, NftSets

from test_nftsets import FakeNft, bl_with
from test_verdict import FakeFw, GateModel, pipeline, procs, verdict      # noqa: F401  (procs is a fixture)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def mk(task="t0", ip="45.33.32.156", port=443, proto="tcp", conf=0.95, action="done:ISOLATE@cgroup:t0[nft-drop-egress]",
       dest_class="public", blocklist=False, model="ISOLATE", final="ISOLATE"):
    evd = {"remote_ip": ip, "remote_port": port, "local_port": 40000, "dest_class": dest_class}
    if proto != "tcp":
        evd["proto"] = proto
    if blocklist:
        evd["blocklist"] = {"list": "x", "kind": "rogue_subnet", "entry": ip}
    ev = {"anomaly": {"kind": "unauthorized_connection", "evidence": evd},
          "subject": {"cgroup": task, "name": "n", "pid": 1}}
    d = {"final": final, "action": action, "model": {"verdict": model, "confidence": conf, "reason": "t"}}
    return ev, d


@pytest.fixture
def env(tmp_path):
    class E:
        pass
    e = E()
    e.fake, e.clock, e.dir = FakeNft(), Clock(), str(tmp_path / "state")
    e.sets = NftSets(run=e.fake)
    e.policy = lambda mode="enforce", **kw: DynPolicy(mode, sets=e.sets, state_dir=e.dir, clock=e.clock,
                                                       log=lambda m: None, **kw)
    e.kernel = lambda: [s for s in e.fake.scripts if "element" in s]
    return e


def go(p, **kw):
    return p.consider(*mk(**kw))


# ================= who is eligible =================
def test_off_and_non_isolate_and_non_model_isolates_are_none(env):
    assert go(env.policy("off")) is None
    assert go(env.policy(), final="ESCALATE") is None                     # "needs a human" never writes
    assert go(env.policy(), final="THROTTLE", model="THROTTLE") is None
    assert go(env.policy(), model="ESCALATE") is None                     # isolated by the floor, not the model


@pytest.mark.parametrize("kw,reason", [
    ({"action": "blocked"}, "not_acted"), ({"action": "needs-human"}, "not_acted"),
    ({"action": "failed:FirewallError@cgroup:t0"}, "not_acted"),
    ({"blocklist": True}, "blocklist"), ({"conf": 0.85}, "low_confidence"),
    ({"dest_class": "private"}, "dest_class:private"), ({"dest_class": "link_local"}, "dest_class:link_local"),
    ({"ip": "10.1.2.3"}, "dest_class:public"),                           # a lying class does not make it global
    ({"port": 53}, "infra_port"), ({"port": 853}, "infra_port"), ({"port": 123, "proto": "udp"}, "infra_port"),
    ({"proto": "icmp"}, "bad_flow"), ({"port": 0}, "bad_flow"), ({"port": 70000}, "bad_flow"),
    ({"ip": ""}, "no_destination"), ({"ip": "not-an-ip"}, "no_destination")])
def test_ineligible_decisions_are_skipped_with_a_reason_and_write_nothing(env, kw, reason):
    r = go(env.policy(), **kw)
    assert r["result"] == "skipped" and r["reason"].startswith(reason.split(":")[0]), r
    assert env.kernel() == []


def test_exempt_addresses_are_never_blocked(env):
    p = env.policy(exempt=lambda ip: "allowed:1.2.3.0/24" if ip == "45.33.32.156" else None)
    assert go(p)["reason"] == "allowed:1.2.3.0/24" and env.kernel() == []
    assert go(p, ip="45.33.33.9")["result"] == "blocked"


def test_confidence_threshold_is_configurable_and_inclusive(env):
    assert go(env.policy(cfg=DynConfig(min_conf=0.95)), conf=0.95)["result"] == "blocked"
    assert go(env.policy(cfg=DynConfig(min_conf=0.95)), ip="45.33.33.9", conf=0.94)["reason"] == "low_confidence"


# ================= shadow is the default and touches nothing =================
def test_shadow_records_would_block_and_leaves_the_kernel_alone(env):
    p = env.policy("shadow")
    r = go(p)
    assert r == {"mode": "shadow", "web": True, "port": 443, "proto": "tcp", "result": "would_block", "kind": "flow",
                 "key": "45.33.32.156|tcp|443", "ttl_s": 600, "offense": 1, "tasks": 1}
    assert env.kernel() == []
    assert (__import__("pathlib").Path(env.dir) / "dyn-ledger-shadow.json").exists()


def test_enforce_stays_shadow_while_the_adjudicator_is_only_dry_running(env):
    r = go(env.policy("enforce"), action="dry-run:ISOLATE@cgroup:t0")
    assert r["mode"] == "shadow" and r["result"] == "would_block" and env.kernel() == []


def test_enforce_without_a_kernel_handle_is_shadow(env):
    p = DynPolicy("enforce", sets=None, state_dir=env.dir, clock=env.clock, log=lambda m: None)
    assert go(p)["mode"] == "shadow"


def test_enforce_writes_the_flow_with_its_ttl(env):
    r = go(env.policy("enforce"))
    assert r["result"] == "blocked" and r["mode"] == "enforce"
    assert "add element inet cora dynflow4 { 45.33.32.156 . tcp . 443 timeout 600s }" in env.kernel()[-1]


def test_ipv6_ipv4_mapped_and_udp_quic(env):
    p = env.policy("enforce")
    go(p, ip="2606:4700::1", port=443)
    assert "dynflow6 { 2606:4700::1 . tcp . 443 timeout 600s }" in env.kernel()[-1]
    go(p, ip="::ffff:45.33.33.4", port=443, proto="udp")
    assert "dynflow4 { 45.33.33.4 . udp . 443 timeout 600s }" in env.kernel()[-1]


# ================= flow, escalation, web ports =================
def test_the_same_task_hitting_the_same_flow_again_is_deduplicated(env):
    p = env.policy("enforce")
    go(p)
    r = go(p)
    assert r["result"] == "dedupe" and len(env.kernel()) == 1


def test_a_new_task_on_an_active_block_is_a_repeat_offense_and_escalates_x4_to_the_cap(env):
    p = env.policy("enforce")
    ttls = [go(p, task=f"t{i}")["ttl_s"] for i in range(6)]
    assert ttls == [600, 2400, 9600, 38400, 86400, 86400]
    assert all("dyn4" not in s and "timeout" in s for s in env.kernel())
    assert "dynflow4" in env.kernel()[1] and "timeout 2400s" in env.kernel()[1]      # the refresh re-adds with the new ttl


@pytest.mark.parametrize("port", [80, 443])
def test_web_ports_never_become_a_whole_address_block(env, port):
    p = env.policy("enforce")
    for i in range(5):
        r = go(p, task=f"t{i}", port=port)
        assert r["kind"] == "flow"
    assert not any(" dyn4 " in s or "dyn4 {" in s for s in env.kernel())


def test_a_hit_after_expiry_escalates_and_the_memory_lasts_a_week(env):
    p = env.policy("enforce")
    go(p, task="a")
    env.clock.advance(601)                                                # expired in the kernel and the ledger
    r = go(p, task="b")
    assert r["result"] == "blocked" and r["offense"] == 2 and r["ttl_s"] == 2400
    env.clock.advance(2401 + 8 * 86400)                                   # long quiet: forgotten
    assert go(p, task="c")["offense"] == 1


# ================= non-web ports: flow first, whole address on two tasks =================
def test_two_distinct_tasks_on_non_web_ports_promote_to_the_whole_address(env):
    p = env.policy("enforce")
    a = go(p, task="a", port=8080)
    b = go(p, task="b", port=9090)
    assert a["kind"] == "flow" and b["result"] == "promoted" and b["kind"] == "ip" and b["ttl_s"] == 1800 and b["tasks"] == 2
    assert "add element inet cora dyn4 { 45.33.32.156 timeout 1800s }" in env.kernel()[-1]
    c = go(p, task="c", port=22)                                          # a third task: a repeat offense on the address
    assert c["result"] == "refreshed" and c["kind"] == "ip" and c["ttl_s"] == 7200


def test_promotion_when_a_second_task_hits_the_same_active_non_web_flow(env):
    p = env.policy("enforce")
    go(p, task="a", port=8080)
    assert go(p, task="b", port=8080)["result"] == "promoted"


def test_web_hits_do_not_count_towards_promotion_and_neither_do_two_ports_of_one_task(env):
    p = env.policy("enforce")
    go(p, task="a", port=443)
    assert go(p, task="b", port=8080)["kind"] == "flow"                   # a's web hit is not a second non-web task
    p2 = env.policy("enforce")
    go(p2, task="x", ip="45.33.33.1", port=8080)
    assert go(p2, task="x", ip="45.33.33.1", port=9090)["kind"] == "flow"


def test_the_promotion_window_is_an_hour(env):
    p = env.policy("enforce")
    go(p, task="a", port=8080)
    env.clock.advance(3601)
    assert go(p, task="b", port=9090)["kind"] == "flow"


# ================= budgets and caps =================
def test_the_write_budget_is_a_token_bucket_that_refills(env):
    p = env.policy("enforce", cfg=DynConfig(write_per_min=3))
    got = [go(p, task="t", ip=f"45.33.33.{i}", port=8000 + i) for i in range(5)]
    assert [g["result"] for g in got] == ["blocked"] * 3 + ["skipped"] * 2 and got[3]["reason"] == "budget"
    env.clock.advance(20)                                                 # 3/min -> one token per 20 s
    assert go(p, task="u", ip="45.33.33.9", port=9000)["result"] == "blocked"
    assert go(p, task="u", ip="45.33.33.10", port=9001)["reason"] == "budget"


def test_a_clock_that_goes_backwards_does_not_break_the_bucket(env):
    p = env.policy("enforce", cfg=DynConfig(write_per_min=2))
    go(p, ip="45.33.33.1", task="t1")
    env.clock.advance(-500)
    assert go(p, ip="45.33.33.2", task="t2")["result"] == "blocked"


def test_a_refresh_also_spends_a_token_and_is_skipped_when_empty(env):
    p = env.policy("enforce", cfg=DynConfig(write_per_min=1))
    go(p, task="a")
    assert go(p, task="b")["reason"] == "budget"                          # the repeat offense could not be written
    assert len(env.kernel()) == 1


def test_the_standing_cap_limits_new_elements_but_not_refreshes(env):
    p = env.policy("enforce", cfg=DynConfig(max_live=2))
    go(p, ip="45.33.33.1", task="a")
    go(p, ip="45.33.33.2", task="b")
    assert go(p, ip="45.33.33.3", task="c")["reason"] == "standing_cap"
    assert go(p, ip="45.33.33.1", task="d")["result"] == "refreshed"


def test_one_task_cannot_block_more_than_its_cap_of_distinct_targets_an_hour(env):
    p = env.policy("enforce", cfg=DynConfig(task_cap=3, write_per_min=100))
    got = [go(p, task="noisy", ip=f"45.33.33.{i}")["result"] for i in range(5)]
    assert got == ["blocked"] * 3 + ["skipped"] * 2
    assert go(p, task="other", ip="45.33.33.77")["result"] == "blocked"
    assert go(p, task="noisy", ip="45.33.33.0")["result"] == "dedupe"   # an existing target is not a new one
    env.clock.advance(3601)
    assert go(p, task="noisy", ip="45.33.33.50")["result"] == "blocked"


def test_a_failed_kernel_write_is_reported_and_not_remembered(env):
    p = env.policy("enforce")
    good = env.fake.__call__
    env.sets._run = lambda args, stdin: (1, "", "Error: Could not process rule: Operation not supported") \
        if args == ["-f", "-"] else good(args, stdin)
    r = go(p)
    assert r["result"] == "failed" and "not supported" in r["error"]
    env.sets._run = good
    assert go(p)["result"] == "blocked"                                   # not deduplicated against a block never made


# ================= the ledger =================
def test_the_ledger_survives_a_restart_and_keeps_shadow_and_enforce_apart(env):
    go(env.policy("enforce"))
    assert go(env.policy("enforce"), task="t0")["result"] == "dedupe"     # a new process, same file
    assert go(env.policy("shadow"), action="dry-run:ISOLATE@x")["result"] == "would_block"    # own ledger: not a dedupe
    d = __import__("pathlib").Path(env.dir)
    assert (d / "dyn-ledger-enforce.json").exists() and (d / "dyn-ledger-shadow.json").exists()


def test_a_corrupt_ledger_is_set_aside_and_replaced_not_fatal(env):
    d = __import__("pathlib").Path(env.dir)
    d.mkdir(parents=True)
    (d / "dyn-ledger-enforce.json").write_text("{not json")
    assert go(env.policy("enforce"))["result"] == "blocked"
    assert (d / "dyn-ledger-enforce.json.corrupt").exists()


def test_an_unwritable_state_directory_falls_back_to_memory(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    logs = []
    p = DynPolicy("shadow", state_dir=str(f / "sub"), log=logs.append)
    assert go(p)["result"] == "would_block" and go(p)["result"] == "dedupe" and any("memory" in m for m in logs)


def test_the_ledger_file_is_bounded(env, monkeypatch):
    monkeypatch.setattr(dynpolicy, "MAX_ENTRIES", 5)
    p = env.policy("shadow", cfg=DynConfig(write_per_min=1000, task_cap=1000))
    for i in range(12):
        go(p, task=f"t{i}", ip=f"45.33.33.{i}", action="dry-run:ISOLATE")
        env.clock.advance(700)                                            # each one expires before the next
    L = DynLedger(str(__import__("pathlib").Path(env.dir) / "dyn-ledger-shadow.json")).read()
    assert len(L["flows"]) <= 6


# ================= release =================
def test_release_removes_what_the_task_alone_caused_and_resets_its_memory(env):
    p = env.policy("enforce")
    go(p, task="a")
    out = dynpolicy.release_entries("a", env.dir, env.sets, clock=env.clock)
    assert out == ["dyn-flow-unblocked:45.33.32.156|tcp|443"]
    assert "delete element inet cora dynflow4 { 45.33.32.156 . tcp . 443 }" in env.kernel()[-1]
    assert go(p, task="b")["offense"] == 1                                # a false positive leaves no history


def test_release_keeps_a_block_another_task_independently_caused(env):
    p = env.policy("enforce")
    go(p, task="a")
    go(p, task="b")
    n = len(env.kernel())
    assert dynpolicy.release_entries("a", env.dir, env.sets, clock=env.clock) == [] and len(env.kernel()) == n
    assert go(p, task="b")["result"] == "dedupe"                          # still blocked, still b's


def test_release_demotes_a_whole_address_block_that_loses_its_second_task(env):
    p = env.policy("enforce")
    go(p, task="a", port=8080)
    go(p, task="b", port=9090)                                            # promoted
    out = dynpolicy.release_entries("a", env.dir, env.sets, clock=env.clock)
    assert "dyn-ip-unblocked:45.33.32.156" in out and "dyn-flow-unblocked:45.33.32.156|tcp|8080" in out
    assert any("delete element inet cora dyn4 { 45.33.32.156 }" in s for s in env.kernel())
    # b's hit WAS the promotion, so it never had a flow entry of its own: its destination is re-blocked (flow level,
    # a clean offense 1) on its next event, rather than being kept alive by evidence a is no longer part of
    r = go(p, task="b", port=9090)
    assert r["result"] == "blocked" and r["kind"] == "flow" and r["offense"] == 1


def test_release_in_shadow_touches_no_kernel_and_ignores_unknown_tasks_and_expired_entries(env):
    ps, pe = env.policy("shadow"), env.policy("enforce")
    go(ps, action="dry-run:ISOLATE")
    assert dynpolicy.release_entries("t0", env.dir, env.sets, clock=env.clock) == ["dyn-flow-dropped(shadow):45.33.32.156|tcp|443"]
    assert env.kernel() == [] and dynpolicy.release_entries("nobody", env.dir, env.sets, clock=env.clock) == []
    go(pe, task="x")
    env.clock.advance(700)
    n = len(env.kernel())
    assert dynpolicy.release_entries("x", env.dir, env.sets, clock=env.clock) == [] and len(env.kernel()) == n


def test_a_failed_unblock_keeps_the_entry_and_says_so(env):
    p = env.policy("enforce")
    go(p, task="a")
    good = env.fake.__call__
    env.sets._run = lambda args, stdin: (1, "", "Error: busy") if args == ["-f", "-"] else good(args, stdin)
    out = dynpolicy.release_entries("a", env.dir, env.sets, clock=env.clock)
    assert out and out[0].startswith("dyn-unblock-FAILED")
    env.sets._run = good
    assert dynpolicy.release_entries("a", env.dir, env.sets, clock=env.clock) == ["dyn-flow-unblocked:45.33.32.156|tcp|443"]


class _Cg:
    def freeze_requested(self, n): return False
    def is_frozen(self, n): return False
    def reset_limits(self, n): return []


class _Fw:
    def unblock(self, n): return False


def test_cora_firewall_release_also_drops_the_dynamic_entries_and_survives_their_failure():
    assert release_task(_Cg(), _Fw(), "t", dyn=lambda n: [f"dyn-flow-unblocked:{n}"]) == ["dyn-flow-unblocked:t"]
    boom = lambda n: (_ for _ in ()).throw(RuntimeError("x"))             # noqa: E731
    assert release_task(_Cg(), _Fw(), "t", dyn=boom) == ["dyn-release-FAILED:RuntimeError"]
    assert release_task(_Cg(), _Fw(), "t") == []                          # the old signature still works


def test_make_release_builds_the_undo_from_the_firewall_and_state_dir(env):
    class Fw:
        table, _run = "cora", env.fake
    go(env.policy("enforce"), task="a")
    assert dynpolicy.make_release(Fw(), env.dir)("a") == ["dyn-flow-unblocked:45.33.32.156|tcp|443"]


# ================= reconcile =================
def test_reconcile_notices_an_element_an_operator_removed_and_blocks_again_on_the_next_hit(env):
    p = env.policy("enforce")
    go(p, task="a")
    assert p.reconcile() == 0
    env.fake.sets["dynflow4"].clear()                                     # cora-floor unblock-flow, or a flush
    assert p.reconcile() == 1
    assert go(p, task="a")["result"] == "blocked"                         # not a dedupe against a block that is gone


def test_reconcile_does_nothing_without_a_floor(env):
    p = env.policy("enforce")
    go(p, task="a")
    env.sets._run = lambda args, stdin: (1, "", "Error: No such file or directory")
    assert p.reconcile() == 0
    assert DynPolicy("shadow", log=lambda m: None).reconcile() == 0


# ================= supporting pieces =================
def test_nftsets_flow_helpers(env):
    ns = env.sets
    ns.block_flow("45.33.32.156", "tcp", 443)
    ns.block_ip("45.33.33.4")
    assert ns.live_flows() == {"45.33.32.156|tcp|443"} and ns.live_ips() == {"45.33.33.4"}
    assert ns.unblock_flow("45.33.32.156", "tcp", 443) is True and ns.unblock_flow("45.33.32.156", "tcp", 443) is False
    with pytest.raises(ValueError):
        ns.unblock_flow("45.33.32.156", "icmp", 1)


def fsync(**kw):
    kw.setdefault("protect", lambda: {"203.0.113.50": "default gateway"})
    return FloorSync(NftSets(run=FakeNft()), log=lambda m: None, resolv=lambda: ["9.9.9.9"],
                     extra_allow=["45.33.33.0/24"], **kw)


def test_exempt_reason_covers_allow_resolvers_protected_and_the_blocklist_allow_file():
    fs = fsync()
    assert fs.exempt_reason("45.33.33.5").startswith("allowed:") and fs.exempt_reason("9.9.9.9").startswith("allowed:")
    assert fs.exempt_reason("203.0.113.50").startswith("protected:") and fs.exempt_reason("8.8.8.8") is None
    fs.track(bl_with(["192.0.2.0/24"], allow=["8.8.8.0/24"]))             # a reload: the cache must not hide the new list
    assert fs.exempt_reason("8.8.8.8").startswith("allowed:")


def test_summarize_decisions_counts_results_reasons_and_targets():
    lines = [json.dumps({"final": "ISOLATE", "dyn": {"result": "would_block", "key": "1.1.1.1|tcp|443", "web": True,
                                                    "kind": "flow", "ttl_s": 600}}),
             json.dumps({"final": "ISOLATE", "dyn": {"result": "would_refresh", "key": "1.1.1.1|tcp|443", "web": True,
                                                    "kind": "flow", "ttl_s": 2400}}),
             json.dumps({"final": "ISOLATE", "dyn": {"result": "skipped", "reason": "infra_port"}}),
             json.dumps({"final": "ALLOW"}), "garbage"]
    r = dynpolicy.summarize_decisions(lines)
    assert r["isolate_decisions"] == 3 and r["with_dyn_record"] == 3 and r["results"]["skipped"] == 1
    assert r["skipped_reasons"] == {"infra_port": 1} and r["targets"] == 1 and r["web_targets"] == 1
    assert r["top"][0][1]["max_ttl_s"] == 2400


# ================= through the real Adjudicator =================
def event(net, p, cg, ip="45.33.34.9", port=443, **ev_extra):
    evd = {"remote_ip": ip, "remote_port": port, "local_port": 40000, "dest_class": "public", **ev_extra}
    return build_payload(p.pid, net.ensure(p.pid), "sleep", "unauthorized_connection", "high", evd,
                         read_starttime(p.pid), cgroup=cg)


def test_a_model_isolate_is_recorded_in_the_decision_in_shadow_and_the_task_is_isolated_as_before(procs, env):
    ps = procs(1)
    net, adj, fw, cgs, decisions = pipeline(ps, GateModel(verdict("ISOLATE", 0.95), delay=0), dyn=env.policy("shadow"))
    d = adj.handle(event(net, ps[0], "task0"))
    assert fw.calls == ["task0"] and d["dyn"]["result"] == "would_block" and d["dyn"]["mode"] == "shadow"
    assert decisions[0]["dyn"]["key"] == "45.33.34.9|tcp|443" and env.kernel() == []


def test_enforcing_adjudicator_plus_enforce_policy_writes_the_kernel(procs, env):
    ps = procs(1)
    net, adj, fw, cgs, decisions = pipeline(ps, GateModel(verdict("ISOLATE", 0.95), delay=0), enforce=True,
                                            dyn=env.policy("enforce"))
    d = adj.handle(event(net, ps[0], "task0"))
    assert d["dyn"]["result"] == "blocked" and "dynflow4 { 45.33.34.9 . tcp . 443 timeout 600s }" in env.kernel()[-1]


def test_an_escalate_verdict_or_a_blocked_gate_never_reaches_the_kernel(procs, env):
    ps = procs(2)
    net, adj, fw, cgs, decisions = pipeline(ps, GateModel(verdict("ESCALATE", 0.95), delay=0), enforce=True,
                                            dyn=env.policy("enforce"))
    assert "dyn" not in adj.handle(event(net, ps[0], "task0")) and env.kernel() == []
    net2, adj2, *_ = pipeline(ps, GateModel(verdict("ISOLATE", 0.95), delay=0), enforce=True, dyn=env.policy("enforce"))
    ev = event(net2, ps[1], "task1")
    net2.release(ps[1].pid)                                              # the gate refuses: the task left the registry
    d = adj2.handle(ev)
    assert d["action"] == "blocked" and d["dyn"]["reason"] == "not_acted" and env.kernel() == []


def test_a_blocklist_isolate_is_left_to_the_static_sets(procs, env):
    ps = procs(1)
    net, adj, fw, cgs, decisions = pipeline(ps, GateModel(verdict("ISOLATE", 0.95), delay=0), dyn=env.policy("shadow"))
    d = adj.handle(event(net, ps[0], "task0", blocklist="demo/rogue_subnet/45.33.34.9/32"))
    assert d["dyn"] == {"mode": "shadow", "result": "skipped", "reason": "blocklist"}


def test_a_policy_that_raises_never_breaks_the_decision(procs):
    class Boom:
        def consider(self, ev, d):
            raise RuntimeError("ledger exploded")
    ps = procs(1)
    net, adj, fw, cgs, decisions = pipeline(ps, GateModel(verdict("ISOLATE", 0.95), delay=0), dyn=Boom())
    d = adj.handle(event(net, ps[0], "task0"))
    assert d["final"] == "ISOLATE" and d["dyn"]["result"] == "error" and decisions and fw.calls == ["task0"]


def test_no_policy_means_no_dyn_field(procs):
    ps = procs(1)
    net, adj, fw, cgs, decisions = pipeline(ps, GateModel(verdict("ISOLATE", 0.95), delay=0))
    assert "dyn" not in adj.handle(event(net, ps[0], "task0"))


# ================= CLI and daemon flags =================
def test_cora_floor_dyn_and_dyn_report(env, tmp_path, capsys):
    p = env.policy("shadow")
    go(p, action="dry-run:ISOLATE")
    real = dynpolicy.time.time
    dynpolicy.time.time = env.clock
    try:
        assert nftsets.main(["--state-dir", env.dir, "dyn", "--mode", "shadow"]) == 0
        out = capsys.readouterr().out
        assert "[shadow] 1 active" in out and "45.33.32.156|tcp|443" in out
        assert nftsets.main(["--state-dir", env.dir, "dyn", "--mode", "enforce"]) == 0
        assert "no ledger" in capsys.readouterr().out
    finally:
        dynpolicy.time.time = real
    f = tmp_path / "decisions.jsonl"
    f.write_text(json.dumps({"final": "ISOLATE", "dyn": {"result": "would_block", "key": "1.1.1.1|tcp|443",
                                                         "web": True, "kind": "flow", "ttl_s": 600}}) + "\n")
    assert nftsets.main(["dyn-report", str(f)]) == 0
    assert "would_block 1" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["--dyn-policy", "enforce"], ["--dyn-policy", "enforce", "--model", "m", "--floor", "--nft",
                                                                  "--cgroup-root", "/x"],
                                  ["--dyn-min-conf", "0.2"], ["--dyn-task-cap", "0"]])
def test_dyn_flags_are_validated(argv, monkeypatch, capsys):
    import sys
    from cora_sentinel import daemon
    monkeypatch.setattr(sys, "argv", ["cora-sentinel", *argv])
    assert daemon.main() == 1 and "--dyn" in capsys.readouterr().err


def test_the_default_is_shadow_and_bad_modes_are_rejected():
    import subprocess, sys
    h = subprocess.run([sys.executable, "-m", "cora_sentinel.daemon", "--help"], capture_output=True, text=True).stdout
    assert "default shadow" in h
    with pytest.raises(ValueError):
        DynPolicy("sometimes")
