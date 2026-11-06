"""A process can exit while its event waits behind the model (2-4 s per event, 32 slots). Two things used to follow: its VIP was released
by the next tick, so the safety gate refused to act on a perfectly good verdict; and if the gate had not, the process-identity check
would have. This file pins the fix: the VIP stays registered while an event about it is in flight (pin/unpin), and ISOLATE of the
process's cgroup may go ahead when the process is GONE, provided the cgroup is provably the same one.

No kernel except where a test says so (it skips itself without root). Run: pytest -q tests/test_inflight.py"""
import queue
import subprocess
import sys
import time

import pytest

from cora_sentinel.daemon import Sentinel, VirtualNet, build_payload, read_starttime
from cora_sentinel.verdict import Adjudicator, Executor, Qwen3B
from test_verdict import FakeCg, FakeFw, FakeModel, GateModel, verdict


# ---------------------------------------------------------------------------------------------- VirtualNet: pin / unpin
def registered(net, pid):
    return net.reg.get(VirtualNet.name_for(pid)) is not None


def test_release_without_a_pin_frees_the_vip_at_once():
    net = VirtualNet()
    net.ensure(5001)
    net.release(5001)
    assert not net.by_pid and not registered(net, 5001)


def test_a_pinned_pid_that_exits_keeps_its_vip_until_the_last_unpin():
    net = VirtualNet()
    ip = net.ensure(5002)
    net.pin(5002)
    net.release(5002)                                          # the process exited; tick() releases it
    assert net.by_pid == {5002: ip} and registered(net, 5002)  # but an event about it is still being judged
    net.unpin(5002)
    assert not net.by_pid and not registered(net, 5002)        # the deferred release happens now
    assert not net._pins and not net._deferred and not net._pin_since


def test_two_pins_need_two_unpins():
    net = VirtualNet()
    net.ensure(5003)
    net.pin(5003)
    net.pin(5003)
    net.release(5003)
    net.unpin(5003)
    assert registered(net, 5003), "one event is still in flight"
    net.unpin(5003)
    assert not registered(net, 5003)


def test_tick_asking_to_release_every_second_is_idempotent_while_pinned():
    net = VirtualNet()
    net.ensure(5004)
    net.pin(5004)
    for _ in range(5):
        net.release(5004)
    assert registered(net, 5004)
    net.unpin(5004)
    assert not registered(net, 5004)


def test_unbalanced_unpin_is_ignored_and_never_goes_negative():
    net = VirtualNet()
    net.ensure(5005)
    net.unpin(5005)                                            # never pinned
    net.unpin(99999)                                           # never heard of
    assert net._pins == {} and registered(net, 5005)
    net.pin(5005)
    net.unpin(5005)
    net.unpin(5005)                                            # one too many
    assert net._pins == {} and registered(net, 5005)
    net.pin(5005)                                              # and a later pin still counts from zero
    net.release(5005)
    assert registered(net, 5005)


def test_a_lost_unpin_cannot_leak_a_vip_for_good():
    now = [1000.0]
    net = VirtualNet()
    net._clock = lambda: now[0]
    net.ensure(5006)
    net.pin(5006)                                              # ... and the adjudicator thread dies: nobody will ever unpin
    net.release(5006)
    assert registered(net, 5006)
    now[0] += VirtualNet.PIN_MAX_AGE_S + 1
    net.release(5006)                                          # tick() asks again, a second later
    assert not net.by_pid and not registered(net, 5006) and not net._pins
    net.unpin(5006)                                            # a late, belated unpin is harmless
    assert net._pins == {}


def test_a_reused_pid_takes_the_vip_over_so_the_old_events_unpin_cannot_free_it():
    net = VirtualNet()
    ip = net.ensure(5007)
    net.pin(5007)                                              # an event about the OLD process
    net.release(5007)                                          # the old process exits (deferred)
    assert net.ensure(5007) == ip                              # a NEW process gets the same pid number: tick() asks for it
    net.unpin(5007)                                            # the old event finishes
    assert registered(net, 5007) and 5007 in net.by_pid, "the VIP is in use by the new process: it must not be freed"
    net.release(5007)                                          # when the NEW process exits it is released normally
    assert not registered(net, 5007)


def test_the_subnet_never_fills_up_when_pins_and_releases_interleave():
    net = VirtualNet()
    for pid in range(20000, 20700):                            # far more than the /24 holds at once
        net.ensure(pid)
        net.pin(pid)
        net.release(pid)
        net.unpin(pid)
    assert not net.by_pid and not net._pins and not net._deferred and not net._pin_since
    assert all(not registered(net, p) for p in (20000, 20350, 20699))
    for pid in range(30000, 30200):                            # and it still has room
        net.ensure(pid)
    assert len(net.by_pid) == 200


# ---------------------------------------------------------------------------------------------- Adjudicator: pin on submit
class IdCg(FakeCg):
    """FakeCg that also knows each cgroup's identity (the inode the kernel gives it)."""
    def __init__(self):
        super().__init__()
        self.ids = {}

    def cgroup_id(self, name):
        return self.ids.get(name)


@pytest.fixture
def sleepers():
    made = []

    def mk(n=1):
        ps = [subprocess.Popen(["sleep", "60"]) for _ in range(n)]
        time.sleep(0.2)
        made.extend(ps)
        return ps
    yield mk
    for p in made:
        p.kill()
        p.wait()


def rig(model_out, enforce=True, **kw):
    net, fw, cgs, decisions = VirtualNet(), FakeFw(), IdCg(), []
    adj = Adjudicator(net, FakeModel(model_out), Executor(enforce, cgs, fw), None, 0.6, sink=decisions.append, **kw)
    return net, adj, fw, cgs, decisions


def event(net, p, cg=None, cgid=None, blocklist=None, kind="path_violation"):
    evidence = {"path": "/etc/shadow"} if not blocklist else {"remote_ip": "203.0.113.9", "remote_port": 443, "blocklist": blocklist}
    ev = build_payload(p.pid, net.ensure(p.pid), "sleep", "unauthorized_connection" if blocklist else kind, "high", evidence,
                       read_starttime(p.pid), cgroup=cg, cgroup_id=cgid)
    ev["timing"] = {"seen_mono_s": time.monotonic()}
    return ev


def exit_(net, p):
    """The process exits and the next tick() releases it."""
    p.kill()
    p.wait()
    net.release(p.pid)


def run_queued(adj):
    return adj.handle(adj.q.get_nowait())


def test_submit_pins_and_the_decision_unpins_after_it_is_written(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(verdict("ALLOW"), enforce=False)
    ev = event(net, p)
    adj.submit(ev)
    assert net._pins == {p.pid: 1}
    exit_(net, p)
    assert registered(net, p.pid), "the process is gone but the event is still waiting behind the model"
    d = run_queued(adj)
    assert decisions == [d] and not registered(net, p.pid) and net._pins == {} and not net.by_pid


def test_a_full_queue_unpins_at_once_because_the_event_will_never_be_handled(sleepers):
    (p,) = sleepers()
    net, adj, *_ = rig(verdict("ALLOW"), enforce=False)
    adj.q = queue.Queue(maxsize=1)
    adj.q.put_nowait({"filler": True})
    adj.submit(event(net, p))
    assert adj.dropped == 1 and net._pins == {} and adj._pinned == set()
    net.release(p.pid)
    assert not registered(net, p.pid), "nothing is pinned, so the exit releases it"


def test_an_exception_while_handling_still_unpins(sleepers):
    (p,) = sleepers()

    class Boom(Executor):
        def run(self, *a, **k):
            raise RuntimeError("nft exploded")
    net, fw, cgs = VirtualNet(), FakeFw(), IdCg()
    adj = Adjudicator(net, FakeModel(verdict("TERMINATE")), Boom(True, cgs, fw), None, 0.6)
    adj.submit(event(net, p))
    with pytest.raises(RuntimeError):
        run_queued(adj)
    assert net._pins == {} and adj._pinned == set()


def test_a_direct_handle_call_never_steals_another_events_pin(sleepers):
    (p,) = sleepers()
    net, adj, *_ = rig(verdict("ALLOW"), enforce=False)
    queued = event(net, p)
    adj.submit(queued)                                         # pinned: 1
    adj.handle(event(net, p))                                  # a different event, never submitted
    assert net._pins == {p.pid: 1}
    adj.handle(queued)
    assert net._pins == {}


def test_the_worker_thread_releases_the_vip_after_the_decision(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(verdict("ALLOW"), enforce=False)
    adj.start()
    try:
        adj.submit(event(net, p))
        exit_(net, p)
        end = time.monotonic() + 10
        while not decisions and time.monotonic() < end:
            time.sleep(0.02)
        assert len(decisions) == 1
        end = time.monotonic() + 5
        while registered(net, p.pid) and time.monotonic() < end:
            time.sleep(0.02)
        assert not registered(net, p.pid) and net._pins == {}
    finally:
        adj.stop()


# ---------------------------------------------------------------------------------------------- the gate: the process is GONE
def gone_case(sleepers, model_out, cgid=1000, enforce=True, blocklist=None):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(model_out, enforce=enforce)
    cgs.where[p.pid] = "task0"
    cgs.ids["task0"] = 1000
    ev = event(net, p, "task0", cgid, blocklist=blocklist)
    adj.submit(ev)                                             # pinned
    exit_(net, p)                                              # gone: the cgroup no longer lists its pid
    cgs.where.pop(p.pid, None)
    return net, adj, fw, cgs, decisions, p


def test_isolate_goes_ahead_when_the_trigger_exited_and_its_cgroup_is_provably_the_same(sleepers):
    net, adj, fw, cgs, decisions, p = gone_case(sleepers, verdict("ISOLATE"))
    d = run_queued(adj)
    assert d["gate"]["ok"] and d["gate"]["code"] == "OK_PROCESS_GONE"
    assert d["action"].startswith("done:ISOLATE@cgroup:task0") and fw.calls == ["task0"]
    assert not registered(net, p.pid), "and the VIP is released afterwards"


def test_without_the_pin_the_old_behaviour_holds_and_the_gate_blocks(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(verdict("ISOLATE"))
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    ev = event(net, p, "task0", 1000)                          # handle() directly: never submitted, so never pinned
    exit_(net, p)
    d = adj.handle(ev)
    assert d["action"] == "blocked" and not d["gate"]["ok"] and fw.calls == []


@pytest.mark.parametrize("v", ["TERMINATE", "SUSPEND", "THROTTLE"])
def test_only_isolate_is_relaxed_the_irreversible_and_whole_tree_actions_stay_strict(sleepers, v):
    net, adj, fw, cgs, decisions, p = gone_case(sleepers, verdict(v))
    d = run_queued(adj)
    assert d["action"] == "blocked" and d["gate"]["code"] == "PID_REUSED"
    assert cgs.killed == [] and cgs.frozen == [] and cgs.throttled == [] and fw.calls == []


def test_a_cgroup_recreated_under_the_same_name_is_not_the_same_cgroup(sleepers):
    net, adj, fw, cgs, decisions, p = gone_case(sleepers, verdict("ISOLATE"))
    cgs.ids["task0"] = 4242                                    # the task was removed and a LATER task took the name
    d = run_queued(adj)
    assert d["action"] == "blocked" and d["gate"]["code"] == "CGROUP_REPLACED" and fw.calls == []


def test_a_removed_cgroup_cannot_be_isolated(sleepers):
    net, adj, fw, cgs, decisions, p = gone_case(sleepers, verdict("ISOLATE"))
    del cgs.ids["task0"]
    d = run_queued(adj)
    assert d["action"] == "blocked" and d["gate"]["code"] == "CGROUP_GONE" and fw.calls == []


def test_an_event_that_did_not_record_the_cgroup_identity_fails_closed(sleepers):
    net, adj, fw, cgs, decisions, p = gone_case(sleepers, verdict("ISOLATE"), cgid=None)
    d = run_queued(adj)
    assert d["action"] == "blocked" and d["gate"]["code"] == "CGROUP_UNPINNED" and fw.calls == []


def test_a_live_process_with_a_different_starttime_is_still_a_reused_pid(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(verdict("ISOLATE"))
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    ev = event(net, p, "task0", 1000)
    ev["subject"]["starttime"] += 1                            # the pid now belongs to someone else: NOT gone, DIFFERENT
    adj.submit(ev)
    d = run_queued(adj)
    assert d["action"] == "blocked" and d["gate"]["code"] == "PID_REUSED" and fw.calls == []


def test_a_live_process_that_left_the_cgroup_is_still_a_mismatch(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(verdict("ISOLATE"))
    cgs.where[p.pid], cgs.ids["task0"] = "elsewhere", 1000
    adj.submit(event(net, p, "task0", 1000))
    d = run_queued(adj)
    assert d["action"] == "blocked" and d["gate"]["code"] == "CGROUP_MISMATCH" and fw.calls == []


def test_without_a_cgroup_there_is_nothing_to_relax(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(verdict("ISOLATE"))
    ev = event(net, p)
    adj.submit(ev)
    exit_(net, p)
    with net.lock:
        ok, code, detail, gv = adj._gate(ev["subject"], "ISOLATE")
    assert not ok and code == "PID_REUSED"


def test_the_strict_gate_is_the_default_when_no_action_is_given(sleepers):
    net, adj, fw, cgs, decisions, p = gone_case(sleepers, verdict("ISOLATE"))
    ev = adj.q.get_nowait()
    with net.lock:
        ok, code, *_ = adj._gate(ev["subject"])
    assert not ok and code == "PID_REUSED"
    adj.handle(ev)


# ---------------------------------------------------------------------------------------------- the early containment
def test_contain_first_isolates_a_blocklist_hit_whose_process_already_exited(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig(verdict("ALLOW"))
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    ev = event(net, p, "task0", 1000, blocklist="demo/rogue_subnet/203.0.113.9/32")
    exit_(net, p)
    cgs.where.pop(p.pid, None)
    net.ensure(p.pid)                                          # (the event already holds a VIP; re-register it for this ordering)
    adj.submit(ev)                                             # contain_first runs HERE, in the caller's thread
    assert fw.calls == ["task0"] and adj._early[ev["event_id"]]["gate"]["code"] == "OK_PROCESS_GONE"


def test_already_contained_is_recorded_as_such_not_as_blocked(sleepers):
    net, adj, fw, cgs, decisions, p = gone_case(sleepers, verdict("ISOLATE"), blocklist="demo/rogue_subnet/203.0.113.9/32")
    ev = adj.q.queue[0]
    assert adj._early[ev["event_id"]]["action"].startswith("done:ISOLATE")     # contained at submit(), after the process exited
    del cgs.ids["task0"]                                       # then the task's cgroup is removed before its turn behind the model
    d = run_queued(adj)
    assert d["action"] == "already-contained" and d["gate"]["code"] == "CGROUP_GONE" and d["contained_first"]["action"].startswith("done:")


# ---------------------------------------------------------------------------------------------- the identity is recorded
def test_build_payload_records_the_cgroup_identity_and_defaults_to_none():
    assert build_payload(1, "10.1.1.10", "x", "k", "high", {}, 5, cgroup="t", cgroup_id=77)["subject"]["cgroup_id"] == 77
    assert build_payload(1, "10.1.1.10", "x", "k", "high", {}, 5)["subject"]["cgroup_id"] is None


def test_the_model_never_sees_the_identity():
    marker = 918273645501                                      # distinctive: the prompt carries live memory figures that could contain "77"
    ev = build_payload(1, "10.1.1.10", "x", "k", "high", {}, 5, cgroup="t", cgroup_id=marker)
    prompt = Qwen3B.render(ev)
    assert "cgroup_id" not in prompt and str(marker) not in prompt


def test_the_sentinel_records_the_identity_of_the_tasks_cgroup():
    cgs = IdCg()
    cgs.ids["task0"] = 31337
    s = Sentinel("CORA_TASK", ["/tmp"], 150, 10.0, lambda p: None, cgroups=cgs)
    s._cg[777] = "task0"
    assert s._payload(777, "10.1.1.10", "x", "path_violation", "high", {}, 5)["subject"]["cgroup_id"] == 31337
    assert s._payload(778, "10.1.1.11", "x", "path_violation", "high", {}, 5)["subject"]["cgroup_id"] is None   # not in a cgroup
    assert Sentinel("CORA_TASK", ["/tmp"], 150, 10.0, lambda p: None).cgroup_id_of("task0") is None             # no cgroup mode


# ---------------------------------------------------------------------------------------------- the real kernel (root only)
from test_cgroup import cg  # noqa: E402,F401  (the fixture: a real delegated cgroup root, skipped without root)


def test_a_real_cgroup_has_an_identity_that_changes_when_it_is_recreated(cg):
    cg.create("idt")
    first = cg.cgroup_id("idt")
    assert isinstance(first, int) and first > 0
    assert cg.cgroup_id("idt") == first, "stable while it exists"
    (cg.root / "idt").rmdir()
    assert cg.cgroup_id("idt") is None
    cg.create("idt")
    second = cg.cgroup_id("idt")
    assert second is not None and second != first, "a task that reuses the name must not look like the same task"
    assert cg.cgroup_id("../etc") is None and cg.cgroup_id("no such name") is None


from test_nflog import beacons, drain, env, listener, monitor, real, task   # noqa: E402,F401  (env: a real cgroup root + nft table)


@real
def test_a_connection_seen_by_the_tap_becomes_an_event_carrying_the_real_cgroup_identity(env):
    """The connect-time tap builds its events on a different code path from tick(): it must record the identity as well."""
    cgroups, fw, made = env
    events = []
    lis, port = listener()
    stop = drain(lis)
    s, nm = monitor(cgroups, fw, made, events, interval=0.2)
    p = task(cgroups, fw, "idtap", beacons(port, 2, hold=1.5))
    time.sleep(2.5)
    p.wait(30)
    stop.set()
    lis.close()
    got = [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection" and e["subject"]["cgroup"] == "idtap"]
    assert got, "the tap saw nothing"
    want = cgroups.cgroup_id("idtap")
    assert want is not None and all(e["subject"]["cgroup_id"] == want for e in got)


# ---------------------------------------------------------------------------------------------- the docs
def test_the_docs_describe_the_gate_codes_and_the_list_directories():
    from pathlib import Path
    doc = (Path(__file__).resolve().parents[1] / "docs" / "service.md").read_text()
    for word in ("OK_PROCESS_GONE", "already-contained", "subject.cgroup_id", "CGROUP_REPLACED", "CGROUP_UNPINNED", "CGROUP_GONE",
                 "PID_REUSED", "/etc/cora-sentinel/blocklists", "/etc/cora-sentinel/allow", "ISOLATE"):
        assert word in doc, word


# ---------------------------------------------------------------------------------------------- in-flight coalescing (0.8.6)
class Counting(FakeModel):
    def __init__(self, out):
        super().__init__(out)
        self.calls = []

    def judge(self, ev):
        self.calls.append(ev["event_id"])
        return super().judge(ev)


def rig2(model, enforce=False, **kw):
    net, fw, cgs, decisions = VirtualNet(), FakeFw(), IdCg(), []
    adj = Adjudicator(net, model, Executor(enforce, cgs, fw), None, 0.6, sink=decisions.append, **kw)
    return net, adj, fw, cgs, decisions


def conn(net, p, cg=None, cgid=None, ip="203.0.113.9", port=443, blocklist=None):
    evidence = {"remote_ip": ip, "remote_port": port, "local_port": 40000, "dest_class": "public"}
    if blocklist:
        evidence["blocklist"] = blocklist
    ev = build_payload(p.pid, net.ensure(p.pid), "sleep", "unauthorized_connection", "high", evidence, read_starttime(p.pid),
                       cgroup=cg, cgroup_id=cgid)
    ev["timing"] = {"seen_mono_s": time.monotonic()}
    return ev


def clean(net, adj):
    assert net.by_pid == {} and net._pins == {} and net._deferred == set() and net._pin_since == {}
    assert adj._pinned == set() and adj._in_flight == {}


def test_a_burst_of_ten_identical_events_runs_the_model_once_and_leaves_nothing_behind(sleepers):
    (p,) = sleepers()
    model = Counting(verdict("ISOLATE"))
    net, adj, fw, cgs, decisions = rig2(model, enforce=True)
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    for _ in range(10):
        adj.submit(conn(net, p, "task0", 1000))
    assert adj.q.qsize() == 1 and adj.coalesced == 9
    assert net._pins == {p.pid: 1} and len(adj._pinned) == 1, "nine coalesced events took no pin at all"
    exit_(net, p)                                              # the task exits while its evaluation waits
    cgs.where.pop(p.pid, None)
    d = run_queued(adj)
    assert len(model.calls) == 1, "the model judged once, not ten times"
    assert d["coalesced"] == {"count": 9, "destinations": ["203.0.113.9:443"]}
    assert d["gate"]["code"] == "OK_PROCESS_GONE" and fw.calls == ["task0"]
    clean(net, adj)
    assert not registered(net, p.pid)


def test_events_that_arrive_while_the_model_is_judging_are_coalesced_too(sleepers):
    (p,) = sleepers()
    model = GateModel(verdict("ISOLATE"))                      # blocks inside judge() until released
    net, adj, fw, cgs, decisions = rig2(model, enforce=True)
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    adj.start()
    try:
        adj.submit(conn(net, p, "task0", 1000))
        assert model.started.wait(5)
        for i in range(9):
            adj.submit(conn(net, p, "task0", 1000, ip=f"203.0.113.{20 + i}"))      # nine MORE, to nine other hosts, mid-inference
        assert adj.q.qsize() == 0 and adj.coalesced == 9
        assert net._pins == {p.pid: 1}
        model.release.set()
        end = time.monotonic() + 10
        while not decisions and time.monotonic() < end:
            time.sleep(0.02)
        assert len(decisions) == 1 and model.calls == 1
        assert decisions[0]["coalesced"]["count"] == 9 and len(decisions[0]["coalesced"]["destinations"]) == 9
        assert adj.q.qsize() == 0, "ISOLATE contained the task: no follow-up is needed"
    finally:
        model.release.set()
        adj.stop()
    exit_(net, p)
    clean(net, adj)


def test_the_decision_line_says_how_many_were_folded_in(sleepers, capsys):
    (p,) = sleepers()
    net, adj, *_ = rig2(Counting(verdict("ALLOW")))
    for _ in range(4):
        adj.submit(conn(net, p))
    run_queued(adj)
    assert "+3 coalesced" in capsys.readouterr().err


def test_a_different_kind_is_never_coalesced(sleepers):
    (p,) = sleepers()
    model = Counting(verdict("ALLOW"))
    net, adj, *_ = rig2(model)
    adj.submit(conn(net, p))
    adj.submit(event(net, p))                                  # a path_violation for the same task while the connection is pending
    assert adj.q.qsize() == 2 and adj.coalesced == 0 and net._pins == {p.pid: 2}
    run_queued(adj)
    run_queued(adj)
    assert len(model.calls) == 2
    exit_(net, p)
    clean(net, adj)


def test_a_blocklist_hit_is_never_coalesced_and_is_contained_at_submit(sleepers):
    (p,) = sleepers()
    net, adj, fw, cgs, decisions = rig2(Counting(verdict("ALLOW")), enforce=True)
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    adj.submit(conn(net, p, "task0", 1000))                    # a plain connection event is pending
    assert fw.calls == []
    adj.submit(conn(net, p, "task0", 1000, ip="198.51.100.7", blocklist="demo/rogue_subnet/198.51.100.7/32"))
    assert adj.coalesced == 0 and adj.q.qsize() == 2, "a deterministic detection always gets its own evaluation"
    assert fw.calls == ["task0"], "and is isolated at submit(), whatever the model is doing"
    assert net._pins == {p.pid: 2}


def test_events_of_different_tasks_are_never_coalesced(sleepers):
    a, b = sleepers(2)
    net, adj, fw, cgs, decisions = rig2(Counting(verdict("ALLOW")))
    adj.submit(conn(net, a, "task-a", 1))
    adj.submit(conn(net, b, "task-b", 2))
    assert adj.q.qsize() == 2 and adj.coalesced == 0


def test_without_a_cgroup_a_task_is_its_pid_and_start_time_so_a_reused_pid_is_not_coalesced(sleepers):
    (p,) = sleepers()
    net, adj, *_ = rig2(Counting(verdict("ALLOW")))
    first = conn(net, p)
    again = conn(net, p)
    reused = conn(net, p)
    reused["subject"]["starttime"] += 1                        # same pid number, a different process
    adj.submit(first)
    adj.submit(again)
    adj.submit(reused)
    assert adj.q.qsize() == 2 and adj.coalesced == 1


def test_a_full_queue_leaves_no_record_behind_so_the_next_event_is_not_swallowed(sleepers):
    (p,) = sleepers()
    net, adj, *_ = rig2(Counting(verdict("ALLOW")))
    adj.q = queue.Queue(maxsize=1)
    adj.q.put_nowait({"filler": True})
    adj.submit(conn(net, p))
    assert adj.dropped == 1 and adj._in_flight == {} and net._pins == {} and adj._pinned == set()
    adj.submit(conn(net, p))                                   # NOT coalesced into the dropped one: it tries (and is dropped) itself
    assert adj.coalesced == 0 and adj.dropped == 2


def test_a_lost_evaluation_cannot_silence_a_task_for_ever(sleepers):
    (p,) = sleepers()
    now = [1000.0]
    net, adj, *_ = rig2(Counting(verdict("ALLOW")))
    adj._clock = lambda: now[0]
    first, second = conn(net, p), conn(net, p)
    adj.submit(first)                                          # ...and the worker dies: nobody will ever handle it
    adj.submit(conn(net, p))
    assert adj.coalesced == 1
    now[0] += Adjudicator.IN_FLIGHT_MAX_AGE_S + 1
    adj.submit(second)
    assert adj.stale_in_flight == 1 and adj.q.qsize() == 2, "the stale record is ignored: this event gets its own evaluation"
    adj.handle(adj.q.get_nowait())                             # the old one finally runs: it must not delete the new record
    assert list(adj._in_flight.values())[0]["event_id"] == second["event_id"]
    adj.handle(adj.q.get_nowait())
    assert adj._in_flight == {}


def test_an_exception_while_handling_clears_the_record(sleepers):
    (p,) = sleepers()

    class Boom(Executor):
        def run(self, *a, **k):
            raise RuntimeError("nft exploded")
    net, fw, cgs = VirtualNet(), FakeFw(), IdCg()
    adj = Adjudicator(net, FakeModel(verdict("TERMINATE")), Boom(True, cgs, fw), None, 0.6)
    adj.submit(conn(net, p))
    with pytest.raises(RuntimeError):
        run_queued(adj)
    assert adj._in_flight == {} and net._pins == {}
    adj.submit(conn(net, p))
    assert adj.coalesced == 0 and adj.q.qsize() == 1, "the next event is judged, not swallowed by a record that never cleared"


# ---- the burst's tail is never hidden: one trailing evaluation when the verdict did not contain the task
def test_a_burst_to_many_hosts_costs_two_evaluations_not_ten_when_the_verdict_does_not_contain_the_task(sleepers):
    (p,) = sleepers()
    model = Counting(verdict("ALLOW"))
    net, adj, *_ = rig2(model)
    events = [conn(net, p, ip=f"203.0.113.{10 + i}") for i in range(10)]
    for ev in events:
        adj.submit(ev)
    assert adj.q.qsize() == 1 and adj.coalesced == 9
    first = run_queued(adj)                                    # the verdict for the first: ALLOW
    assert first["coalesced"]["follow_up"] == events[-1]["event_id"], "the burst's latest event is what gets judged next"
    assert adj.q.qsize() == 1 and adj.follow_ups == 1
    second = run_queued(adj)
    assert model.calls == [events[0]["event_id"], events[-1]["event_id"]] and "coalesced" not in second
    assert adj.q.qsize() == 0
    exit_(net, p)
    clean(net, adj)


def test_no_trailing_evaluation_when_the_verdict_contained_the_task(sleepers):
    (p,) = sleepers()
    model = Counting(verdict("ISOLATE"))
    net, adj, fw, cgs, decisions = rig2(model, enforce=True)
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    for i in range(10):
        adj.submit(conn(net, p, "task0", 1000, ip=f"203.0.113.{10 + i}"))
    d = run_queued(adj)
    assert d["action"].startswith("done:ISOLATE") and "follow_up" not in d["coalesced"] and adj.q.qsize() == 0 and len(model.calls) == 1


def test_a_verdict_that_could_not_be_carried_out_does_not_count_as_containing(sleepers):
    (p,) = sleepers()
    model = Counting(verdict("ISOLATE"))
    net, adj, fw, cgs, decisions = rig2(model, enforce=True)
    cgs.where[p.pid], cgs.ids["task0"] = "task0", 1000
    for i in range(3):
        adj.submit(conn(net, p, "task0", 1000, ip=f"203.0.113.{10 + i}"))
    exit_(net, p)
    cgs.where.pop(p.pid, None)
    cgs.ids["task0"] = 4242                                    # the cgroup was replaced: the gate refuses (CGROUP_REPLACED)
    d = run_queued(adj)
    assert d["action"] == "blocked" and d["coalesced"]["follow_up"], "ISOLATE was said but not done: the tail still needs judging"


def test_identical_events_need_no_trailing_evaluation_even_after_allow(sleepers):
    (p,) = sleepers()
    model = Counting(verdict("ALLOW"))
    net, adj, *_ = rig2(model)
    for _ in range(10):
        adj.submit(conn(net, p))                               # same destination: the same inputs, so the same verdict
    d = run_queued(adj)
    assert d["coalesced"]["count"] == 9 and "follow_up" not in d["coalesced"] and adj.q.qsize() == 0 and len(model.calls) == 1


# ---- the premise: what the cooldown already does
def test_identical_connections_are_already_deduplicated_by_the_cooldown_so_coalescing_is_for_the_rest():
    emitted = []
    s = Sentinel("CORA_TASK", ["/tmp"], 150, 10.0, emitted.append, cooldown_s=30.0)

    def fire(ip, now):
        s._fire(("task0", "unauthorized_connection", ip, 443, None), now, {"ip": ip})
    for i in range(20):
        fire("203.0.113.9", 100.0 + i * 0.01)
    assert len(emitted) == 1, "twenty connections to ONE destination reach the adjudicator as one event"
    emitted.clear()
    for i in range(20):
        fire(f"203.0.113.{10 + i}", 200.0 + i * 0.01)
    assert len(emitted) == 20, "twenty DIFFERENT destinations are twenty events: that burst is what stalls the model"
    emitted.clear()
    fire("203.0.113.9", 131.0)
    assert len(emitted) == 1, "and after the cooldown the same destination fires again, while a stalled queue may still hold the first"


def test_the_docs_describe_coalescing_and_its_rules():
    from pathlib import Path
    doc = (Path(__file__).resolve().parents[1] / "docs" / "service.md").read_text()
    for word in ("coalesc", "blocklist", "follow_up", "IN_FLIGHT_MAX_AGE_S", "cooldown"):
        assert word in doc, word
