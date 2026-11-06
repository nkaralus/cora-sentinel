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
from test_verdict import FakeCg, FakeFw, FakeModel, verdict


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
