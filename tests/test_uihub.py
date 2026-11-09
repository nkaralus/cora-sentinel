"""The read-only status feed (uihub) and its client core (uiclient). Real Unix sockets in a temp dir."""
import json
import os
import socket
import stat
import time

import pytest

from cora_sentinel import uihub, uiclient
from cora_sentinel.uihub import Hub
from cora_sentinel.uiclient import StatusClient


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(uihub, "HEARTBEAT_S", 0.3)
    monkeypatch.setattr(uihub, "MIN_INTERVAL_S", 0.05)


@pytest.fixture
def rundir(tmp_path):
    d = tmp_path / "run"
    d.mkdir(mode=0o755)
    return d


class Live:
    def __init__(self):
        self.tasks, self.evaluating = {}, 0


@pytest.fixture
def live():
    return Live()


@pytest.fixture
def hub(rundir, live):
    logs = []
    h = Hub(str(rundir / "ui.sock"), mode="enforce", tasks=lambda: dict(live.tasks),
            evaluating=lambda: live.evaluating, log=logs.append)
    h.logs = logs
    h.start()
    yield h
    h.stop()


def connect(hub):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(hub.path))
    s.settimeout(3)
    return s


def next_state(s, pred=lambda m: True, timeout=3.0):
    f = s.makefile("rb")
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        line = f.readline()
        if not line:
            raise AssertionError("connection closed")
        m = json.loads(line)
        if pred(m):
            return m
    raise AssertionError("no matching state in time")


def ev(lst="community-trackers", entry="criteo.com"):
    return {"anomaly": {"evidence": {"blocklist": {"list": lst, "type": "tracker_domain", "entry": entry}}}}


# ---------------------------------------------------------------- the feed

def test_a_new_client_gets_a_snapshot_at_once(hub):
    s = connect(hub)
    m = next_state(s)
    assert m["schema"] == uihub.SCHEMA and m["type"] == "state" and m["status"] == "clear" and m["mode"] == "enforce"


def test_heartbeat_arrives_without_any_change(hub):
    s = connect(hub)
    first = next_state(s)
    second = next_state(s, lambda m: m["seq"] > first["seq"], timeout=2)
    assert second["status"] == "clear"


def test_community_and_other_blocklist_hits_are_counted_apart(hub):
    s = connect(hub)
    hub.note_event(ev())
    hub.note_event(ev("trackers-starter", "x.net"))
    hub.note_event({"anomaly": {"evidence": {}}})                 # not a blocklist hit
    hub.note_event({"garbage": 1})                                # malformed: ignored, never raises
    m = next_state(s, lambda m: m["session"]["blocked_total"] == 2)
    assert m["session"]["community_blocked"] == 1


def test_evaluating_then_contained_then_cleared_when_the_task_exits(hub, live):
    s = connect(hub)
    live.tasks = {"game": {"pids": 3, "mem_bytes": 100}}
    live.evaluating = 2
    assert next_state(s, lambda m: m["status"] == "evaluating")["evaluating"] == 2
    hub.note_decision({"final": "ISOLATE", "action": "done:ISOLATE@cgroup:game[nft-drop-egress]"})
    m = next_state(s, lambda m: m["status"] == "contained")
    assert m["tasks"][0]["contained"] == ["ISOLATE"]
    live.tasks, live.evaluating = {}, 0
    assert next_state(s, lambda m: m["status"] == "clear")["tasks"] == []


def test_early_containment_counts(hub, live):
    live.tasks = {"game": {"pids": 1, "mem_bytes": 1}}
    hub.note_decision({"final": "ESCALATE", "action": "noop",
                       "contained_first": {"action": "done:ISOLATE@cgroup:game[nft-drop-egress]"}})
    assert hub.snapshot()["status"] == "contained"


def test_throttle_and_suspend_contain_terminate_does_not_linger(hub, live):
    live.tasks = {"a": {"pids": 1, "mem_bytes": 1}, "b": {"pids": 1, "mem_bytes": 1}}
    hub.note_decision({"action": "done:THROTTLE@cgroup:a[cpu.max=20000 100000,memory.high=current]"})
    hub.note_decision({"action": "done:TERMINATE@cgroup:b"})
    t = {x["name"]: x["contained"] for x in hub.snapshot()["tasks"]}
    assert t == {"a": ["THROTTLE"], "b": []}


@pytest.mark.parametrize("d", [
    {"final": "DROPPED", "action": "dropped:queue-full", "queue_dropped": True},
    {"final": "ISOLATE", "action": "failed:FirewallError@cgroup:x"},
])
def test_alarm_is_sticky_and_beats_everything(hub, live, d):
    live.tasks = {"x": {"pids": 1, "mem_bytes": 1}}
    live.evaluating = 1
    hub.note_decision({"action": "done:ISOLATE@cgroup:x[nft-drop-egress]"})
    hub.note_decision(d)
    assert hub.snapshot()["status"] == "alarm"
    live.tasks, live.evaluating = {}, 0
    assert hub.snapshot()["status"] == "alarm"                    # a light that heals itself hides the event


def test_a_dropped_event_that_was_contained_first_is_not_an_alarm(hub):
    hub.note_decision({"final": "ISOLATE", "queue_dropped": True, "action": "done:ISOLATE@cgroup:x[...]"})
    assert hub.snapshot()["session"]["dropped_uncontained"] == 0


def test_memory_delta_is_from_first_sight(hub, live):
    live.tasks = {"game": {"pids": 1, "mem_bytes": 1000}}
    hub.snapshot()
    live.tasks = {"game": {"pids": 1, "mem_bytes": 5000}}
    t = hub.snapshot()["tasks"][0]
    assert t["mem_bytes"] == 5000 and t["mem_delta_bytes"] == 4000
    live.tasks = {}
    hub.snapshot()
    live.tasks = {"game": {"pids": 1, "mem_bytes": 7}}            # a new task with the same name starts over
    assert hub.snapshot()["tasks"][0]["mem_delta_bytes"] == 0


def test_unknown_memory_is_none_not_zero(hub, live):
    live.tasks = {"game": {"pids": 1, "mem_bytes": None}}
    t = hub.snapshot()["tasks"][0]
    assert t["mem_bytes"] is None and t["mem_delta_bytes"] is None


# ---------------------------------------------------------------- the daemon is never held up

def test_a_client_that_never_reads_cannot_stall_the_daemon(hub, live):
    live.tasks = {f"t{i}": {"pids": 1, "mem_bytes": i} for i in range(200)}   # fat snapshots
    s = connect(hub)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    t0 = time.monotonic()
    for _ in range(20000):
        hub.note_event(ev())
    assert time.monotonic() - t0 < 2.0
    end = time.monotonic() + 10
    while time.monotonic() < end and hub._clients:
        time.sleep(0.05)
    assert not hub._clients and any("too slow" in l for l in hub.logs)


def test_a_client_that_floods_is_dropped(hub):
    s = connect(hub)
    s.sendall(b"x" * (uihub.MAX_LINE_IN + 10))
    end = time.monotonic() + 3
    while time.monotonic() < end and not any("oversized" in l for l in hub.logs):
        time.sleep(0.05)
    assert any("oversized" in l for l in hub.logs)


def test_client_limit(hub):
    socks = [connect(hub) for _ in range(uihub.MAX_CLIENTS)]
    for s in socks:
        next_state(s)
    extra = connect(hub)
    extra.settimeout(2)
    assert extra.recv(10) == b""


def test_peer_uid_is_logged(hub):
    s = connect(hub)
    next_state(s)
    assert any(f"uid {os.getuid()}" in l for l in hub.logs)


# ---------------------------------------------------------------- the socket file

def test_socket_is_root_only_without_a_group(hub):
    assert stat.S_IMODE(hub.path.stat().st_mode) == 0o600


def test_socket_takes_the_group_and_0660(rundir):
    import grp
    g = grp.getgrgid(os.getgid()).gr_name
    h = Hub(str(rundir / "ui.sock"), group=g, log=lambda m: None)
    h.start()
    try:
        st = h.path.stat()
        assert stat.S_IMODE(st.st_mode) == 0o660 and st.st_gid == os.getgid()
    finally:
        h.stop()


def test_unknown_group_refused(rundir):
    with pytest.raises(OSError, match="no such group"):
        Hub(str(rundir / "ui.sock"), group="no-such-group-cora", log=lambda m: None).start()


def test_world_writable_directory_refused(tmp_path):
    d = tmp_path / "tmpish"
    d.mkdir()
    os.chmod(d, 0o1777)
    with pytest.raises(OSError, match="not world-writable"):
        Hub(str(d / "ui.sock"), log=lambda m: None).start()


def test_will_not_replace_a_non_socket(rundir):
    (rundir / "ui.sock").write_text("not a socket")
    with pytest.raises(OSError, match="not a socket"):
        Hub(str(rundir / "ui.sock"), log=lambda m: None).start()


def test_replaces_its_own_stale_socket_and_cleans_up(rundir):
    p = rundir / "ui.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(p))
    stale.close()
    h = Hub(str(p), log=lambda m: None)
    h.start()
    h.stop()
    assert not p.exists()


# ---------------------------------------------------------------- the client core

def test_client_view_while_connected(hub, live):
    live.tasks = {"game": {"pids": 2, "mem_bytes": 2 * 1024 ** 3}}
    hub.note_event(ev())
    c = StatusClient(str(hub.path))
    assert c.connect()
    end = time.monotonic() + 3
    while time.monotonic() < end and not (c.state and c.state["session"]["community_blocked"]):
        c.poll()
        time.sleep(0.02)
    v = c.view()
    assert v["status"] == "clear" and v["colour"] == "green"
    assert "1 community trackers blocked" in v["detail"] and v["tasks"][0]["line"].startswith("game: 2.0 GiB")


def test_silence_is_unreachable_never_the_last_colour(hub):
    now = [0.0]
    c = StatusClient(str(hub.path), clock=lambda: now[0])
    c.connect()
    end = time.monotonic() + 3
    while time.monotonic() < end and c.state is None:
        c.poll()
        time.sleep(0.02)
    assert c.view()["colour"] == "green"
    now[0] += uihub.STALE_AFTER_S + 0.1                           # nothing arrived for too long
    v = c.view()
    assert v["status"] == "unreachable" and v["colour"] == "grey" and "connected, no data for 6 s" in v["detail"]


def test_daemon_gone_is_unreachable(rundir, live):
    h = Hub(str(rundir / "ui.sock"), log=lambda m: None)
    h.start()
    c = StatusClient(str(h.path))
    c.connect()
    end = time.monotonic() + 3
    while time.monotonic() < end and c.state is None:
        c.poll()
        time.sleep(0.02)
    h.stop()
    end = time.monotonic() + 3
    while time.monotonic() < end and c.sock is not None:
        c.poll()
        time.sleep(0.02)
    assert c.view()["status"] == "unreachable"


def test_no_socket_explains_itself(tmp_path):
    c = StatusClient(str(tmp_path / "nope.sock"))
    assert not c.connect()
    assert "--ui-socket" in c.view()["detail"]


def test_dry_run_containment_says_nothing_was_done():
    c = StatusClient("/nonexistent")
    c.sock, c.last_rx = object(), 0.0
    c.clock = lambda: 0.0
    c.state = {"schema": uihub.SCHEMA, "type": "state", "status": "contained", "mode": "dry-run", "tasks": [],
               "session": {}}
    assert "nothing was done" in c.view()["title"]


def test_alarm_detail_names_the_cause():
    c = StatusClient("/nonexistent")
    c.sock, c.last_rx, c.clock = object(), 0.0, (lambda: 0.0)
    c.state = {"schema": uihub.SCHEMA, "type": "state", "status": "alarm", "mode": "enforce", "tasks": [],
               "session": {"dropped_uncontained": 2, "failed_actions": 0}}
    v = c.view()
    assert v["colour"] == "red" and v["detail"] == "2 dropped uncontained"


def test_client_ignores_garbage_and_foreign_schemas(hub):
    c = StatusClient(str(hub.path))
    c.connect()
    c.buf = b'not json\n{"schema":"other","type":"state"}\n'
    c.poll()
    assert c.state is None or c.state["schema"] == uihub.SCHEMA


def test_once_cli(hub, capsys):
    assert uiclient.main(["--socket", str(hub.path), "--once"]) == 0
    assert "[GREEN" in capsys.readouterr().out
    assert uiclient.main(["--socket", "/nonexistent/ui.sock", "--once"]) == 1


def test_a_relaunch_faster_than_a_snapshot_does_not_inherit_containment(rundir):
    """Keyed on the kernel cgroup id, not the name: a relaunch between two snapshots is still a different task."""
    ids = {"game": 41}
    live = {"game": {"pids": 1, "mem_bytes": 1, "id": 41}}
    h = Hub(str(rundir / "ui.sock"), tasks=lambda: {k: dict(v) for k, v in live.items()},
            cgroup_id=lambda n: ids.get(n), log=lambda m: None)
    h.note_decision({"action": "done:ISOLATE@cgroup:game[nft-drop-egress]"})
    assert h.snapshot()["status"] == "contained"
    live["game"]["id"] = ids["game"] = 42                         # exited and relaunched, no snapshot in between
    assert h.snapshot()["tasks"][0]["contained"] == []


def test_a_relaunched_task_with_the_same_name_does_not_inherit_the_old_containment(hub, live):
    live.tasks = {"game": {"pids": 1, "mem_bytes": 1}}
    hub.note_decision({"action": "done:ISOLATE@cgroup:game[nft-drop-egress]"})
    assert hub.snapshot()["status"] == "contained"
    live.tasks = {}
    hub.snapshot()                                                # the daemon sees it gone
    live.tasks = {"game": {"pids": 1, "mem_bytes": 1}}            # relaunched: a new task, nothing done to it
    assert hub.snapshot()["tasks"][0]["contained"] == []


def test_adjudicator_pending_counts_queue_and_the_running_one():
    from cora_sentinel.verdict import Adjudicator
    a = Adjudicator.__new__(Adjudicator)
    import queue
    a.q, a._busy = queue.Queue(), False
    assert a.pending() == 0
    a.q.put({}); a.q.put({})
    a._busy = True
    assert a.pending() == 3


def test_the_service_unit_provides_the_socket_directory():
    from pathlib import Path
    unit = (Path(__file__).resolve().parents[1] / "deploy" / "cora-sentinel.service").read_text()
    assert "RuntimeDirectory=cora-sentinel" in unit and "RuntimeDirectoryMode=0755" in unit


# ---------------------------------------------------------------- Track A: blind, and launch limits are not THROTTLE

def test_truth_errors_escalate_to_blind_and_clear_when_the_read_works_again(live):
    live.tasks = {"t": {"pids": 1, "mem_bytes": 1, "id": 7, "enforced": [], "unknown": ["ISOLATE"],
                        "errors": ["firewall unreadable (PermissionError)"], "psi": None}}
    h = Hub("/nonexistent/ui.sock", tasks=lambda: dict(live.tasks), log=lambda m: None)
    s = h.snapshot()
    assert s["status"] == "blind" and s["truth_errors"] == ["firewall unreadable (PermissionError)"]
    live.tasks["t"].update(unknown=[], errors=[])
    assert h.snapshot()["status"] == "clear"


def test_alarm_beats_blind_and_blind_beats_contained(live):
    live.tasks = {"t": {"pids": 1, "mem_bytes": 1, "id": 7, "enforced": ["ISOLATE"], "unknown": [],
                        "errors": ["firewall unreadable (X)"], "psi": None}}
    h = Hub("/nonexistent/ui.sock", tasks=lambda: dict(live.tasks), log=lambda m: None)
    assert h.snapshot()["status"] == "blind"
    h.note_decision({"final": "DROPPED"})
    assert h.snapshot()["status"] == "alarm"


def test_a_blind_daemon_is_red_with_the_exact_error_end_to_end(hub, live):
    live.tasks = {"t": {"pids": 1, "mem_bytes": 1, "id": 7, "enforced": [], "unknown": ["ISOLATE"],
                        "errors": ["firewall unreadable (PermissionError)"], "psi": None}}
    hub.note_event({})
    c = StatusClient(str(hub.path))
    c.connect()
    end = time.monotonic() + 3
    while time.monotonic() < end and not (c.state and c.state["status"] == "blind"):
        c.poll()
        time.sleep(0.02)
    v = c.view()
    assert (v["status"], v["colour"]) == ("blind", "red")
    assert v["detail"].startswith("firewall unreadable (PermissionError)")
    assert "firewall unreadable (PermissionError)" in f"{v['title']}\n{v['detail']}"   # the trays' tooltip


@pytest.fixture
def scoped(tmp_path):
    from cora_sentinel.cgroup import CgroupRoot
    from cora_sentinel.scope import Scopes
    root = tmp_path / "cora"
    root.mkdir()
    cg = CgroupRoot(str(root))
    scopes = Scopes(cg, state_path=str(tmp_path / "scopes.json"))

    def make(memory_max=None, memory_high=None, mem=64 << 20):
        name = scopes.create_scope("tracka", uid=1000, memory_max=memory_max, memory_high=memory_high)
        d = root / name
        for f, v in (("cgroup.procs", "4242"), ("cpu.max", "max 100000"), ("memory.current", str(mem)),
                     ("cgroup.freeze", "0")):
            (d / f).write_text(v + "\n")
        for f in ("memory.high", "memory.max"):
            if not (d / f).exists():
                (d / f).write_text("max\n")
        return name, d
    h = Hub("/nonexistent/ui.sock", tasks=uihub.cgroup_tasks(cg, None), cgroup_id=cg.cgroup_id, scopes=scopes,
            act=lambda v, t: "done", log=lambda m: None)
    return h, cg, make


def snap_task(h, name):
    s = h.snapshot()
    return s, next(t for t in s["tasks"] if t["name"] == name)


def can_cap(state, name):
    c = StatusClient("/x", clock=lambda: 0.0)
    c.sock, c.last_rx, c.connected_at, c.state = object(), 0.0, 0.0, state
    return next(t for t in c.view()["tasks"] if t["name"] == name)["can_cap"], c.view()


def test_a_launch_ceiling_is_not_throttle_and_cap_stays_offered(scoped):
    """Track A item 1b: cora-run --app --memory-high 400M alone read as THROTTLE and turned the tray indigo."""
    h, cg, make = scoped
    name, d = make(memory_max="512M", memory_high="400M")
    assert (d / "memory.high").read_text().strip() == str(400 << 20)
    s, t = snap_task(h, name)
    assert t["enforced"] == [] and t["contained"] == [] and s["status"] == "clear"
    assert t["limits"] == {"source": "launch", "cpu_max": None, "memory_high": 400 << 20, "memory_max": 512 << 20}
    ok, v = can_cap(s, name)
    assert ok and v["colour"] == "green"


def test_the_cap_breaker_on_a_launch_limited_task_is_sentinel_throttle(scoped):
    h, cg, make = scoped
    name, d = make(memory_max="512M", memory_high="400M")
    cg.throttle(name)                                        # what the Cap button runs: cpu.max 20%, memory.high=current
    s, t = snap_task(h, name)
    assert t["enforced"] == ["THROTTLE"] and s["status"] == "contained"
    assert t["limits"]["source"] == "sentinel" and t["limits"]["cpu_max"] == "20000 100000"
    assert t["limits"]["memory_high"] == 64 << 20
    ok, v = can_cap(s, name)
    assert not ok and v["colour"] == "indigo"


def test_memory_high_moved_off_the_launch_value_is_sentinel_even_without_cpu(scoped):
    h, cg, make = scoped
    name, d = make(memory_max="512M", memory_high="400M")
    (d / "memory.high").write_text(str(100 << 20))
    _, t = snap_task(h, name)
    assert t["enforced"] == ["THROTTLE"] and t["limits"]["source"] == "sentinel"


def test_a_launch_with_only_a_hard_ceiling_is_launch_and_not_throttle(scoped):
    h, cg, make = scoped
    name, _ = make(memory_max="512M")
    s, t = snap_task(h, name)
    assert t["enforced"] == [] and t["limits"]["source"] == "launch" and s["status"] == "clear"


def test_a_task_that_is_not_a_launch_scope_has_no_launch_limits(scoped, tmp_path):
    h, cg, make = scoped
    d = tmp_path / "cora" / "agent"
    d.mkdir()
    for f, v in (("cgroup.procs", "1"), ("cpu.max", "max 100000"), ("memory.high", str(400 << 20)),
                 ("memory.current", "1"), ("cgroup.freeze", "0"), ("memory.max", "max")):
        (d / f).write_text(v + "\n")
    _, t = snap_task(h, "agent")
    assert t["enforced"] == ["THROTTLE"] and t["limits"]["source"] == "sentinel"   # exactly as before


def test_no_kernel_reader_means_no_limits_claimed(live):
    live.tasks = {"t": {"pids": 1, "mem_bytes": 1}}
    t = Hub("/nonexistent/ui.sock", tasks=lambda: dict(live.tasks), log=lambda m: None).snapshot()["tasks"][0]
    assert t["limits"] is None


def test_a_cpu_limit_on_a_launch_limited_task_is_sentinel_even_at_the_launch_memory_value(scoped):
    h, cg, make = scoped
    name, d = make(memory_max="512M", memory_high="400M")
    (d / "cpu.max").write_text("20000 100000\n")             # memory.high still exactly the launch value
    _, t = snap_task(h, name)
    assert t["enforced"] == ["THROTTLE"] and t["limits"]["source"] == "sentinel"


def test_the_hub_ranks_contained_over_pressure_over_evaluating_over_clear(live):
    live.tasks = {"t": {"pids": 1, "mem_bytes": 1, "id": 7, "enforced": [], "unknown": [], "errors": [], "psi": None}}
    h = Hub("/nonexistent/ui.sock", tasks=lambda: dict(live.tasks), evaluating=lambda: live.evaluating,
            log=lambda m: None)
    assert h.snapshot()["status"] == "clear"
    live.evaluating = 1
    assert h.snapshot()["status"] == "evaluating"
    h.note_pressure("t", {"some_avg10": 40.0, "full_avg10": 5.0})
    assert h.snapshot()["status"] == "pressure"
    live.tasks["t"]["enforced"] = ["ISOLATE"]
    assert h.snapshot()["status"] == "contained"


def test_the_hub_never_sends_a_null_source(scoped, tmp_path):
    h, cg, make = scoped
    make(memory_max="512M", memory_high="400M")
    make(memory_max="512M")
    d = tmp_path / "cora" / "plain"
    d.mkdir()
    for f, v in (("cgroup.procs", "1"), ("cpu.max", "max 100000"), ("memory.high", "max"), ("memory.current", "1"),
                 ("cgroup.freeze", "0"), ("memory.max", "max")):
        (d / f).write_text(v + "\n")
    sources = {t["name"]: t["limits"]["source"] for t in h.snapshot()["tasks"]}
    assert sources["plain"] == "none" and set(sources.values()) <= {"launch", "sentinel", "none"}


def test_high_psi_on_a_launch_limited_task_is_amber_pressure(scoped):
    """Before Track A a launch ceiling read as `contained`, which outranks `pressure`: the tripwire's amber alert was
    hidden for exactly the tasks that have tripwires."""
    h, cg, make = scoped
    name, _ = make(memory_max="512M", memory_high="400M")
    h.note_pressure(name, {"some_avg10": 42.0, "full_avg10": 7.5})
    s, t = snap_task(h, name)
    assert s["status"] == "pressure" and t["limits"]["source"] == "launch" and t["pressure"]["active"]
    ok, v = can_cap(s, name)
    assert (v["status"], v["colour"]) == ("pressure", "amber") and ok
    assert name in v["title"] and "[PRESSURE some 42.0%]" in next(x["line"] for x in v["tasks"] if x["name"] == name)


def test_pressure_on_a_capped_task_stays_visible_on_its_line(scoped):
    h, cg, make = scoped
    name, _ = make(memory_max="512M", memory_high="400M")
    cg.throttle(name)
    h.note_pressure(name, {"some_avg10": 42.0, "full_avg10": 7.5})
    s, _ = snap_task(h, name)
    _, v = can_cap(s, name)
    assert v["status"] == "contained" and "[PRESSURE some 42.0%]" in next(x["line"] for x in v["tasks"] if x["name"] == name)


# ---------------------------------------------------------------- psi_state / psi_threshold: from what the kernel armed

class _Poll:
    def __init__(self):
        self.fds = {}

    def register(self, fd, ev):
        self.fds[fd] = ev

    def unregister(self, fd):
        self.fds.pop(fd, None)

    def poll(self, timeout=None):
        return []


@pytest.fixture
def psi_world(tmp_path, monkeypatch):
    from cora_sentinel.cgroup import CgroupRoot
    from cora_sentinel.psi import PressureWatcher
    from cora_sentinel.scope import Scopes
    from cora_sentinel import psi as psimod
    root = tmp_path / "cora"
    root.mkdir()
    cg = CgroupRoot(str(root))
    scopes = Scopes(cg, state_path=str(tmp_path / "scopes.json"))
    w = PressureWatcher(cg, on_trip=lambda n, s: None, log=lambda m: None, poller=_Poll)
    refuse = set()
    real = psimod.os.write

    def write(fd, data):
        if fd != w._wake_w and data.rstrip(b"\0").decode(errors="replace") in refuse:
            raise OSError(22, "Invalid argument")
        return real(fd, data)
    monkeypatch.setattr(psimod.os, "write", write)

    def make(trigger, app="game"):
        name = scopes.create_scope(app, uid=1000, memory_max="512M", psi_memory=trigger)
        d = root / name
        for f, v in (("cgroup.procs", "4242"), ("cpu.max", "max 100000"), ("memory.current", "1"),
                     ("cgroup.freeze", "0"), ("memory.high", "max"), ("memory.pressure", "")):
            if not (d / f).exists() or f in ("cgroup.procs", "memory.current"):
                (d / f).write_text(v + "\n")
        if trigger:
            try:
                w.add(name, trigger)
            except psimod.PsiError:
                pass
        return name

    def hub(with_psi=True):
        return Hub("/nonexistent/ui.sock", tasks=uihub.cgroup_tasks(cg, None), cgroup_id=cg.cgroup_id, scopes=scopes,
                   psi=w if with_psi else None, log=lambda m: None)
    yield make, hub, w, refuse, root
    w.stop()


def psi_of(h, name):
    t = next(t for t in h.snapshot()["tasks"] if t["name"] == name)
    return t["psi_state"], t["psi_threshold"]


def test_an_armed_tripwire_is_armed_with_its_threshold(psi_world):
    make, hub, w, refuse, root = psi_world
    name = make("some 150000 1000000")
    assert psi_of(hub(), name) == ("armed", {"kind": "some", "stall_us": 150000, "window_us": 1000000,
                                             "fraction": 0.15, "trigger": "some 150000 1000000"})


def test_a_kernel_refused_tripwire_is_refused_although_the_registry_keeps_it(psi_world):
    make, hub, w, refuse, root = psi_world
    refuse.add("some 150000 1000000")
    name = make("some 150000 1000000")
    h = hub()
    assert h.scopes.describe(name)["psi_memory"] == "some 150000 1000000"   # what the registry would have claimed
    assert psi_of(h, name) == ("refused", None)


def test_off_is_disabled_and_a_plain_task_is_unmonitored(psi_world):
    make, hub, w, refuse, root = psi_world
    off = make(None)
    plain = root / "agent"
    plain.mkdir()
    for f, v in (("cgroup.procs", "1"), ("cpu.max", "max 100000"), ("memory.current", "1"), ("cgroup.freeze", "0"),
                 ("memory.high", "max"), ("memory.max", "max")):
        (plain / f).write_text(v + "\n")
    h = hub()
    assert psi_of(h, off) == ("disabled", None) and psi_of(h, "agent") == ("unmonitored", None)


def test_without_a_watcher_a_requested_tripwire_is_unmonitored_not_armed(psi_world):
    make, hub, w, refuse, root = psi_world
    name = make("some 150000 1000000")
    assert psi_of(hub(with_psi=False), name) == ("unmonitored", None)


def test_removal_cleans_the_entry_and_a_relaunch_gets_a_fresh_one(psi_world):
    make, hub, w, refuse, root = psi_world
    refuse.add("some 150000 1000000")
    first = make("some 150000 1000000")
    h = hub()
    assert psi_of(h, first)[0] == "refused"
    w.remove(first)
    assert psi_of(h, first) == ("unmonitored", None)                      # nothing armed, nothing refused any more
    refuse.clear()
    second = make("some 150000 1000000")                                   # a relaunch: a new scope, a new cgroup
    assert second != first and psi_of(h, second)[0] == "armed"
    w.add(first, "some 300000 2000000")                                    # the same name re-armed
    assert psi_of(h, first) == ("armed", {"kind": "some", "stall_us": 300000, "window_us": 2000000,
                                          "fraction": 0.15, "trigger": "some 300000 2000000"})


def test_the_client_passes_known_psi_states_and_calls_anything_else_unknown(psi_world):
    make, hub, w, refuse, root = psi_world
    name = make("some 150000 1000000")
    snap = hub().snapshot()
    c = StatusClient("/x", clock=lambda: 0.0)
    c.sock, c.last_rx, c.connected_at, c.state = object(), 0.0, 0.0, snap
    vt = next(t for t in c.view()["tasks"] if t["name"] == name)
    assert vt["psi_state"] == "armed" and vt["psi_threshold"]["fraction"] == 0.15
    for t in snap["tasks"]:
        t.pop("psi_state"), t.pop("psi_threshold")                          # an older daemon
    assert all(t["psi_state"] == "unknown" and t["psi_threshold"] is None for t in c.view()["tasks"])
    for t in snap["tasks"]:
        t["psi_state"], t["psi_threshold"] = "melting", {"fraction": 0.5}
    assert all(t["psi_state"] == "unknown" and t["psi_threshold"] is None for t in c.view()["tasks"])


def test_a_live_refused_tripwire_raises_the_daemon_status_to_psi_refused(psi_world):
    make, hub, w, refuse, root = psi_world
    refuse.add("some 150000 1000000")
    name = make("some 150000 1000000")
    h = hub()
    snap = h.snapshot()
    assert snap["status"] == "psi_refused"
    c = StatusClient("/x", clock=lambda: 0.0)
    c.sock, c.last_rx, c.connected_at, c.state = object(), 0.0, 0.0, snap
    v = c.view()
    assert (v["status"], v["colour"]) == ("psi_refused", "amber") and f"psi refused on {name}" in v["detail"]
    assert "received status" not in v["detail"]                           # a status the client knows, not "unknown"
    (root / name / "cgroup.procs").write_text("")                          # every process gone: pids == 0
    assert h.snapshot()["status"] == "clear"


def test_psi_refused_sits_below_alarm_blind_and_contained_and_above_pressure(live):
    live.tasks = {"t": {"pids": 1, "mem_bytes": 1, "id": 7, "enforced": [], "unknown": [], "errors": [], "psi": None}}

    class P:
        def armed(self):
            return {}

        def refused(self):
            return {"t"}
    h = Hub("/nonexistent/ui.sock", tasks=lambda: dict(live.tasks), evaluating=lambda: 1, psi=P(), log=lambda m: None)
    h.note_pressure("t", {"some_avg10": 40.0})
    assert h.snapshot()["status"] == "psi_refused"                         # above pressure and evaluating
    live.tasks["t"]["enforced"] = ["ISOLATE"]
    assert h.snapshot()["status"] == "contained"                           # an active containment is never hidden
    live.tasks["t"]["errors"] = ["firewall unreadable (X)"]
    assert h.snapshot()["status"] == "blind"
    h.note_decision({"final": "DROPPED"})
    assert h.snapshot()["status"] == "alarm"


# ---------------------------------------------------------------- Track A gaps 1-3: refused, hierarchy, cross-layer agreement

class ScriptedPsi:
    def __init__(self, armed=None, refused=()):
        self._armed, self._refused = dict(armed or {}), set(refused)

    def armed(self):
        return dict(self._armed)

    def refused(self):
        return set(self._refused)


def _one_task(enforced=(), errors=(), pids=1):
    return {"t": {"pids": pids, "mem_bytes": 1, "id": 7, "enforced": list(enforced), "unknown": [], "errors": list(errors),
                  "psi": None}}


def test_snapshot_says_refused_when_the_watcher_reports_it():
    h = Hub("/nonexistent/ui.sock", tasks=lambda: _one_task(), psi=ScriptedPsi(refused={"t"}), log=lambda m: None)
    t = h.snapshot()["tasks"][0]
    assert (t["psi_state"], t["psi_threshold"]) == ("refused", None)
    h = Hub("/nonexistent/ui.sock", tasks=lambda: _one_task(), psi=ScriptedPsi(armed={"t": "some 150000 1000000"}),
            log=lambda m: None)
    assert h.snapshot()["tasks"][0]["psi_state"] == "armed"


def test_contained_outranks_psi_refused_and_alarm_outranks_blind_and_contained():
    h = Hub("/nonexistent/ui.sock", tasks=lambda: _one_task(enforced=["ISOLATE"]), psi=ScriptedPsi(refused={"t"}),
            log=lambda m: None)
    snap = h.snapshot()
    assert snap["tasks"][0]["contained"] == ["ISOLATE"] and snap["tasks"][0]["psi_state"] == "refused"
    assert snap["status"] == "contained"
    h2 = Hub("/nonexistent/ui.sock", tasks=lambda: _one_task(enforced=["ISOLATE"], errors=["firewall unreadable (X)"]),
             psi=ScriptedPsi(refused={"t"}), log=lambda m: None)
    h2.note_decision({"final": "DROPPED"})
    assert h2.snapshot()["status"] == "alarm"


import itertools


@pytest.mark.parametrize("alarm, blind, contained, refused, pressure, evaluating, exited",
                         list(itertools.product([False, True], repeat=7)))
def test_the_hub_and_the_client_agree_on_the_status(alarm, blind, contained, refused, pressure, evaluating, exited):
    """Every combination of the seven conditions: the status the hub computes is the status the client shows."""
    tasks = _one_task(enforced=["ISOLATE"] if contained else [], errors=["firewall unreadable (X)"] if blind else [],
                      pids=0 if exited else 1)
    h = Hub("/nonexistent/ui.sock", tasks=lambda: tasks, evaluating=lambda: int(evaluating),
            psi=ScriptedPsi(refused={"t"} if refused else ()), log=lambda m: None)
    if pressure:
        h.note_pressure("t", {"some_avg10": 40.0})
    if alarm:
        h.note_decision({"final": "DROPPED"})
    snap = h.snapshot()
    c = StatusClient("/x", clock=lambda: 0.0)
    c.sock, c.last_rx, c.connected_at, c.state = object(), 0.0, 0.0, snap
    assert snap["status"] == c.view()["status"], (snap["status"], c.view()["status"], c.view()["detail"])
