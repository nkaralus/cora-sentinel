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
    assert v["status"] == "unreachable" and v["colour"] == "grey" and "no update" in v["detail"]


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
