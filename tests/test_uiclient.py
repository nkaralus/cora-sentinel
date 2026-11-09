"""uiclient fails closed: what it cannot understand is loud (red "unknown"), what it cannot see is never green, and a
new connection never shows the previous connection's colour. Replays the Track A live check (03-unknown-status.log,
2026-11-08 on Dimgeon), where a missing status rendered green "all clear"."""
import json
import socket
import threading
import time

import pytest

from cora_sentinel import uihub, uiclient
from cora_sentinel.uihub import SCHEMA, STALE_AFTER_S, Hub
from cora_sentinel.uiclient import StatusClient, menu_spec

BASE = {"schema": SCHEMA, "type": "state", "ts": "x", "mode": "enforce", "evaluating": 0, "tasks": [], "session": {},
        "breakers": ["cap", "sever"], "truth_errors": []}


def task(**kw):
    t = {"name": "odd", "cgroup_id": 1, "pids": 1, "mem_bytes": 1, "mem_delta_bytes": 0, "contained": [],
         "enforced": [], "unknown": [], "psi": None}
    t.update(kw)
    return t


def view_of(state):
    c = StatusClient("/nonexistent", clock=lambda: 0.0)
    c.sock, c.last_rx, c.connected_at, c.state = object(), 0.0, 0.0, state
    return c.view()


def loud(v):
    assert v["colour"] == "red", v
    assert v["status"] not in ("clear", "unreachable", "connecting")


# ================================================================ missing, null, unrecognised status
@pytest.mark.parametrize("raw, shown", [
    ("<missing>", "<missing>"),
    (None, "None"),
    ("melting", "'melting'"),
    ("", "''"),
    ("CLEAR", "'CLEAR'"),                                    # not the same word
    (1, "1"),
    ({"status": "clear"}, "{'status': 'clear'}"),
    (["clear"], "['clear']"),
])
def test_a_status_the_client_does_not_know_is_unknown_and_loud(raw, shown):
    state = {k: v for k, v in BASE.items()} if raw == "<missing>" else {**BASE, "status": raw}
    v = view_of(state)
    loud(v)
    assert v["status"] == "unknown" and v["title"] == "cora: UNKNOWN status from cora-sentinel"
    assert f"received status: {shown}" in v["detail"]


@pytest.mark.parametrize("status, colour", [("clear", "green"), ("evaluating", "amber"), ("pressure", "amber"),
                                            ("contained", "indigo"), ("blind", "red"), ("alarm", "red")])
def test_the_statuses_the_daemon_sends_keep_their_colours(status, colour):
    v = view_of({**BASE, "status": status})
    assert (v["status"], v["colour"]) == (status, colour) and "received status" not in v["detail"]


# ================================================================ truth errors: blind, never green
def test_truth_errors_make_it_blind_even_if_the_daemon_said_clear():
    v = view_of({**BASE, "status": "clear", "truth_errors": ["firewall unreadable (PermissionError)"]})
    loud(v)
    assert v["status"] == "blind" and v["title"] == "cora: BLIND: cannot read what is enforced"
    assert v["detail"].startswith("firewall unreadable (PermissionError)")


def test_the_hubs_blind_shows_the_exact_error_text():
    v = view_of({**BASE, "status": "blind", "truth_errors": ["firewall unreadable (OSError)", "second problem"]})
    loud(v)
    assert v["detail"].startswith("firewall unreadable (OSError); second problem | ")


def test_alarm_stays_alarm_and_still_shows_the_truth_error():
    v = view_of({**BASE, "status": "alarm", "session": {"failed_actions": 1}, "truth_errors": ["firewall unreadable (X)"]})
    assert v["status"] == "alarm" and v["colour"] == "red" and "firewall unreadable (X)" in v["detail"]


# ================================================================ unrecognised verbs
@pytest.mark.parametrize("key", ["enforced", "contained", "unknown"])
def test_an_unknown_verb_is_loud_never_quiet_containment(key):
    v = view_of({**BASE, "status": "contained", "tasks": [task(**{key: ["MELT"]})]})
    loud(v)
    assert v["status"] == "unknown" and v["title"] == "cora: UNKNOWN verb from cora-sentinel"
    assert "unknown verb 'MELT' on odd" in v["detail"]


def test_the_task_line_names_the_unknown_verb_once():
    v = view_of({**BASE, "status": "contained", "tasks": [task(contained=["ISOLATE", "MELT"], enforced=["ISOLATE", "MELT"])]})
    assert "[ISOLATE, MELT: unknown verb]" in v["tasks"][0]["line"]
    assert v["detail"].count("unknown verb 'MELT' on odd") == 1


def test_an_unknown_verb_under_an_alarm_keeps_the_alarm_and_says_so():
    v = view_of({**BASE, "status": "alarm", "session": {"dropped_uncontained": 1}, "tasks": [task(enforced=["MELT"])]})
    assert v["status"] == "alarm" and "unknown verb 'MELT'" in v["detail"]


@pytest.mark.parametrize("bad", ["ISOLATE", {"v": 1}, [1], [None]])
def test_a_malformed_verb_list_is_unknown(bad):
    v = view_of({**BASE, "status": "clear", "tasks": [task(enforced=bad)]})
    loud(v)
    assert "malformed enforced" in v["detail"]


def test_known_verbs_are_not_flagged():
    v = view_of({**BASE, "status": "contained", "tasks": [task(contained=["ISOLATE", "SUSPEND", "THROTTLE"],
                                                                 enforced=["ISOLATE", "SUSPEND", "THROTTLE"])]})
    assert (v["status"], v["colour"]) == ("contained", "indigo") and "unknown verb" not in v["detail"]


# ================================================================ unreadable snapshots
@pytest.mark.parametrize("state", [
    {**BASE, "status": "clear", "tasks": "not a list"},
    {**BASE, "status": "clear", "tasks": [{"no": "name"}]},
    {**BASE, "status": "clear", "tasks": [42]},
])
def test_a_snapshot_the_client_cannot_read_is_unknown(state):
    v = view_of(state)
    loud(v)
    assert v["title"] == "cora: UNKNOWN snapshot from cora-sentinel" and "unreadable snapshot" in v["detail"]


# ================================================================ the watchdog and the connecting state
@pytest.fixture
def hub(tmp_path, monkeypatch):
    monkeypatch.setattr(uihub, "HEARTBEAT_S", 0.3)
    monkeypatch.setattr(uihub, "MIN_INTERVAL_S", 0.05)
    run = tmp_path / "run"
    run.mkdir(mode=0o755)
    h = Hub(str(run / "ui.sock"), mode="enforce", log=lambda m: None)
    h.start()
    yield h
    h.stop()


def poll_until(c, pred, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end and not pred():
        c.poll()
        time.sleep(0.02)


def test_a_new_connection_is_connecting_until_its_first_snapshot(hub):
    now = [100.0]
    c = StatusClient(str(hub.path), clock=lambda: now[0])
    assert c.connect()
    v = c.view()
    assert (v["status"], v["colour"], v["detail"]) == ("connecting", "grey", "connected, awaiting first snapshot")
    assert v["tasks"] == [] and not any(i[0] == "task" for i in menu_spec(v))
    assert "no sandboxed tasks" not in json.dumps(menu_spec(v))
    poll_until(c, lambda: c.state is not None)
    assert c.view()["status"] == "clear"


def test_reconnecting_resets_the_watchdog_and_never_shows_the_old_snapshot(hub):
    """The live restart log showed 'no update for 19 s' on a fresh connection: the old clock and the old snapshot."""
    now = [100.0]
    c = StatusClient(str(hub.path), clock=lambda: now[0])
    c.connect()
    poll_until(c, lambda: c.state is not None)
    assert c.view()["colour"] == "green"
    c.close()
    now[0] += 19                                             # the daemon was down this long
    assert c.view()["status"] == "unreachable"
    assert c.connect()
    v = c.view()
    assert v["status"] == "connecting" and "no data" not in v["detail"]
    assert c.state is None and c.last_rx is None and c.connected_at == now[0]


def test_connected_but_silent_past_the_limit_is_unreachable():
    now = [0.0]
    srv_dir = __import__("tempfile").mkdtemp()
    path = f"{srv_dir}/silent.sock"
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)                                            # accepts, never says anything
    try:
        c = StatusClient(path, clock=lambda: now[0])
        assert c.connect()
        assert c.view()["status"] == "connecting"
        now[0] += STALE_AFTER_S + 0.1
        v = c.view()
        assert (v["status"], v["colour"]) == ("unreachable", "grey") and v["detail"] == "connected, no data for 6 s"
    finally:
        srv.close()


def test_silence_after_snapshots_is_still_unreachable(hub):
    now = [0.0]
    c = StatusClient(str(hub.path), clock=lambda: now[0])
    c.connect()
    poll_until(c, lambda: c.state is not None)
    now[0] += STALE_AFTER_S + 0.1
    v = c.view()
    assert v["status"] == "unreachable" and v["detail"] == "connected, no data for 6 s"


# ================================================================ the live check's scenarios, over a real socket
def fake_server(path, msg):
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)

    def run():
        conn, _ = srv.accept()
        try:
            for _ in range(30):
                conn.sendall((json.dumps({**msg, "seq": 1}) + "\n").encode())
                time.sleep(0.05)
        except OSError:
            pass
        conn.close()
        srv.close()
    threading.Thread(target=run, daemon=True).start()


@pytest.mark.parametrize("label, msg, want_status, want_in_detail", [
    ("B unknown string", {**BASE, "status": "melting"}, "unknown", "received status: 'melting'"),
    ("C missing", dict(BASE), "unknown", "received status: <missing>"),
    ("D null", {**BASE, "status": None}, "unknown", "received status: None"),
    ("E unknown verb", {**BASE, "status": "contained", "tasks": [task(contained=["MELT"], enforced=["MELT"])]},
     "unknown", "unknown verb 'MELT' on odd"),
    ("A truth error", {**BASE, "status": "clear", "truth_errors": ["firewall unreadable (PermissionError)"]},
     "blind", "firewall unreadable (PermissionError)"),
])
def test_the_track_a_scenarios_end_to_end(tmp_path, label, msg, want_status, want_in_detail):
    path = str(tmp_path / "fake.sock")
    fake_server(path, msg)
    c = StatusClient(path)
    try:
        assert c.connect()
        poll_until(c, lambda: c.state is not None)
        v = c.view()
    finally:
        c.close()
    loud(v)
    assert v["status"] == want_status and want_in_detail in v["detail"]
    assert want_in_detail in uiclient.render_line(v)          # the HUD and the tooltip carry it too


# ================================================================ several faults at once: the worst wins, all are listed
def test_the_ranking_is_alarm_unknown_blind_contained_pressure_evaluating_clear():
    assert sorted(uiclient.RANK, key=uiclient.RANK.get, reverse=True) == \
        ["alarm", "unknown", "blind", "contained", "psi_refused", "pressure", "evaluating", "clear"]
    assert uiclient.RANK["psi_refused"] == uiclient.RANK["contained"]          # a tie: real containment wins it


ERR = "firewall unreadable (PermissionError)"


@pytest.mark.parametrize("state, want, must_list", [
    ({**BASE, "status": "clear", "truth_errors": [ERR], "tasks": [task(enforced=["MELT"])]},
     "unknown", [ERR, "unknown verb 'MELT' on odd"]),
    ({**BASE, "status": "blind", "truth_errors": [ERR], "tasks": [task(contained=["MELT"])]},
     "unknown", [ERR, "unknown verb 'MELT'"]),
    ({**BASE, "status": "contained", "truth_errors": [ERR], "tasks": [task(enforced=["ISOLATE"], contained=["ISOLATE"])]},
     "blind", [ERR]),
    ({**BASE, "truth_errors": [ERR]},                                                   # no status at all, and blind
     "unknown", ["received status: <missing>", ERR]),
    ({**BASE, "status": "alarm", "session": {"failed_actions": 2}, "truth_errors": [ERR],
      "tasks": [task(enforced=["MELT"])]},
     "alarm", ["2 failed actions", ERR, "unknown verb 'MELT'"]),
    ({**BASE, "status": "melting", "truth_errors": [ERR], "tasks": [task(enforced=["MELT"])]},
     "unknown", ["received status: 'melting'", ERR, "unknown verb 'MELT'"]),
    ({**BASE, "status": "evaluating", "tasks": [task(limits={"memory_high": 1 << 20})]},
     "contained", ["limit without launch provenance on odd"]),
])
def test_simultaneous_faults_the_worst_wins_and_every_fault_is_in_the_detail(state, want, must_list):
    v = view_of(state)
    assert v["status"] == want
    for fault in must_list:
        assert fault in v["detail"], (fault, v["detail"])


def test_unknown_status_and_unknown_verb_together_say_status_in_the_title():
    v = view_of({**BASE, "status": None, "tasks": [task(enforced=["MELT"])]})
    assert v["title"] == "cora: UNKNOWN status from cora-sentinel" and "unknown verb 'MELT'" in v["detail"]


# ================================================================ provenance: missing or null is never "launch"
@pytest.mark.parametrize("limits", [
    {"memory_high": 400 << 20, "source": None},
    {"memory_high": 400 << 20},                                         # no source key at all
    {"memory_high": 400 << 20, "source": "none"},                       # contradicts itself
    {"memory_high": 400 << 20, "source": "LAUNCH"},
    {"cpu_max": "20000 100000", "source": "launch"},                    # a launch never sets cpu.max
    {"cpu_max": "20000 100000", "source": None},
])
def test_a_limit_without_launch_provenance_is_the_sentinels(limits):
    v = view_of({**BASE, "status": "clear", "tasks": [task(limits=limits)]})
    assert (v["status"], v["colour"]) == ("contained", "indigo")
    assert not v["tasks"][0]["can_cap"] and "limit without launch provenance on odd" in v["detail"]


@pytest.mark.parametrize("limits", [
    {"source": "launch", "cpu_max": None, "memory_high": 400 << 20, "memory_max": 512 << 20},
    {"source": "launch", "cpu_max": None, "memory_high": None, "memory_max": 512 << 20},
    {"source": "none", "cpu_max": None, "memory_high": None, "memory_max": None},
    {"source": None, "memory_max": 512 << 20},                          # memory.max is a ceiling, never THROTTLE
    None,                                                               # no kernel reader
])
def test_launch_ceilings_and_no_limits_stay_clear_with_cap_offered(limits):
    v = view_of({**BASE, "status": "clear", "tasks": [task(limits=limits)]})
    assert (v["status"], v["colour"]) == ("clear", "green") and v["tasks"][0]["can_cap"]


# ================================================================ wedged daemon vs dead socket
def test_a_dead_socket_says_so_and_is_not_called_wedged(hub):
    c = StatusClient(str(hub.path))
    c.connect()
    poll_until(c, lambda: c.state is not None)
    hub.stop()
    poll_until(c, lambda: c.sock is None)
    v = c.view()
    assert v["status"] == "unreachable" and v["detail"] == "cora-sentinel closed the connection"
    assert "no data" not in v["detail"]


def test_garbage_frames_do_not_count_as_data():
    now = [0.0]
    d = __import__("tempfile").mkdtemp()
    path = f"{d}/garbage.sock"
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)
    try:
        c = StatusClient(path, clock=lambda: now[0])
        c.connect()
        conn, _ = srv.accept()
        conn.sendall(b'not json\n{"schema": "someone-else/v1", "type": "state", "status": "clear"}\n')
        time.sleep(0.1)
        c.poll()
        now[0] += STALE_AFTER_S + 2
        assert c.view()["detail"] == "connected, no data for 8 s"
        conn.close()
    finally:
        srv.close()


# ================================================================ ingest(): the parsing half of poll(), for replay and simulation
class _NoSock:
    def close(self):
        pass


def virtual(now):
    c = StatusClient("/virtual", clock=lambda: now[0])
    c.sock, c.connected_at = _NoSock(), now[0]
    return c


def test_ingest_takes_frames_in_any_split_with_virtual_time():
    now = [1000.0]
    c = virtual(now)
    line = (json.dumps({**BASE, "status": "clear", "seq": 1}) + "\n").encode()
    assert c.ingest(line[:20]) is False and c.state is None                # half a frame: nothing yet
    now[0] = 1001.5
    assert c.ingest(line[20:]) is True and c.state["seq"] == 1 and c.last_rx == 1001.5
    two = (json.dumps({**BASE, "status": "clear", "seq": 2}) + "\n" + json.dumps({**BASE, "status": "alarm", "seq": 3})
           + "\n").encode()
    assert c.ingest(two) and c.state["seq"] == 3 and c.view()["status"] == "alarm"
    now[0] += STALE_AFTER_S + 0.1                                         # virtual silence
    assert c.view()["status"] == "unreachable"


def test_ingest_keeps_the_old_rules_garbage_foreign_results_oversize():
    now = [0.0]
    c = virtual(now)
    assert c.ingest(b'not json\n{"schema": "other/v1", "type": "state"}\n') is False and c.state is None
    assert c.ingest((json.dumps({"schema": SCHEMA, "type": "result", "id": "t1", "ok": True}) + "\n").encode())
    assert c.results["t1"]["ok"] is True
    assert c.ingest(b"x" * (uiclient.MAX_LINE + 1)) is True and c.sock is None and "oversized" in c.error


# ================================================================ a refused tripwire is elevated, never quiet
def test_a_refused_tripwire_raises_the_view_to_containment_rank_and_names_the_task():
    v = view_of({**BASE, "status": "clear", "tasks": [task(name="game-1a2b3c", psi_state="refused"), task(name="ok")]})
    assert (v["status"], v["colour"]) == ("psi_refused", "amber")
    assert uiclient.RANK["psi_refused"] == uiclient.RANK["contained"]
    assert v["title"] == "cora: memory-pressure tripwire refused" and v["detail"].startswith("psi refused on game-1a2b3c")
    assert "[PSI REFUSED]" in v["tasks"][0]["line"] and "[PSI REFUSED]" not in v["tasks"][1]["line"]


@pytest.mark.parametrize("status, want", [("evaluating", "psi_refused"), ("pressure", "psi_refused"),
                                          ("contained", "contained"), ("blind", "blind"), ("alarm", "alarm")])
def test_refusal_outranks_quieter_states_and_yields_to_louder_ones(status, want):
    tasks = [task(psi_state="refused", enforced=["ISOLATE"] if status == "contained" else [],
                  contained=["ISOLATE"] if status == "contained" else [])]
    extra = {"truth_errors": ["firewall unreadable (X)"]} if status == "blind" else {}
    v = view_of({**BASE, "status": status, "tasks": tasks, **extra})
    assert v["status"] == want and "psi refused on odd" in v["detail"]


def test_an_exited_task_with_a_refused_tripwire_does_not_hold_the_light_up():
    v = view_of({**BASE, "status": "clear", "tasks": [task(psi_state="refused", pids=0)]})
    assert v["status"] == "clear"


# ================================================================ limits.source "unknown": the registry is unreadable
def test_unknown_provenance_keeps_cap_offered_and_does_not_claim_containment():
    t = task(name="game-1a2b3c", contained=["THROTTLE"], enforced=["THROTTLE"],
             limits={"source": "unknown", "cpu_max": None, "memory_high": 400 << 20, "memory_max": 512 << 20})
    v = view_of({**BASE, "status": "blind", "truth_errors": ["scope registry unreadable: x"], "tasks": [t]})
    vt = v["tasks"][0]
    assert vt["can_cap"] is True and vt["can_sever"] is True
    assert "[THROTTLE]" not in vt["line"] and "[limit provenance unknown]" in vt["line"]
    assert "limit provenance unknown (registry unreadable) on game-1a2b3c" in v["detail"]
    assert (v["status"], v["colour"]) == ("blind", "red")


def test_unknown_provenance_is_loud_even_without_truth_errors():
    t = task(limits={"source": "unknown", "cpu_max": None, "memory_high": 1 << 20, "memory_max": None},
             enforced=["THROTTLE"], contained=["THROTTLE"])
    v = view_of({**BASE, "status": "clear", "tasks": [t]})
    assert v["status"] == "blind" and v["tasks"][0]["can_cap"] is True


def test_unknown_provenance_does_not_hide_a_real_isolation():
    t = task(limits={"source": "unknown", "cpu_max": "20000 100000", "memory_high": 1 << 20, "memory_max": None},
             enforced=["ISOLATE", "THROTTLE"], contained=["ISOLATE", "THROTTLE"])
    vt = view_of({**BASE, "status": "blind", "truth_errors": ["scope registry unreadable: x"], "tasks": [t]})["tasks"][0]
    assert vt["can_sever"] is False and vt["can_cap"] is True and "[ISOLATE]" in vt["line"]


# ================================================================ ACK_NOT_REFLECTED: an acknowledged breaker must show up in force
class _SendSock(_NoSock):
    def __init__(self):
        self.sent = []

    def setblocking(self, v):
        pass

    def settimeout(self, v):
        pass

    def sendall(self, data):
        self.sent.append(json.loads(data))


def acked(now, ok=True, cmd="sever", **at_press):
    c = StatusClient("/virtual", clock=lambda: now[0])
    c.sock, c.connected_at = _SendSock(), now[0]
    c.ingest((json.dumps({**BASE, "status": "clear", "seq": 1, "mono": 50.0,
                          "tasks": [task(name="game", cgroup_id=9, **at_press)]}) + "\n").encode())
    tag = c.send(cmd, "game", 9)
    assert c.sock.sent[-1] == {"cmd": cmd, "task": "game", "cgroup_id": 9, "id": tag}
    c.ingest((json.dumps({"schema": SCHEMA, "type": "result", "id": tag, "ok": ok}) + "\n").encode())
    return c


CAPPED = {"source": "none", "cpu_max": "20000 100000", "memory_high": 64 << 20, "memory_max": None}
UNCAPPED = {"source": "none", "cpu_max": None, "memory_high": None, "memory_max": None}


def frame_with(c, seq, mono=None, **kw):
    c.ingest((json.dumps({**BASE, "status": kw.pop("status", "clear"), "seq": seq, "mono": 50.0 + seq if mono is None else mono,
                          "tasks": [task(name="game", cgroup_id=9, **kw)]}) + "\n").encode())


def test_an_acknowledged_breaker_that_never_shows_up_is_loud():
    now = [100.0]
    c = acked(now)
    frame_with(c, 2)
    assert c.view()["status"] == "clear"                                  # still within the grace period
    now[0] += uiclient.ACK_TIMEOUT_S + 0.1
    frame_with(c, 3)
    v = c.view()
    assert (v["status"], v["colour"], v["title"]) == ("unknown", "red", "cora: breaker acknowledged but not in force")
    assert "ACK_NOT_REFLECTED: sever on game acknowledged 5 s ago, ISOLATE not in force" in v["detail"]


def test_a_breaker_that_shows_up_in_force_is_settled():
    now = [100.0]
    c = acked(now, cmd="cap")
    frame_with(c, 2, status="contained", enforced=["THROTTLE"], contained=["THROTTLE"], limits=CAPPED)
    now[0] += uiclient.ACK_TIMEOUT_S + 0.5                                # past the deadline, inside the 6 s staleness
    assert c.awaiting == {} and c.view()["status"] == "contained"


def test_a_refused_breaker_or_a_task_that_ended_is_not_awaited():
    now = [100.0]
    assert acked(now, ok=False).awaiting == {}
    c = acked(now)
    c.ingest((json.dumps({**BASE, "status": "clear", "seq": 2, "tasks": []}) + "\n").encode())
    now[0] += uiclient.ACK_TIMEOUT_S + 1
    assert c.awaiting == {} and c.view()["status"] == "clear"


def late(now):
    now[0] += uiclient.ACK_TIMEOUT_S + 0.1


def alerting(c):
    return "ACK_NOT_REFLECTED" in c.view()["detail"]


def test_a_sever_pressed_while_isolate_was_already_in_force_is_not_proven_by_it():
    now = [100.0]
    c = acked(now, enforced=["ISOLATE"], contained=["ISOLATE"])
    late(now)
    frame_with(c, 2, status="contained", enforced=["ISOLATE"], contained=["ISOLATE"])
    assert alerting(c)


def test_a_cap_is_proven_by_numbers_that_changed_not_by_throttle_alone():
    now = [100.0]
    c = acked(now, cmd="cap", enforced=["THROTTLE"], limits=CAPPED)
    late(now)
    frame_with(c, 2, status="contained", enforced=["THROTTLE"], limits=CAPPED)          # the same numbers: no proof
    assert alerting(c)
    c = acked(now, cmd="cap", limits=UNCAPPED)
    frame_with(c, 2, status="contained", enforced=["THROTTLE"], limits=CAPPED)          # cpu.max and memory.high moved
    late(now)
    frame_with(c, 3, status="contained", enforced=["THROTTLE"], limits=CAPPED)
    assert c.awaiting == {} and not alerting(c)
    c = acked(now, cmd="cap", limits=UNCAPPED)
    frame_with(c, 2, status="clear", enforced=[], limits=CAPPED)                         # numbers but no THROTTLE
    late(now)
    frame_with(c, 3, status="clear", enforced=[], limits=CAPPED)
    assert alerting(c)


def test_the_alert_unlatches_when_the_verb_shows_up_late():
    now = [100.0]
    c = acked(now)
    late(now)
    frame_with(c, 2)
    assert alerting(c)
    frame_with(c, 3, status="contained", enforced=["ISOLATE"], contained=["ISOLATE"])   # a slow kernel, then there
    assert c.awaiting == {} and not alerting(c) and c.view()["status"] == "contained"


def test_the_alert_unlatches_on_a_new_press_and_on_reconnect():
    now = [100.0]
    c = acked(now)
    late(now)
    frame_with(c, 2)
    assert alerting(c)
    c.send("cap", "game", 9)                                              # a new press supersedes the old check
    assert c.awaiting == {} and not alerting(c) and len(c._sent) == 1
    c = acked(now)
    late(now)
    frame_with(c, 2)
    assert alerting(c)
    c.close()                                                             # reconnect starts with close()
    assert c.awaiting == {} and c._sent == {}


@pytest.mark.parametrize("why", ["exited", "gone", "seq went back", "mono went back"])
def test_a_pending_check_is_dropped_when_its_task_exits_or_the_daemon_restarts(why):
    now = [100.0]
    c = acked(now)
    if why == "exited":
        frame_with(c, 2, pids=0)
    elif why == "gone":
        c.ingest((json.dumps({**BASE, "status": "clear", "seq": 2, "mono": 52.0, "tasks": []}) + "\n").encode())
    elif why == "seq went back":
        frame_with(c, 0, mono=60.0)
    else:
        frame_with(c, 5, mono=10.0)
    assert c.awaiting == {}
    late(now)
    frame_with(c, 9, mono=70.0)                                           # even with the task back, unchanged
    assert not alerting(c)


def test_an_unanswered_press_is_dropped_on_a_restart_too():
    now = [100.0]
    c = StatusClient("/virtual", clock=lambda: now[0])
    c.sock, c.connected_at = _SendSock(), now[0]
    frame_with(c, 5)
    tag = c.send("sever", "game", 9)
    frame_with(c, 1, mono=10.0)                                           # restarted before it answered
    c.ingest((json.dumps({"schema": SCHEMA, "type": "result", "id": tag, "ok": True}) + "\n").encode())
    assert c.awaiting == {}


class _EOFSock(_SendSock):
    def recv(self, n):
        return b""


def test_a_pending_check_is_dropped_when_the_link_drops():
    now = [100.0]
    c = acked(now)
    c.sock = _EOFSock()
    assert c.poll() is True and c.sock is None and c.awaiting == {}



# ================================================================ what a HUD reads off the view
def test_the_view_carries_the_replay_source_and_the_daemon_never_does():
    assert view_of({**BASE, "status": "clear", "tasks": []})["replay"] is None
    v = view_of({**BASE, "status": "clear", "tasks": [], "replay": {"source": "scenario:burst"}})
    assert v["replay"] == "scenario:burst"
    assert view_of({**BASE, "status": "clear", "tasks": [], "replay": True})["replay"] == "True"
    assert StatusClient("/nonexistent").view()["replay"] is None


def test_view_tasks_carry_mem_bytes_for_the_cap_confirmation():
    v = view_of({**BASE, "status": "clear", "tasks": [task(mem_bytes=64 << 20), task(name="b", mem_bytes=None)]})
    assert [t["mem_bytes"] for t in v["tasks"]] == [64 << 20, None]
    head, body = uiclient.confirm_text("cap", "game", 64 << 20)
    assert "memory.high = its memory.current at that moment (last seen 64.0 MiB)" in body
    assert f"cpu.max = {uiclient.CAP_CPU_MAX} (20% of one CPU)" in body
    assert "last seen ?" in uiclient.confirm_text("cap", "game")[1]
    assert "memory.high" not in uiclient.confirm_text("sever", "game", 1)[1]


def test_on_state_sees_every_frame_even_several_in_one_read():
    seen = []
    c = StatusClient("/virtual", clock=lambda: 0.0)
    c.on_state = lambda f: seen.append(f["seq"])
    c.ingest(b"".join((json.dumps({**BASE, "status": "clear", "seq": i, "tasks": []}) + "\n").encode() for i in (1, 2, 3)))
    assert seen == [1, 2, 3] and c.state["seq"] == 3



# ================================================================ a frozen daemon: commands time out, never hang
def _frozen_pair(now):
    a, b = socket.socketpair()
    a.setblocking(False)
    c = StatusClient("/virtual", clock=lambda: now[0])
    c.sock, c.connected_at = a, now[0]
    c.ingest((json.dumps({**BASE, "status": "clear", "seq": 1, "mono": 50.0,
                          "tasks": [task(name="game", cgroup_id=9)]}) + "\n").encode())
    return c, b


def test_a_breaker_sent_to_a_frozen_daemon_times_out_instead_of_waiting_forever():
    now = [100.0]
    c, peer = _frozen_pair(now)
    try:
        tag = c.send("sever", "game", 9)                                   # the daemon reads nothing, answers nothing
        assert tag in c._sent and c.view()["tasks"][0]["pending"] is None
        now[0] += uiclient.ACK_TIMEOUT_S + 0.1
        c.last_rx = now[0]                                                 # the feed itself still looks alive
        v = c.view()
        assert c._sent == {} and tag in c.timed_out
        assert v["tasks"][0]["pending"] == "unconfirmed, may still apply" and v["tasks"][0]["pending_cmd"] == "sever"
        assert (v["status"], v["title"]) == ("unknown", "cora: breaker unanswered: daemon unresponsive")
        assert "COMMAND_TIMEOUT: sever on game sent 5 s ago, no reply (unconfirmed, may still apply)" in v["detail"]
        c.ingest((json.dumps({"schema": SCHEMA, "type": "result", "id": tag, "ok": True}) + "\n").encode())
        assert c.timed_out == {} and tag in c.awaiting                     # a late answer un-latches, then is checked
    finally:
        c.close()
        peer.close()


def test_a_send_into_a_full_socket_gives_up_after_send_timeout(monkeypatch):
    now = [100.0]
    c, peer = _frozen_pair(now)
    try:
        c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        try:
            while True:
                c.sock.send(b"x" * 65536)                                  # fill it: nobody on the other end reads
        except BlockingIOError:
            pass
        monkeypatch.setattr(uiclient, "SEND_TIMEOUT_S", 0.2)
        t0 = time.monotonic()
        assert c.send("cap", "game", 9) is None
        assert time.monotonic() - t0 < 1.5 and c.sock is None and c.error.startswith("could not send")
        assert c._sent == {} and c.timed_out == {}                         # nothing left pending on a dead link
    finally:
        c.close()
        peer.close()


def test_task_status_ranks_one_task_by_what_the_feed_says_about_it():
    c = StatusClient("/x")
    assert c.task_status(task()) == "clear"
    assert c.task_status(task(pressure={"active": True})) == "pressure"
    assert c.task_status(task(psi_state="refused")) == "psi_refused"
    assert c.task_status(task(psi_state="refused", pids=0)) == "clear"
    assert c.task_status(task(enforced=["ISOLATE"])) == "contained"
    assert c.task_status(task(enforced=["MELT"])) == "unknown"
    assert c.task_status(task(errors=["firewall unreadable (x)"], enforced=["ISOLATE"])) == "blind"
    assert c.task_status(task(alarm="action failed: x", errors=["e"])) == "alarm"
