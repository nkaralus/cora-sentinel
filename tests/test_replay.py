"""tools/cora-replay.py: the stand-in feed for cora-tray and cora-hud. Its frames come from the real Hub, its breaker
replies follow the hub's contract, and the real client (uiclient) and ring buffer read them as they would the daemon."""
import importlib.util
import json
import os
import socket
import time
from pathlib import Path

import pytest

from cora_sentinel import uiclient
from cora_sentinel.ring_buffer import RingStore, build_stall_segments
from cora_sentinel.uihub import SCHEMA

_spec = importlib.util.spec_from_file_location("cora_replay", Path(__file__).resolve().parents[1] / "tools" / "cora-replay.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


def frames(name):
    return [f for _, f in replay.scenario_frames(name)]


def only(f):
    assert len(f["tasks"]) == 1
    return f["tasks"][0]


class _Sock:
    def close(self):
        pass


def client_view(fs, now=None):
    """The real client's view after it has read these frames."""
    clock = [fs[-1]["mono"] if now is None else now]
    c = uiclient.StatusClient("/virtual", clock=lambda: clock[0])
    c.sock, c.connected_at = _Sock(), clock[0]
    for f in fs:
        c.ingest((json.dumps(f) + "\n").encode())
    return c.view()


# ================================================================ scenarios
@pytest.mark.parametrize("name", list(replay.SCENARIOS))
def test_every_scenario_speaks_the_schema_with_increasing_seq_and_mono(name):
    fs = frames(name)
    assert len(fs) >= 10
    assert all(f["schema"] == SCHEMA and f["type"] == "state" for f in fs)
    assert [f["seq"] for f in fs] == list(range(1, len(fs) + 1))
    assert all(b["mono"] > a["mono"] for a, b in zip(fs, fs[1:]))
    assert all(isinstance(f["status"], str) and f["status"] in uiclient.KNOWN_STATUS for f in fs)


def test_steady_is_a_clear_2s_heartbeat_with_one_live_task():
    fs = frames("steady")
    assert {f["status"] for f in fs} == {"clear"}
    assert {round(b["mono"] - a["mono"], 6) for a, b in zip(fs, fs[1:])} == {2.0}
    assert all(only(f)["pids"] == 1 and only(f).get("pressure") is None for f in fs)


def test_burst_goes_clear_then_trips_then_recovers():
    fs = frames("burst")
    st = [f["status"] for f in fs]
    first_trip = st.index("pressure")
    assert fs[first_trip]["mono"] - fs[0]["mono"] >= 10.0                 # 10 s clear first
    assert st[-1] == "clear" and only(fs[-1])["pressure"]["active"] is False
    counts = [(only(f).get("pressure") or {}).get("count") or 0 for f in fs]
    assert max(counts) == 10 and counts == sorted(counts)
    stalled = [only(f)["psi"]["some_avg10"] for f in fs if f["status"] == "pressure"]
    assert max(stalled) >= 15.0                                           # over the 150 ms / 1 s trigger


def test_refusal_recovery_heals_from_psi_refused_to_armed_and_clear():
    fs = frames("refusal_recovery")
    assert (fs[0]["status"], only(fs[0])["psi_state"]) == ("psi_refused", "refused")
    assert (fs[-1]["status"], only(fs[-1])["psi_state"]) == ("clear", "armed")
    assert client_view(fs[:1])["status"] == "psi_refused" and client_view(fs)["status"] == "clear"


def test_blind_recovery_is_blind_with_unknown_provenance_and_cap_still_offered_then_heals():
    fs = frames("blind_recovery")
    blind = [i for i, f in enumerate(fs) if f["status"] == "blind"]
    assert blind and fs[-1]["status"] == "clear" and only(fs[-1])["limits"]["source"] == "launch"
    f = fs[blind[0]]
    assert f["truth_errors"] == ["scope registry unreadable: /var/lib/cora-sentinel/scopes.json: not valid JSON "
                                 "(Expecting value at line 1 column 15)"]
    assert only(f)["limits"]["source"] == "unknown"
    v = client_view(fs[: blind[0] + 1])
    assert v["status"] == "blind" and v["tasks"][0]["can_cap"] is True and v["tasks"][0]["can_sever"] is True
    assert "limit provenance unknown (registry unreadable)" in v["detail"]
    assert client_view(fs)["status"] == "clear"


def test_coarse_stretch_is_hatched_coarse_by_the_ring_buffer():
    fs = frames("coarse_stretch")
    assert {round(b["mono"] - a["mono"], 6) for a, b in zip(fs, fs[1:])} == {2.0}
    assert only(fs[0])["psi_threshold"]["window_us"] == 1_000_000          # a 1 s window
    store = RingStore()
    for f in fs:
        store.feed(f, f["mono"])
    ring = store.rings[only(fs[0])["cgroup_id"]]
    segs = build_stall_segments(ring.samples, window_s=1.0)
    assert segs and all(s.coarse for s in segs)


def test_mid_trip_start_shows_the_trip_but_marks_none_of_its_history():
    fs = frames("mid_trip_start")
    p = only(fs[0])["pressure"]
    assert (p["count"], p["active"], fs[0]["status"]) == (3, True, "pressure")
    store = RingStore()
    store.feed(fs[0], fs[0]["mono"])
    ring = store.rings[only(fs[0])["cgroup_id"]]
    assert list(ring.marks) == [] and ring.pressure_active is True
    for f in fs[1:]:
        store.feed(f, f["mono"])
    assert [m.detail for m in ring.marks if m.kind == "trip"] == ["+1"] * 5     # later trips only (3 -> 8)
    assert fs[-1]["status"] == "clear" and ring.pressure_active is False


def test_unmonitored_has_no_scope_and_no_limits():
    t = only(frames("unmonitored")[0])
    assert t.get("scope") is None and t["psi_state"] == "unmonitored" and t["limits"]["source"] == "none"


def test_exited_refused_drops_the_warning_light_cleanly():
    fs = frames("exited_refused")
    assert fs[0]["status"] == "psi_refused"
    exited = next(f for f in fs if f["tasks"] and only(f)["pids"] == 0)
    assert exited["status"] == "clear" and only(exited)["psi_state"] == "refused"
    assert client_view([f for f in fs if f["seq"] <= exited["seq"]])["status"] == "clear"
    assert fs[-1]["tasks"] == [] and fs[-1]["status"] == "clear"


# ================================================================ the socket
@pytest.fixture
def served(tmp_path):
    made = []

    def make(name="breaker_rate_limit", clock=time.monotonic):
        w = replay.World()
        srv = replay.ReplayServer(str(tmp_path / "ui.sock"), w, clock=clock)
        srv.start()
        made.append(srv)
        fs = replay.scenario_frames(name, w)
        srv.broadcast(next(fs)[1])
        return srv, w
    yield make
    for s in made:
        s.stop()


class Conn:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(3)
        self.s.connect(path)
        self.buf = b""

    def msg(self):
        while b"\n" not in self.buf:
            d = self.s.recv(65536)
            assert d, "server closed the connection"
            self.buf += d
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def until(self, typ):
        while True:
            m = self.msg()
            if m.get("type") == typ:
                return m

    def send(self, **cmd):
        self.s.sendall((json.dumps(cmd) + "\n").encode())

    def close(self):
        self.s.close()


def wait_for(cond, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_the_socket_is_private_serves_the_latest_frame_at_once_and_is_removed_on_stop(served, tmp_path):
    srv, w = served()
    path = tmp_path / "ui.sock"
    assert (os.stat(path).st_mode & 0o777) == 0o600
    a, b = Conn(str(path)), Conn(str(path))
    assert a.msg()["seq"] == 1 and b.msg()["seq"] == 1
    assert wait_for(lambda: srv.connected() == 2)
    a.close()
    assert wait_for(lambda: srv.connected() == 1)                         # a disconnect is cleaned up
    srv.broadcast(dict(srv.latest, seq=2))
    assert b.msg()["seq"] == 2                                            # the other client is unaffected
    b.close()
    srv.stop()
    assert not path.exists()


def test_it_replaces_a_stale_socket_but_never_a_regular_file(tmp_path):
    p = tmp_path / "ui.sock"
    p.write_text("not a socket")
    with pytest.raises(SystemExit, match="not a socket"):
        replay.ReplayServer(str(p)).start()
    assert p.read_text() == "not a socket"
    p.unlink()
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(p))
    stale.close()
    srv = replay.ReplayServer(str(p))
    srv.start()
    srv.stop()


def test_breakers_take_effect_in_the_next_frame(served, tmp_path):
    srv, w = served()
    c = Conn(str(tmp_path / "ui.sock"))
    t = only(c.msg())
    c.send(cmd="sever", task=t["name"], cgroup_id=t["cgroup_id"], id="t1")
    state = c.until("state")
    res = c.until("result")
    assert res["ok"] is True and res["id"] == "t1" and res["action"].startswith("done:ISOLATE@cgroup:")
    assert "ISOLATE" in only(state)["enforced"] and state["status"] == "contained" and state["seq"] == 2
    c.close()


def test_a_second_breaker_within_a_second_is_refused_with_the_hubs_words(served, tmp_path):
    now = [500.0]
    srv, w = served(clock=lambda: now[0])
    c = Conn(str(tmp_path / "ui.sock"))
    t = only(c.msg())
    c.send(cmd="cap", task=t["name"], cgroup_id=t["cgroup_id"], id="t1")
    assert c.until("result")["ok"] is True
    now[0] += 0.4
    c.send(cmd="sever", task=t["name"], cgroup_id=t["cgroup_id"], id="t2")
    assert c.until("result") == {"schema": SCHEMA, "type": "result", "id": "t2", "ok": False,
                                 "error": "slow down: one command per second"}
    now[0] += 0.7
    c.send(cmd="sever", task=t["name"], cgroup_id=t["cgroup_id"], id="t3")
    assert c.until("result")["ok"] is True
    c.close()


@pytest.mark.parametrize("cmd,why", [
    ({"cmd": "release", "task": "x", "cgroup_id": 1}, "unknown command 'release'"),
    ({"cmd": "sever", "task": "nope", "cgroup_id": 1}, "no live task named 'nope'"),
    ({"cmd": "sever", "task": "ratelimit-b8c9d0", "cgroup_id": 999}, "is not the task you saw"),
])
def test_refusals_follow_the_hub(served, tmp_path, cmd, why):
    srv, w = served()
    c = Conn(str(tmp_path / "ui.sock"))
    c.msg()
    c.send(id="r", **cmd)
    res = c.until("result")
    assert res["ok"] is False and res["id"] == "r" and why in res["error"]
    c.close()


def test_garbage_does_not_kill_the_server(served, tmp_path):
    srv, w = served()
    c = Conn(str(tmp_path / "ui.sock"))
    c.msg()
    c.s.sendall(b"not json\n")
    assert c.until("result")["error"] == "not a JSON object"
    c.s.sendall(b"x" * 5000 + b"\n")                                      # over the line limit: dropped
    assert wait_for(lambda: srv.connected() == 0)
    d = Conn(str(tmp_path / "ui.sock"))
    assert d.msg()["type"] == "state"
    d.close()


def test_ack_not_reflected_acknowledges_changes_nothing_and_the_real_client_says_so(served, tmp_path):
    srv, w = served("ack_not_reflected")
    now = [0.0]
    c = uiclient.StatusClient(str(tmp_path / "ui.sock"), clock=lambda: now[0])
    assert c.connect()
    assert wait_for(lambda: c.poll() or c.state is not None)
    t = c.state["tasks"][0]
    tag = c.send("sever", t["name"], t["cgroup_id"])
    assert wait_for(lambda: c.poll() or tag in c.results)
    assert c.results[tag]["ok"] is True and "acknowledged only" in c.results[tag]["action"]
    assert "ISOLATE" not in c.state["tasks"][0]["enforced"]
    now[0] += uiclient.ACK_TIMEOUT_S + 0.1
    srv.broadcast(dict(srv.latest, seq=srv.latest["seq"] + 1))
    assert wait_for(lambda: c.poll() or c.state["seq"] == srv.latest["seq"])
    v = c.view()
    assert v["status"] == "unknown" and f"ACK_NOT_REFLECTED: sever on {t['name']}" in v["detail"]
    c.close()


# ================================================================ recorded feeds and pacing
def test_a_capture_log_replays_with_its_daemon_timing_and_loops_without_looking_like_a_restart(tmp_path):
    fs = frames("steady")[:4]
    log = tmp_path / "raw.log"
    log.write_text("### header\n2026-11-08T21:10:03.599 CONNECTED\n"
                   + "".join(f"2026-11-08T21:10:{3 + i:02d}.000 {json.dumps(f)}\n" for i, f in enumerate(fs))
                   + "garbage {\n" + json.dumps(fs[0]) + "\n")             # a raw line too
    out = list(replay.log_frames(str(log)))
    assert [dt for dt, _ in out] == [0.0, 2.0, 2.0, 2.0, 0.0]             # mono, not capture time; a jump back is 0
    looped = replay.log_frames(str(log), loop=True)
    two = [next(looped) for _ in range(10)]
    assert [f["seq"] for _, f in two[5:9]] == [f["seq"] + 4 for f in fs]   # pass 2 starts above pass 1's highest seq
    assert two[5][1]["mono"] > two[3][1]["mono"]


def test_a_log_without_frames_is_an_error(tmp_path):
    (tmp_path / "empty.log").write_text("CONNECTED\n")
    with pytest.raises(SystemExit, match="no state frames"):
        list(replay.log_frames(str(tmp_path / "empty.log")))


def test_run_paces_by_speed_and_keeps_seq_increasing_after_a_breaker_frame(tmp_path):
    slept = []
    srv = replay.ReplayServer(str(tmp_path / "ui.sock"))
    srv.latest = {"seq": 5}
    sent = []
    srv.broadcast = lambda f: (sent.append(f), setattr(srv, "latest", f))
    n = replay.run(srv, iter([(0.0, {"seq": 1}), (2.0, {"seq": 2}), (2.0, {"seq": 9})]), speed=4.0, sleep=slept.append)
    assert n == 3 and slept == [0.5, 0.5] and [f["seq"] for f in sent] == [6, 7, 9]


def test_the_cli_lists_scenarios_and_rejects_unknown_ones(capsys):
    assert replay.main(["list"]) == 0
    out = capsys.readouterr().out
    assert all(name in out for name in replay.SCENARIOS)
    with pytest.raises(SystemExit):
        replay.main(["scenario", "nope", "--socket", "/nonexistent/x.sock"])
