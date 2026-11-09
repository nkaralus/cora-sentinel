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
from cora_sentinel import ring_buffer as rb
from cora_sentinel.ring_buffer import RingStore, build_stall_segments
from cora_sentinel.uihub import SCHEMA

_spec = importlib.util.spec_from_file_location("cora_replay", Path(__file__).resolve().parents[1] / "tools" / "cora-replay.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


def frames(name):
    return [f for _, f in replay.scenario_frames(name) if not isinstance(f, replay.Op)]


IRREGULAR = {"seq_regression", "mono_regression", "unknown_status"}       # each tested on its own below


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
@pytest.mark.parametrize("name", sorted(set(replay.SCENARIOS) - IRREGULAR))
def test_every_scenario_speaks_the_schema_with_increasing_seq_and_mono(name):
    fs = frames(name)
    assert len(fs) >= 6
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
        srv = replay.ReplayServer(str(tmp_path / "ui.sock"), w, clock=clock, source=f"scenario:{name}")
        srv.start()
        made.append(srv)
        fs = replay.scenario_frames(name, w)
        srv.broadcast(next(fs)[1])
        return srv, w
    yield make
    for s in made:
        s.stop()


OPEN = []                                                                 # every test socket, closed at teardown


@pytest.fixture(autouse=True)
def _close_test_sockets():
    yield
    while OPEN:
        try:
            OPEN.pop().close()
        except OSError:
            pass


class Conn:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        OPEN.append(self.s)
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
    assert srv.connected() == 0 and not p.exists()


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
    OPEN.append(c)
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


def test_run_paces_by_speed_and_shifts_seq_past_breaker_frames_without_hiding_a_regression(tmp_path):
    slept, sent = [], []
    srv = replay.ReplayServer(str(tmp_path / "ui.sock"))
    srv.broadcast = lambda f, pieces=1: sent.append(f["seq"])
    srv.inserted = 2                                                      # two breaker replies went out
    n = replay.run(srv, iter([(0.0, {"seq": 1}), (2.0, {"seq": 2}), (2.0, {"seq": 1})]), speed=4.0, sleep=slept.append)
    assert n == 3 and slept == [0.5, 0.5] and sent == [3, 4, 3]


def test_the_cli_lists_scenarios_and_fixtures_and_rejects_unknown_ones(capsys):
    assert replay.main(["list"]) == 0
    out = capsys.readouterr().out
    assert all(name in out for name in replay.SCENARIOS) and "psiw_trip" in out and "psir_refused_healed" in out
    with pytest.raises(SystemExit):
        replay.main(["scenario", "nope", "--socket", "/nonexistent/x.sock"])



# ================================================================ played to the real client, on a virtual clock
def play_to_client(tmp_path, name, reconnect=True):
    """Serve a scenario and read it with the real StatusClient. Virtual time: every scripted wait advances the shared
    clock and sleeps only a moment. Returns (states seen, views seen, ring store, client)."""
    vt = [1000.0]
    w = replay.World()
    srv = replay.ReplayServer(str(tmp_path / "ui.sock"), w, clock=lambda: vt[0], source=f"scenario:{name}")
    srv.start()
    OPEN.append(srv)                                                      # stopped at teardown even if this fails
    c = uiclient.StatusClient(str(tmp_path / "ui.sock"), clock=lambda: vt[0])
    OPEN.append(c)
    assert c.connect()
    assert wait_for(lambda: srv.connected() == 1)                         # registered before the first frame
    store, states, views, done = RingStore(), [], [], []

    def sleep(d):
        time.sleep(0.03)
        vt[0] += d
    import threading
    th = threading.Thread(target=lambda: (replay.run(srv, replay.scenario_frames(name, w), sleep=sleep), done.append(1)))
    th.start()
    last = None

    def take():
        nonlocal last
        c.poll()
        if c.state is not None and c.state is not last:
            last = c.state
            states.append(c.state)
            store.feed(c.state, vt[0])
    while not done:
        if c.sock is None and reconnect:
            store.link_lost()
            c.connect()
        take()
        views.append(c.view())
        time.sleep(0.003)
    time.sleep(0.05)
    take()
    views.append(c.view())
    th.join()
    c.close()
    srv.stop()
    return states, views, store, c


def test_every_frame_on_the_wire_says_it_is_a_replay(tmp_path):
    states, views, store, c = play_to_client(tmp_path, "steady")
    assert states and all(f["replay"] == {"source": "scenario:steady"} for f in states)


def test_closed_connection_shows_unreachable_then_reconnects_to_the_latest_frame(tmp_path):
    states, views, store, c = play_to_client(tmp_path, "closed_connection")
    st = [v["status"] for v in views]
    i = st.index("unreachable")
    assert "clear" in st[:i] and "clear" in st[i:]
    assert store.global_resets == 0 and any(isinstance(p, rb.Gap) for p in store.rings[109].samples)


def test_silence_goes_unreachable_never_clear(tmp_path):
    states, views, store, c = play_to_client(tmp_path, "silence")
    st = [v["status"] for v in views]
    assert "unreachable" in st and st[-1] == "clear"
    assert "no data for" in next(v["detail"] for v in views if v["status"] == "unreachable")


def test_garbage_lines_are_skipped_and_the_feed_goes_on(tmp_path):
    states, views, store, c = play_to_client(tmp_path, "garbage")
    assert len(states) == 7 and all(f["schema"] == SCHEMA and f["type"] == "state" for f in states)
    assert {v["status"] for v in views} <= {"connecting", "clear"}


def test_split_frames_are_put_back_together(tmp_path):
    ops = [f for _, f in replay.scenario_frames("split_frames") if isinstance(f, replay.Op)]
    assert ops and all(o == replay.Op("split", 7) for o in ops)
    states, views, store, c = play_to_client(tmp_path, "split_frames")
    assert [f["seq"] for f in states] == list(range(1, 8))


def test_duplicate_frames_are_ignored_by_the_ring_buffer(tmp_path):
    states, views, store, c = play_to_client(tmp_path, "duplicate_frames")
    ring = store.rings[113]
    assert len([p for p in ring.samples if isinstance(p, rb.Sample)]) == 7 == len({f["seq"] for f in states})


def test_seq_regression_and_mono_regression_start_the_history_over():
    for name in ("seq_regression", "mono_regression"):
        fs = frames(name)
        store = RingStore()
        for f in fs:
            store.feed(f, f["mono"])
        assert store.global_resets == 1, name
        if name == "seq_regression":
            assert [f["seq"] for f in fs][5:7] == [6, 1]
        else:
            assert fs[6]["mono"] < fs[5]["mono"] and fs[6]["seq"] == 7


def test_counter_reset_starts_that_ring_over_with_no_negative_stall():
    fs = frames("counter_reset")
    store = RingStore()
    for f in fs:
        store.feed(f, f["mono"])
    ring = store.rings[fs[0]["tasks"][0]["cgroup_id"]]
    assert ring.resets == 1 and store.global_resets == 0
    assert all(v >= 0 for seg in build_stall_segments(ring.samples, 1.0) for _, v in seg.points)


def test_a_relaunch_under_a_new_cgroup_id_is_a_new_history_and_the_old_id_is_refused(served, tmp_path):
    fs = frames("relaunch_new_cgroup")
    ids = [f["tasks"][0]["cgroup_id"] if f["tasks"] else None for f in fs]
    assert ids[0] == 101 and None in ids and ids[-1] == 214
    store = RingStore()
    for f in fs:
        store.feed(f, f["mono"])
    assert store.rings[214].state == "live" and store.rings[101].state == "exited"     # two histories, not one
    srv, w = served("relaunch_new_cgroup")
    for _ in replay.scenario_frames("relaunch_new_cgroup", w):
        pass
    conn = Conn(str(tmp_path / "ui.sock"))
    conn.msg()
    conn.send(cmd="sever", task="relaunch-f8a9b0", cgroup_id=101, id="old")
    assert "is not the task you saw" in conn.until("result")["error"]
    conn.close()


def test_twenty_tasks_cover_every_band_and_the_client_reads_them_all():
    fs = frames("many_tasks")
    assert all(len(f["tasks"]) == 20 for f in fs)
    states = {t["psi_state"] for t in fs[-1]["tasks"]}
    assert states == {"armed", "refused", "disabled", "unmonitored"}
    v = client_view(fs)
    assert len(v["tasks"]) == 20 and v["status"] == "psi_refused"


def test_an_unknown_status_string_is_loud_and_then_clears():
    fs = frames("unknown_status")
    odd = [f for f in fs if f["status"] == "meltdown"]
    assert len(odd) == 4 and fs[-1]["status"] == "clear"
    v = client_view(fs[: fs.index(odd[0]) + 1])
    assert (v["status"], v["colour"]) == ("unknown", "red") and "received status: 'meltdown'" in v["detail"]
    assert client_view(fs)["status"] == "clear"


# ================================================================ the private socket directory
def test_the_default_socket_lives_in_a_private_0700_directory(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
    sock = replay.default_socket()
    assert sock == str(run / "cora-replay" / "ui.sock")
    assert (os.stat(run / "cora-replay").st_mode & 0o777) == 0o700
    assert replay.default_socket() == sock                                # reused when it is ours and 0700
    os.chmod(run / "cora-replay", 0o755)
    with pytest.raises(SystemExit, match="not a 0700 directory of ours"):
        replay.default_socket()


def test_without_a_runtime_dir_it_makes_a_fresh_private_temp_dir(monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    a, b = replay.default_socket(), replay.default_socket()
    try:
        assert a != b and os.path.basename(os.path.dirname(a)).startswith("cora-replay-")
        assert (os.stat(os.path.dirname(a)).st_mode & 0o777) == 0o700
    finally:
        for p in (a, b):
            os.rmdir(os.path.dirname(p))


def test_no_fixed_tmp_path_is_left_in_the_tool():
    src = (Path(__file__).resolve().parents[1] / "tools" / "cora-replay.py").read_text()
    assert "/tmp/cora-test-ui.sock" not in src


# ================================================================ sanitized real captures
def test_sanitize_keeps_only_named_tasks_zeroes_the_session_and_picks_the_last_run(tmp_path):
    f = lambda seq, *names: {"schema": SCHEMA, "type": "state", "seq": seq, "mono": 100.0 + seq, "ts": "2026-11-09T01:00:00+00:00",
                             "status": "clear", "session": {"community_blocked": 41, "started": "2026-11-08", "failed_actions": 0},
                             "tasks": [{"name": n} for n in names], "replay": {"source": "x"}}
    frames_ = [f(1, "psiq-1", "firefox"), f(2, "psiq-1"), f(1, "psiq-1", "steam"), f(2, "psiq-1", "game"), f(3)]
    out = replay.sanitize(frames_, ["psi"], (1, 2))
    assert [g["seq"] for g in out] == [1, 2] and out[0]["tasks"] == [{"name": "psiq-1"}]   # the second run
    assert out[0]["session"] == {"community_blocked": 0, "failed_actions": 0} and "replay" not in out[0]
    assert out[0]["ts"].startswith("2026-01-01T")
    assert replay.sanitize(frames_, ["psi"], (7, 8)) == []


def fixture_frames(name):
    return [f for _, f in replay.log_frames(replay.fixture_path(name))]


def test_the_shipped_fixtures_are_sanitized():
    for name in replay.fixtures():
        text = Path(replay.fixture_path(name)).read_text()
        for leak in ("/home/", "/media/", "Dimgeon", "nick", "firefox", "steam"):
            assert leak not in text, (name, leak)
        for f in fixture_frames(name):
            assert all(t["name"].startswith("psi") for t in f["tasks"])
            assert all(v in (0, None) for v in (f.get("session") or {}).values())


def test_fixture_psiw_trip_marks_the_live_trips_it_saw():
    fs = fixture_frames("psiw_trip")
    store = RingStore()
    for f in fs:
        store.feed(f, f["mono"])
    ring = next(r for r in store.rings.values() if r.name.startswith("psiw-"))
    trips = [m for m in ring.marks if m.kind == "trip"]
    assert len(trips) >= 15 and ring.pressure_active is True
    assert client_view(fs)["status"] == "contained"                       # psiz is isolated in the same frames


def test_fixture_psir_is_refused_after_the_restart_and_heals_without_another():
    fs = fixture_frames("psir_refused_healed")
    psir = [(f["seq"], f["status"], next(t for t in f["tasks"] if t["name"].startswith("psir-"))["psi_state"]) for f in fs]
    restart = next(i for i in range(1, len(fs)) if fs[i]["seq"] < fs[i - 1]["seq"])
    assert psir[restart][1:] == ("psi_refused", "refused")
    healed = next(i for i in range(restart, len(fs)) if psir[i][2] == "armed")
    assert psir[healed][1] == "clear" and all(fs[i]["seq"] > fs[i - 1]["seq"] for i in range(restart + 1, len(fs)))
    assert client_view(fs[: restart + 1])["status"] == "psi_refused" and client_view(fs)["status"] == "clear"


PRIVATE_IP = __import__("re").compile(r"\b(10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d+\.\d+\b"
                                      r"|\b(fe80|fc[0-9a-f]{2}|fd[0-9a-f]{2}):", __import__("re").I)


def test_the_fixtures_carry_no_user_host_path_or_private_address():
    for name in replay.fixtures():
        text = Path(replay.fixture_path(name)).read_text()
        for leak in ("nick", "dimgeon", "/media/", "/home/"):
            assert leak not in text.lower(), (name, leak)
        assert not PRIVATE_IP.search(text), (name, PRIVATE_IP.search(text).group(0))


def test_sanitize_changes_only_the_allowlisted_fields():
    t = lambda n: {"name": n, "cgroup_id": 9, "pids": 1, "psi": {"some_avg10": 1.5, "some_total_us": 123},
                   "limits": {"source": "launch", "memory_max": 1 << 29}, "pressure": {"active": True, "count": 19},
                   "scope": {"app": n.split("-")[0], "uid": 1000}}
    raw = [{"schema": SCHEMA, "type": "state", "seq": i, "mono": 50.0 + i, "ts": "2026-11-09T01:00:00+00:00",
            "status": "clear", "mode": "enforce", "session": {"community_blocked": 7, "started": "x"},
            "tasks": [t("psiq-1"), t("firefox-2")], "replay": {"source": "x"}} for i in (1, 2)]
    out = replay.sanitize(raw, ["psi"])
    for r, o in zip(raw, out):
        changed = {k for k in set(r) | set(o) if r.get(k) != o.get(k)}
        assert changed <= {"ts", "session", "tasks", "replay"}, changed
        assert json.dumps(o["tasks"], sort_keys=True) == json.dumps([r["tasks"][0]], sort_keys=True)   # kept tasks: byte for byte


def test_the_psiw_fixture_reaches_count_19_on_its_last_frame():
    lines = Path(replay.fixture_path("psiw_trip")).read_text().splitlines()
    f = json.loads(lines[32])
    t = next(t for t in f["tasks"] if t["name"].startswith("psiw-"))
    assert (len(lines), f["seq"], t["pressure"]["count"], t["pressure"]["active"]) == (33, 159, 19, True)


CAPTURES = Path("/media/nick/UE5_Storage/cora_scratch/psilive")


@pytest.mark.parametrize("fixture, capture", [("psiw_trip", "raw.log"), ("psir_refused_healed", "raw2.log")])
def test_the_fixtures_differ_from_their_raw_captures_only_where_allowed(fixture, capture):
    """Author's machine only (the raw captures never leave it): each fixture frame against the frame it came from."""
    if not (CAPTURES / capture).exists():
        pytest.skip("the raw capture is not on this machine")
    raw = {(f["seq"], f["mono"]): f for _, f in replay.read_log(str(CAPTURES / capture))}
    out = fixture_frames(fixture)
    assert out
    for o in out:
        r = raw[(o["seq"], o["mono"])]
        changed = {k for k in set(r) | set(o) if r.get(k) != o.get(k)}
        assert changed <= {"ts", "session", "tasks"}, changed
        by_name = {t["name"]: t for t in r["tasks"]}
        for t in o["tasks"]:
            assert json.dumps(t, sort_keys=True) == json.dumps(by_name[t["name"]], sort_keys=True)   # byte for byte
        assert [t["name"] for t in o["tasks"]] == [t["name"] for t in r["tasks"] if t["name"].startswith("psi")]
