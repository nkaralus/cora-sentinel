"""tools/cora-hud.py: a window over uiclient.view() and ring_buffer. The builder is pure (view + rings + clock ->
primitives), so most of this runs without any GUI; pixel tests use the HUD's own raster, and Qt's when PySide6 is
importable."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

from cora_sentinel import ring_buffer as rb
from cora_sentinel import uiclient
from cora_sentinel.uihub import SCHEMA

ROOT = Path(__file__).resolve().parents[1]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


hud = _load("cora_hud", "tools/cora-hud.py")
replay = _load("cora_replay_for_hud", "tools/cora-replay.py")
W, H = 960, 640
PLOT_BG = hud.INK["plot"]


class FakeSock:
    def __init__(self):
        self.sent = []

    def close(self):
        pass

    def recv(self, n):
        raise BlockingIOError

    def setblocking(self, v):
        pass

    def settimeout(self, v):
        pass

    def sendall(self, data):
        self.sent.append(json.loads(data))


class Rig:
    """A HudModel on a virtual clock, fed frames as if from the socket."""

    def __init__(self, socket_path=uiclient.DEFAULT_SOCKET, scale="sqrt"):
        self.t = [0.0]
        self.m = hud.HudModel(socket_path, clock=lambda: self.t[0], wall=lambda: 1_700_000_000.0 + self.t[0],
                              scale=scale)
        self.m.client.sock, self.m.client.connected_at = FakeSock(), 0.0
        self.m._linked = True
        self.m._next_try = float("inf")           # never dial a real socket (the default one is the live daemon's)

    def feed(self, frame, dt=0.0):
        self.t[0] += dt
        self.m.client.ingest((json.dumps(frame) + "\n").encode())
        self.m.tick()

    def wait(self, dt):
        self.t[0] += dt
        self.m.tick()

    def scene(self, w=W, h=H):
        return self.m.scene(w, h)


def play(name, rig=None, stamp=True, until=None):
    rig = rig or Rig()
    for dt, f in replay.scenario_frames(name):
        if isinstance(f, replay.Op):
            if f.kind == "silence":
                rig.wait(dt)
            continue
        rig.feed(dict(f, replay={"source": f"scenario:{name}"}) if stamp else f, dt)
        if until is not None and until(f):
            break
    return rig


def base(seq, mono, tasks, status="clear", **kw):
    return {"schema": SCHEMA, "type": "state", "seq": seq, "mono": mono, "status": status, "mode": "enforce",
            "evaluating": 0, "breakers": ["sever", "cap"], "truth_errors": [], "session": {}, "tasks": tasks, **kw}


def task(cid=7, name="game-1a2b3c", some=0, psi_state="armed", thr=(150000, 1000000), pids=1, count=None,
         active=False, enforced=(), limits=None, avg10=None):
    t = {"name": name, "cgroup_id": cid, "pids": pids, "mem_bytes": 64 << 20, "mem_delta_bytes": 0, "contained": list(enforced),
         "enforced": list(enforced), "unknown": [], "psi_state": psi_state,
         "psi": {"some_avg10": avg10 if avg10 is not None else 0.0, "some_avg60": 0.0, "some_total_us": some,
                 "full_avg10": 0.0, "full_avg60": 0.0, "full_total_us": some // 2},
         "limits": limits or {"source": "launch", "cpu_max": None, "memory_high": None, "memory_max": 512 << 20}}
    if psi_state == "armed" and thr:
        t["psi_threshold"] = {"kind": "some", "stall_us": thr[0], "window_us": thr[1], "fraction": thr[0] / thr[1],
                              "trigger": f"some {thr[0]} {thr[1]}"}
    if count is not None:
        t["pressure"] = {"active": active, "count": count, "some_avg10": 0.0, "full_avg10": 0.0}
    return t


def steady(rig, n, step=0.5, seq0=1, mono0=100.0, per_s=50_000, **kw):
    for i in range(n):
        m = mono0 + i * step
        rig.feed(base(seq0 + i, m, [task(some=int((m - 90) * per_s), **kw)]), step if i else 0.0)
    return mono0 + (n - 1) * step


def only(scene):
    assert len(scene.panels) == 1
    return scene.panels[0]


def texts(scene):
    return [it.text for it in scene.items if isinstance(it, hud.Text)]


def raster(scene):
    return hud.Raster(scene)


# ================================================================ status, colour, banners: uiclient's, verbatim
STATUS_FRAMES = {
    "clear": base(1, 100.0, [task()]),
    "pressure": base(1, 100.0, [task(count=1, active=True)], status="pressure"),
    "psi_refused": base(1, 100.0, [task(psi_state="refused")], status="psi_refused"),
    "contained": base(1, 100.0, [task(enforced=["ISOLATE"])], status="contained"),
    "blind": base(1, 100.0, [task()], status="blind", truth_errors=["firewall unreadable (x)"]),
    "alarm": base(1, 100.0, [task()], status="alarm"),
    "unknown": base(1, 100.0, [task()], status="meltdown"),
}


@pytest.mark.parametrize("status", list(STATUS_FRAMES))
def test_the_header_is_exactly_the_clients_colour_and_title(status):
    r = Rig()
    r.feed(STATUS_FRAMES[status])
    v, s = r.m.view, r.scene()
    assert v["status"] == status
    assert s.header_colour == rb.PALETTE[uiclient.COLOURS[status]] == rb.PALETTE[v["colour"]]
    assert v["title"] in texts(s) and v["detail"][:W // 7] in texts(s)


def test_unreachable_and_connecting_are_grey_never_the_last_colour():
    r = Rig()
    assert r.scene().header_colour == rb.PALETTE["grey"]                   # connecting
    r.feed(STATUS_FRAMES["clear"])
    r.wait(10.0)                                                          # silent past STALE_AFTER_S
    s = r.scene()
    assert r.m.view["status"] == "unreachable" and s.header_colour == rb.PALETTE["grey"]


def test_replay_banner_is_shown_and_stays_for_the_life_of_the_window():
    r = Rig()
    r.feed(STATUS_FRAMES["clear"])
    assert not any(b.startswith("REPLAY") for b in r.scene().banners)     # the daemon's own feed: no banner
    r.feed(dict(base(2, 101.0, [task()]), replay={"source": "scenario:burst"}), 1.0)
    assert r.scene().banners[0] == "REPLAY — not the live daemon (scenario:burst)"
    r.feed(base(3, 102.0, [task()]), 1.0)                                 # an unstamped frame does not clear it
    r.wait(30.0)                                                          # nor does silence
    r.m.client.close()
    r.m.tick()
    assert r.m.client.sock is None and r.scene().banners[0].startswith("REPLAY")


def test_a_non_default_socket_is_flagged_loudly():
    assert Rig().scene().banners == ()
    s = Rig("/tmp/x/ui.sock").scene()
    assert s.banners == ("NON-DEFAULT SOCKET: /tmp/x/ui.sock — this may not be cora-sentinel",)
    assert any(isinstance(i, hud.Rect) and i.fill == hud.INK["nondefault"] for i in s.items)


# ================================================================ time axis and history
def test_history_says_how_far_back_it_really_goes():
    r = Rig()
    assert r.scene().history == "history: none yet"
    steady(r, 21)                                                         # 10 s
    assert r.scene().history.endswith("(10 s)")
    assert "since" in r.scene().history and "120" not in r.scene().history


def test_the_right_edge_runs_on_the_client_clock_so_a_silent_feed_grows_a_gap():
    r = Rig()
    steady(r, 21)
    g0 = only(r.scene()).gaps
    r.wait(3.0)                                                           # no frames: still within staleness
    g1 = only(r.scene()).gaps
    assert g0 == () and len(g1) == 1
    x0, y0, pw, h = only(r.scene()).plot
    assert g1[0][1] == x0 + pw - 1 and g1[0][1] - g1[0][0] >= int(3.0 / (hud.SPAN_S / pw)) - 2
    curve_right = max(x for c in only(r.scene()).curves for x, _ in c)
    assert curve_right <= g1[0][0]


def test_a_hole_in_the_feed_is_background_and_nothing_is_drawn_across_it():
    r = Rig()
    end = steady(r, 21)
    steady(r, 21, seq0=30, mono0=end + 8.0)                               # 8 s with no frames
    p = only(r.scene())
    (a, b), = [g for g in p.gaps if g[1] < p.plot[0] + p.plot[2] - 2]
    for c in p.curves:
        assert all(not (a <= x <= b) for x, _ in c)
        assert not any(x1 < a and x2 > b for (x1, _), (x2, _) in zip(c, c[1:]))
    assert all(x1 <= a or x0 >= b for x0, x1, _, _ in p.runs)
    px = raster(r.scene())
    for x in range(a + 1, b):
        assert {px.px(x, y) for y in range(p.plot[1], p.plot[1] + p.plot[3])} == {PLOT_BG}


# ================================================================ bands and thresholds
def test_each_epoch_draws_its_own_threshold():
    r = Rig()
    end = steady(r, 21, thr=(150000, 1000000))
    steady(r, 21, seq0=30, mono0=end + 0.5, thr=(300000, 1000000))
    p = only(r.scene())
    armed = [run for run in p.runs if run[2] == "armed"]
    assert len(armed) == 2
    y = lambda f: int(round(p.plot[1] + p.plot[3] - 2 - hud.scale_value(f) * (p.plot[3] - 4)))
    assert [run[3] for run in armed] == [y(0.15), y(0.30)]
    assert armed[0][1] <= armed[1][0]                                     # they meet, never overlap


@pytest.mark.parametrize("psi_state, label", [("refused", "BLIND (no tripwire)"), ("disabled", "off"),
                                              ("unmonitored", "not-configured"), ("weird", "unknown")])
def test_bands_are_named_and_filled(psi_state, label):
    r = Rig()
    steady(r, 11, psi_state=psi_state)
    s = r.scene()
    p = only(s)
    assert {run[2] for run in p.runs} == {psi_state if psi_state != "weird" else "unknown"}
    assert all(run[3] is None for run in p.runs)                          # no threshold to draw
    assert label in texts(s)
    fill = hud.BAND_FILL[p.runs[0][2]]
    assert any(isinstance(i, hud.Rect) and i.fill == fill for i in s.items)


def test_a_task_not_yet_drawn_still_names_its_band():
    r = Rig()
    r.feed(base(1, 100.0, [task(psi_state="refused")]))
    assert "BLIND (no tripwire)" in texts(r.scene())
    r = Rig()
    r.feed(base(1, 100.0, [task()]))
    assert "waiting for data" in texts(r.scene())


# ================================================================ coarse
def test_coarse_stretches_are_hatched_and_carry_no_curve():
    r = play("coarse_stretch")
    p = only(r.scene())
    assert p.coarse and not p.curves
    hatches = [i for i in r.scene().items if isinstance(i, hud.Hatch)]
    assert [(h.x, h.x + h.w) for h in hatches] == list(p.coarse)
    px = raster(r.scene())
    a, b = p.coarse[0]
    colours = {px.px(x, y) for x in range(a, b) for y in range(p.plot[1] + 20, p.plot[1] + p.plot[3] - 20)}
    assert hud.INK["hatch"] in colours


def test_a_fine_feed_draws_a_curve_and_no_hatching():
    r = Rig()
    steady(r, 41, step=0.25)
    p = only(r.scene())
    assert p.curves and not p.coarse


# ================================================================ marks and the badge
def test_trip_marks_follow_count_increments_and_the_badge_follows_active():
    r = Rig()
    r.feed(base(1, 100.0, [task(some=0)]))
    r.feed(base(2, 100.5, [task(some=25_000, count=1, active=True)]), 0.5)
    r.feed(base(3, 101.0, [task(some=50_000, count=4, active=True)]), 0.5)
    p = only(r.scene())
    assert [(k, d) for _, k, d in p.marks] == [("trip", "+1"), ("trip", "+3")] and p.badge == "tripped ≤ 10 s ago"
    r.feed(base(4, 101.5, [task(some=75_000, count=4, active=False)]), 0.5)
    assert only(r.scene()).badge is None and len(only(r.scene()).marks) == 2


def test_a_hud_opened_mid_trip_shows_the_badge_and_no_history_marks():
    r = play("mid_trip_start", until=lambda f: f["seq"] == 1)
    p = only(r.scene())
    assert p.badge and p.marks == ()
    r = play("mid_trip_start")
    assert [d for _, k, d in only(r.scene()).marks if k == "trip"] == ["+1"] * 5


# ================================================================ breakers
def test_buttons_are_exactly_the_views_eligibility():
    for name in ("blind_recovery", "refusal_recovery", "many_tasks", "steady"):
        r = play(name)
        s = r.scene(W, 2000)
        vt = {(t["name"], t["cgroup_id"]): t for t in r.m.view["tasks"]}
        for b in s.buttons:
            assert b.enabled is vt[(b.task, b.cgroup_id)][f"can_{b.cmd}"], (name, b)
    r = Rig()
    r.feed(base(1, 100.0, [task(enforced=["ISOLATE", "THROTTLE"], limits={"source": "sentinel", "cpu_max": "20000 100000",
                                                                      "memory_high": 1, "memory_max": None})], status="contained"))
    assert [b.enabled for b in r.scene().buttons] == [False, False]


def test_unknown_provenance_keeps_cap_offered_in_the_hud():
    r = play("blind_recovery", until=lambda f: f["status"] == "blind")
    (sever, cap), = [p.buttons for p in r.scene().panels]
    assert r.m.view["status"] == "blind" and cap.enabled and sever.enabled


def test_a_press_is_refused_unless_offered_and_only_sever_or_cap_go_out():
    r = Rig()
    r.feed(base(1, 100.0, [task(enforced=["ISOLATE"])], status="contained"))
    assert r.m.press("sever", "game-1a2b3c", 7) is None                   # already isolated: not offered
    assert r.m.press("release", "game-1a2b3c", 7) is None
    assert r.m.press("cap", "game-1a2b3c", 8) is None                     # not the task you saw
    assert r.m.client.sock.sent == []
    tag = r.m.press("cap", "game-1a2b3c", 7)
    assert r.m.client.sock.sent == [{"cmd": "cap", "task": "game-1a2b3c", "cgroup_id": 7, "id": tag}]
    assert [m.detail for m in r.m.store.rings[7].marks] == ["cap:sent"]
    r.m.client.ingest((json.dumps({"schema": SCHEMA, "type": "result", "id": tag, "ok": False,
                                   "error": "slow down: one command per second"}) + "\n").encode())
    r.m.tick()
    assert [m.detail for m in r.m.store.rings[7].marks] == ["cap:sent", "cap:failed"]
    assert r.m.notice == "cap on game-1a2b3c: refused: slow down: one command per second"
    assert r.m.notice in texts(r.scene())


def test_the_cap_confirmation_names_its_target_values():
    r = Rig()
    r.feed(base(1, 100.0, [task()]))
    head, body = r.m.confirm("cap", "game-1a2b3c", 7)
    assert (head, body) == uiclient.confirm_text("cap", "game-1a2b3c", 64 << 20)
    assert "64.0 MiB" in body and uiclient.CAP_CPU_MAX in body


def test_the_dialogs_default_to_cancel_and_escape_closes_them():
    src = (ROOT / "tools" / "cora-hud.py").read_text()
    assert src.count("box.setDefaultButton(cancel)") == 1 and src.count("box.setEscapeButton(cancel)") == 1


def test_qt_is_the_only_toolkit():
    src = (ROOT / "tools" / "cora-hud.py").read_text()
    assert "tkinter" not in src and "run_tk" not in src and "--backend" not in src


def test_without_pyside6_it_says_how_to_install_it(monkeypatch):
    monkeypatch.setattr(hud, "have_qt", lambda: False)
    with pytest.raises(SystemExit, match=r'pip install "cora-sentinel\[hud\]"'):
        hud.main(["--socket", "/nonexistent/ui.sock"])


def test_the_hud_sends_nothing_but_breakers_and_runs_nothing():
    src = (ROOT / "tools" / "cora-hud.py").read_text()
    for banned in ("subprocess", "os.system", "os.popen", "exec(", "eval(", "shell=True"):
        assert banned not in src.replace("box.exec()", "").replace("app.exec()", ""), banned
    assert hud.ALLOWED == ("sever", "cap") and src.count("client.send(") == 1


def test_hit_testing_finds_buttons():
    r = Rig()
    r.feed(base(1, 100.0, [task()]))
    s = r.scene()
    b = s.buttons[1]
    assert hud.hit(s, b.x + 1, b.y + 1) == b and hud.hit(s, 1, 1) is None


# ================================================================ pacing and scale
def test_repaints_are_capped_at_10_hz_and_only_when_the_picture_changes():
    assert hud.MAX_HZ <= 10 and 1000 // hud.MAX_HZ >= 100
    r = Rig()
    steady(r, 21)
    s0 = r.scene()
    r.wait(0.05)
    assert r.scene() == s0                                                # under a pixel of time: same picture
    r.wait(1.0)
    assert r.scene() != s0                                                # the right edge moved


def test_scale_toggles_between_sqrt_and_symlog():
    assert hud.scale_value(0) == 0 == hud.scale_value(0, "symlog") and hud.scale_value(1) == 1
    assert abs(hud.scale_value(1, "symlog") - 1) < 1e-12
    assert hud.scale_value(0.01) == pytest.approx(0.1) and hud.scale_value(0.01, "symlog") == pytest.approx(0.1503, abs=1e-3)
    assert hud.scale_value(2) == 1 and hud.scale_value(-1) == 0
    r = Rig()
    steady(r, 41, step=0.25)
    a = only(r.scene()).curves
    r.m.toggle_scale()
    assert r.m.scale == "symlog" and only(r.scene()).curves != a and "scale: symlog (s toggles)" in texts(r.scene())


def test_too_many_tasks_say_how_many_are_hidden():
    r = play("many_tasks")
    s = r.scene(W, 480)
    assert s.hidden == 20 - len(s.panels) > 0
    assert s.footer == f"+{s.hidden} more tasks (worst: clear on many04-000004)" and s.footer in texts(s)


def test_an_exited_task_says_so_and_a_task_gone_from_the_feed_is_kept_without_buttons():
    r = play("exited_refused", until=lambda f: f["tasks"] and f["tasks"][0]["pids"] == 0)
    p = only(r.scene())
    assert p.exited and "exited" in texts(r.scene())
    r = play("relaunch_new_cgroup")
    s = r.scene()
    old = next(p for p in s.panels if p.cgroup_id == 101)
    assert old.buttons == () and "no longer in the feed" in texts(s)


# ================================================================ every scenario, on the virtual clock
@pytest.mark.parametrize("name", list(replay.SCENARIOS))
def test_every_scenario_draws_within_the_rules(name):
    r = Rig()
    n = 0
    for dt, f in replay.scenario_frames(name):
        if isinstance(f, replay.Op):
            if f.kind == "silence":
                r.wait(dt)
            continue
        r.feed(dict(f, replay={"source": f"scenario:{name}"}), dt)
        s = r.scene()
        n += 1
        assert s.header_colour == rb.PALETTE[r.m.view["colour"]]
        assert s.banners and s.banners[0].startswith("REPLAY")
        vt = {(t["name"], t["cgroup_id"]): t for t in r.m.view["tasks"]}
        for b in s.buttons:
            assert b.enabled is vt[(b.task, b.cgroup_id)][f"can_{b.cmd}"]
        for p in s.panels:
            x0, _, pw, _ = p.plot
            for c in p.curves:
                assert all(x0 <= x <= x0 + pw for x, _ in c)
                for a, b in p.coarse:                                     # no curve inside a hatched span
                    assert not any(a < x < b for x, _ in c)
                for a, b in p.gaps:
                    assert not any(a <= x <= b for x, _ in c)
    assert n >= 6


# ================================================================ pixels
def test_the_raster_is_not_blank_and_shows_the_status_colour():
    r = play("burst")
    s = r.scene()
    px = raster(s)
    colours = {px.px(x, y) for x in range(0, W, 7) for y in range(0, H, 5)}
    assert len(colours) >= 5
    header_y = 24 + 10                                                    # under the REPLAY banner
    assert px.px(W - 5, header_y) == s.header_colour
    assert px.px(W - 5, 10) == hud.INK["replay"]
    p = only(s)
    assert any(px.px(x, y) == hud.INK["curve"] for c in p.curves for x, y in c)


def test_snapshot_writes_a_png(tmp_path):
    _qt()
    m = hud.HudModel("/nonexistent/ui.sock")
    out = tmp_path / "hud.png"
    assert hud.snapshot(m, (400, 300), 0.0, str(out)) == 0
    assert out.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_the_frame_report_reads_well():
    r = hud.frame_report([1.0, 2.0, 3.0, 10.0], [0.5, 0.6, 0.7, 4.0], 20, 10.0)
    assert r.startswith("cora-hud frame times over 10 s, 20 task(s): 4 repaints (0.4/s);")
    assert "build ms median 3.00 p95 10.00 max 10.00" in r and "paint ms median 0.70 p95 4.00 max 4.00" in r


_QAPP = []                                                                # the QApplication, kept alive


def _qt():
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
    except ImportError:
        if os.environ.get("CORA_REQUIRE_QT"):
            pytest.fail("CORA_REQUIRE_QT is set but PySide6 is not importable")
        pytest.skip("PySide6 is not installed")
    if not _QAPP:
        _QAPP.append(QApplication.instance() or QApplication([]))


def qt_px(img, x, y):
    return "#%06x" % (img.pixel(x, y) & 0xFFFFFF)


def test_qt_paints_the_status_colour_the_gap_as_background_and_the_hatching():
    _qt()
    r = Rig()
    end = steady(r, 21, step=2.0)                                          # coarse: a 2 s heartbeat on a 1 s window
    steady(r, 11, step=2.0, seq0=40, mono0=end + 12.0)                    # a 12 s hole
    s = r.scene()
    img = hud.render_qt_image(s)
    assert qt_px(img, W - 5, 10) == s.header_colour
    p = only(s)
    a, b = next(g for g in p.gaps if g[1] < p.plot[0] + p.plot[2] - 2)
    _, y0, _, h = p.plot
    for x in range(a + 2, b - 1):
        assert {qt_px(img, x, y) for y in range(y0 + 1, y0 + h - 1)} == {PLOT_BG}, x
    ca, cb = p.coarse[0]
    hatch = {qt_px(img, x, y) for x in range(ca, cb) for y in range(y0 + 20, y0 + h - 20)}
    assert hud.INK["hatch"] in hatch and PLOT_BG in hatch
    distinct = {qt_px(img, x, y) for x in range(0, W, 9) for y in range(0, H, 9)}
    assert len(distinct) >= 5


def test_qt_offscreen_snapshot_of_every_scenario_is_not_blank(tmp_path):
    _qt()
    for name in replay.SCENARIOS:
        img = hud.render_qt_image(play(name).scene())
        assert len({qt_px(img, x, y) for x in range(0, W, 13) for y in range(0, H, 11)}) >= 4, name


def test_a_fixture_replayed_over_a_real_socket_shows_the_replay_banner(tmp_path):
    import threading
    import time
    path = str(tmp_path / "ui.sock")
    srv = replay.ReplayServer(path, None, source="fixture:psiw_trip")
    srv.start()
    m = hud.HudModel(path)
    try:
        m.tick()                                                          # connects
        assert m.client.sock is not None
        th = threading.Thread(target=replay.run, args=(srv, replay.log_frames(replay.fixture_path("psiw_trip"))),
                              kwargs={"sleep": lambda d: time.sleep(0.002)})
        th.start()
        end = time.monotonic() + 5
        while (th.is_alive() or m._frames < 33) and time.monotonic() < end:
            m.tick()
            time.sleep(0.002)
        th.join()
        s = m.scene(W, H)
        assert m._frames == 33
        assert s.banners[0] == "REPLAY — not the live daemon (fixture:psiw_trip)"
        assert s.banners[1].startswith("NON-DEFAULT SOCKET: ")
        assert any(p.name.startswith("psiw-") and p.badge for p in s.panels)
    finally:
        m.client.close()
        srv.stop()



# ================================================================ severity first: the worst rows are never below the fold
def _named(i, **kw):
    return task(cid=100 + i, name=f"t{i:02d}-{i:06x}", **kw)


def test_an_alarmed_task_is_row_one_even_when_it_is_listed_last():
    tasks = [_named(i) for i in range(1, 15)] + [_named(15)]
    tasks[-1]["alarm"] = "action failed: failed:FirewallError@cgroup:t15-00000f"
    r = Rig()
    r.feed(base(1, 100.0, tasks, status="alarm"))
    for height in (H, 300, 220):
        s = r.scene(W, height)
        assert s.panels[0].name == "t15-00000f", height
        assert s.hidden == 15 - len(s.panels)
    s = r.scene(W, 300)
    assert s.footer == f"+{s.hidden} more tasks (worst: clear on {sorted(t['name'] for t in tasks[:14])[len(s.panels) - 1]})"


def test_rows_go_by_the_clients_per_task_status_then_name():
    tasks = [_named(1), _named(2, count=1, active=True), _named(3, enforced=["ISOLATE"]), _named(4, psi_state="refused"),
             _named(5, limits={"source": "unknown", "cpu_max": None, "memory_high": None, "memory_max": None}), _named(6)]
    tasks[5]["alarm"] = "action failed: x"
    r = Rig()
    r.feed(base(1, 100.0, tasks, status="alarm"))
    s = r.scene(W, 2000)
    states = {t["name"]: t["status"] for t in r.m.view["tasks"]}
    assert [states[p.name] for p in s.panels] == ["alarm", "blind", "contained", "psi_refused", "pressure", "clear"]
    s = r.scene(W, 260)
    assert s.panels[0].name == "t06-000006"
    hidden_worst = [p.name for p in r.scene(W, 2000).panels][len(s.panels)]
    assert s.footer.startswith(f"+{s.hidden} more task") and f"worst: {states[hidden_worst]} on {hidden_worst}" in s.footer


def test_a_task_gone_from_the_feed_sorts_after_live_ones():
    r = play("relaunch_new_cgroup")
    assert [p.cgroup_id for p in r.scene().panels] == [214, 101]


# ================================================================ a breaker the daemon never answers
def test_an_unanswered_breaker_times_out_and_says_so_on_its_row():
    r = Rig()
    r.feed(base(1, 100.0, [task()]))
    tag = r.m.press("cap", "game-1a2b3c", 7)
    assert tag and not any("timed out" in t for t in texts(r.scene()))
    r.wait(uiclient.ACK_TIMEOUT_S + 0.1)
    r.feed(base(2, 105.0, [task()]))
    s = r.scene()
    assert "cap: timed out (unconfirmed)" in texts(s)
    assert r.m.view["status"] == "unknown" and "COMMAND_TIMEOUT: cap on game-1a2b3c" in r.m.view["detail"]


# ================================================================ window size, and the dialog's [X]
def test_fit_height_shows_twenty_tasks_without_hiding_any():
    r = Rig("/tmp/x/ui.sock")
    r.feed(base(1, 100.0, [_named(i) for i in range(1, 21)]))
    exact = hud.fit_height(20, banners=1, notice=False)
    s = r.scene(800, exact)
    assert s.hidden == 0 and len(s.panels) == 20 and len(s.banners) == 1
    assert r.scene(800, exact - 1).hidden > 0                             # the exact fit: one pixel less hides a row
    assert hud.fit_height(20) == 1060 <= 1150                             # both banners and a notice line: still fits


def test_height_overrides_the_size(monkeypatch):
    got = {}
    monkeypatch.setattr(hud, "have_qt", lambda: True)
    monkeypatch.setattr(hud, "run_qt", lambda model, size, frame_times=None: got.update(size=size, ft=frame_times) or 0)
    assert hud.main(["--socket", "/nonexistent/ui.sock", "--size", "800x600", "--height", "1150", "--frame-times", "60"]) == 0
    assert got == {"size": (800, 1150), "ft": 60.0}
    with pytest.raises(SystemExit):
        hud.main(["--socket", "/nonexistent/ui.sock", "--height", "50"])


def test_closing_the_confirm_dialog_from_its_title_bar_cancels():
    _qt()
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QApplication, QDialog
    box, ok = hud.confirm_box("sever", "Cut it?", "body")
    assert box.defaultButton() is box.escapeButton() and box.defaultButton() is not ok
    box.show()
    box.close()                                                          # what the compositor's [X] asks for
    assert not hud.confirmed(box, ok) and box.result() == QDialog.Rejected and not box.isVisible()
    box, ok = hud.confirm_box("cap", "Cap it?", "body")
    box.show()
    QApplication.sendEvent(box, QKeyEvent(QEvent.KeyPress, Qt.Key_Escape, Qt.NoModifier))
    assert not hud.confirmed(box, ok) and not box.isVisible()
    box, ok = hud.confirm_box("cap", "Cap it?", "body")
    box.show()
    ok.click()
    assert hud.confirmed(box, ok)


def test_a_benchmark_window_grows_until_every_task_fits():
    r = Rig()
    r.feed(base(1, 100.0, [_named(i) for i in range(1, 21)]))
    s = r.scene(800, 640)
    assert s.hidden and hud.grow_to_fit(s) == hud.fit_height(20, 0)
    assert r.scene(800, hud.grow_to_fit(s)).hidden == 0 and hud.grow_to_fit(r.scene(800, hud.grow_to_fit(s))) is None


def test_the_real_benchmark_window_grows_to_show_all_twenty(capsys):
    _qt()
    r = Rig()
    r.feed(base(1, 100.0, [_named(i) for i in range(1, 21)]))
    assert hud.run_qt(r.m, (800, 400), frame_times=0.5) == 0            # opens too short for 20 rows
    out = capsys.readouterr().out
    assert "cora-hud frame times over 0 s, 20 task(s):" in out or "cora-hud frame times over 1 s, 20 task(s):" in out, out
