#!/usr/bin/env python3
"""
cora-hud - a desktop window over cora-sentinel's status feed: each task's memory-stall curve, the tripwire it is judged
against, its trips, and the two breakers. For desktops without a tray: it assumes there is none.

    python3 tools/cora-hud.py [--socket /run/cora-sentinel/ui.sock] [--scale sqrt|symlog]

Needs cora_sentinel importable (installed, or PYTHONPATH=src) and PySide6 (pip install "cora-sentinel[hud]", or
pip install PySide6-Essentials). Qt only: one toolkit, one set of dialogs to get right. There is no layer-shell overlay
(PySide6 has no binding for it), so it is an ordinary top-level window; on Wayland it opens through Qt's wayland
platform plugin, elsewhere through xcb.

A thin shell, like cora-tray. It decides nothing:
  * the banner text, detail line, colour, which breakers are offered and the confirmation text are
    cora_sentinel.uiclient's view(), verbatim (the HUD's colour for a status is the tray's colour for it);
  * every curve, gap, epoch, coarse span and mark comes from cora_sentinel.ring_buffer.

What it draws, per task (right edge = now, 120 s across):
  * the exact stall fraction from the cumulative counters (bright), the kernel's avg10 / avg60 (faint), on a sqrt or
    symlog scale (press s);
  * the band each stretch of history was in: armed draws its own epoch's threshold line; refused is
    "BLIND (no tripwire)"; disabled is "off"; unmonitored is "not-configured"; anything else is "unknown";
  * hatching where frames were too far apart for the tripwire's window (coarse): a coarse stretch is never drawn as a
    curve under the line, because it may hide a peak;
  * holes as plain background: a lost link, a gap in the frames, and the stretch between the last frame and now,
    which grows while the feed is silent (the right edge runs on this client's clock);
  * trip marks (+1, +3: pressure.count increments seen), breaker marks, and a "tripped <= 10 s ago" badge while
    pressure.active;
  * "history since HH:MM:SS (N s)": how far back it really goes, never a full 120 s it does not have.

Breakers: only sever and cap, only where the view offers them, always through a confirmation dialog with Cancel as
the default (Enter cancels, Escape closes); Cap names the values it will write. Nothing else is ever sent, and the HUD
runs no commands.

Banners: REPLAY, as long as this window has seen a frame stamped by tools/cora-replay.py; NON-DEFAULT SOCKET whenever
--socket is not /run/cora-sentinel/ui.sock (what is on the other end may not be cora-sentinel at all).

Repaints at most 10 times a second, and only when the picture changed: the time axis moves in whole-pixel steps of
at least 0.5 s, and a scene is rebuilt only when a frame, the view, the axis step, the size or the scale changed.

Testing aids: --snapshot FILE [--after SECONDS] reads the feed for that long, writes one frame of the window as PNG
and exits (QT_QPA_PLATFORM=offscreen runs it headless); --frame-times SECONDS opens the real window and prints how long
each scene took to build and paint, then exits.
"""
from __future__ import annotations

import argparse
import importlib.util
import math
import sys
import time
from typing import Callable, List, NamedTuple, Optional, Tuple

try:
    from cora_sentinel import ring_buffer as rb
    from cora_sentinel.ring_buffer import Epoch, Gap, RingStore, Sample, band_of, build_avg_series, build_stall_segments
    from cora_sentinel.uiclient import BREAKER_LABEL, DEFAULT_SOCKET, RANK, StatusClient, confirm_text
except ImportError:
    sys.exit("cora-hud: cannot import cora_sentinel (install it, or run with PYTHONPATH=/path/to/cora-sentinel/src)")

SPAN_S = rb.WINDOW_S                      # 120 s across
CURVE_WINDOW_S = 1.0                      # the stall fraction's trailing window (the default tripwire's)
MAX_HZ = 10
AXIS_STEP_S = 0.5                         # the time axis moves in steps of this much (and of whole pixels)
RECONNECT_S = 2.0
SYMLOG_C = 0.01
ALLOWED = ("sever", "cap")                # the only commands this window can send
LABEL_W, BUTTONS_W = 210, 150
PANEL_MIN, PANEL_MAX = 46, 150
INK = {"bg": "#0f1317", "plot": "#171c22", "text": "#e6e6e6", "dim": "#8b949e", "curve": "#4fc3f7",
       "avg10": "#5f6b76", "avg60": "#434c55", "threshold": "#ef5350", "hatch": "#a0a0a0", "trip": "#ffb300",
       "breaker": "#ce93d8", "replay": "#8e24aa", "nondefault": "#e65100", "button": "#2b3a42", "button_off": "#1b2025",
       "badge": "#ffb300"}
BAND_FILL = {"refused": "#4a1f1f", "disabled": "#2a2a2a", "unmonitored": "#22303a", "unknown": "#3b2942"}
BAND_LABEL = {"refused": "BLIND (no tripwire)", "disabled": "off", "unmonitored": "not-configured", "unknown": "unknown"}


# ---------------------------------------------------------------------------------------------- the picture, as data
class Rect(NamedTuple):
    x: int
    y: int
    w: int
    h: int
    fill: str


class Hatch(NamedTuple):
    x: int
    y: int
    w: int
    h: int
    colour: str


class Line(NamedTuple):
    pts: Tuple[Tuple[int, int], ...]
    colour: str
    width: int = 1
    dash: bool = False


class Text(NamedTuple):
    x: int
    y: int
    text: str
    colour: str
    size: int = 11
    bold: bool = False


class Button(NamedTuple):
    cmd: str
    task: str
    cgroup_id: int
    x: int
    y: int
    w: int
    h: int
    label: str
    enabled: bool


class Panel(NamedTuple):
    """What one task's row shows, in pixels: for tests, and for nothing else."""
    name: str
    cgroup_id: Optional[int]
    plot: Tuple[int, int, int, int]                       # x, y, w, h
    runs: Tuple[Tuple[int, int, str, Optional[int]], ...]  # x0, x1, band, threshold y (armed)
    curves: Tuple[Tuple[Tuple[int, int], ...], ...]
    coarse: Tuple[Tuple[int, int], ...]
    gaps: Tuple[Tuple[int, int], ...]
    marks: Tuple[Tuple[int, str, str], ...]               # x, kind, detail
    badge: Optional[str]
    exited: bool
    buttons: Tuple[Button, ...]


class Scene(NamedTuple):
    width: int
    height: int
    items: Tuple[object, ...]
    banners: Tuple[str, ...]
    header_colour: str
    history: str
    panels: Tuple[Panel, ...]
    buttons: Tuple[Button, ...]
    hidden: int
    footer: Optional[str] = None


def axis_step(width: int) -> float:
    """How far the right edge moves at a time: whole pixels, and at least AXIS_STEP_S (an idle window repaints about
    twice a second, not at every pixel)."""
    pw = max(40, width - LABEL_W - BUTTONS_W - 8)
    px_s = SPAN_S / pw
    return math.ceil(AXIS_STEP_S / px_s) * px_s


def scale_value(v: float, mode: str = "sqrt") -> float:
    v = min(max(v, 0.0), 1.0)
    if mode == "symlog":
        return math.log1p(v / SYMLOG_C) / math.log1p(1.0 / SYMLOG_C)
    return math.sqrt(v)


def history_label(store: RingStore, right: Optional[float], wall_now: float) -> str:
    firsts = [r.samples[0].mono for r in store.rings.values() if r.samples]    # a run always starts with a sample
    if right is None or not firsts:
        return "history: none yet"
    secs = min(max(right - min(firsts), 0.0), SPAN_S)
    return f"history since {time.strftime('%H:%M:%S', time.localtime(wall_now - secs))} ({secs:.0f} s)"


def _runs(ring) -> List[List[Sample]]:
    """Stretches of samples with no hole, no epoch boundary and no exit inside: what a band or a threshold spans."""
    out, cur = [], []
    for p in ring.samples:
        if isinstance(p, (Gap, Epoch)) or (isinstance(p, Sample) and p.pids == 0):
            if cur:
                out.append(cur)
            cur = []
            continue
        cur.append(p)
    if cur:
        out.append(cur)
    return out


def _holes(ring, right: float, step: float = 0.0) -> List[Tuple[float, float]]:
    """Daemon-time spans with nothing known: a Gap (back to the sample before it), and the last sample to now once
    that is more than one axis step (less is only the rounding of "now")."""
    out, prev = [], None
    for p in ring.samples:
        if isinstance(p, Sample):
            prev = p.mono
        elif isinstance(p, Gap) and prev is not None:
            out.append((prev, p.mono))
    last = ring.last()
    if last is not None and right - last.mono > step:
        out.append((last.mono, right))
    return out


def build_scene(view: dict, store: RingStore, client_now: float, wall_now: float, width: int, height: int,
                scale: str = "sqrt", socket_path: str = DEFAULT_SOCKET, replay: Optional[str] = None,
                notice: Optional[str] = None) -> Scene:
    """The whole window as drawing primitives. Pure: same inputs, same picture."""
    items: List[object] = []
    banners: List[str] = []
    y = 0
    if replay:
        banners.append(f"REPLAY — not the live daemon ({replay})")
    if socket_path != DEFAULT_SOCKET:
        banners.append(f"NON-DEFAULT SOCKET: {socket_path} — this may not be cora-sentinel")
    for b in banners:
        items += [Rect(0, y, width, 24, INK["replay"] if b.startswith("REPLAY") else INK["nondefault"]),
                  Text(8, y + 5, b, INK["text"], 12, True)]
        y += 24
    header = rb.PALETTE[view["colour"]]
    items += [Rect(0, y, width, 30, header), Text(8, y + 7, view["title"], "#ffffff", 13, True)]
    y += 30
    chars = max(10, width // 7)
    items.append(Text(8, y + 3, view["detail"][:chars], INK["text"], 11))
    y += 20
    if notice:
        items.append(Text(8, y + 2, notice[:chars], INK["dim"], 10))
        y += 18
    right = store.right_edge(client_now)
    hist = history_label(store, right, wall_now)
    items += [Text(8, y + 2, hist, INK["dim"], 10),
              Text(max(8, width - 260), y + 2, f"scale: {scale} (s toggles)", INK["dim"], 10)]
    y += 20

    vtasks = [t for t in view.get("tasks") or [] if isinstance(t, dict)]
    entries = [(t["name"], t.get("cgroup_id"), t, store.rings.get(t.get("cgroup_id"))) for t in vtasks]
    seen = {t.get("cgroup_id") for t in vtasks}
    entries += [(r.name, cid, None, r) for cid, r in store.rings.items() if cid not in seen]
    entries.sort(key=severity_key)                    # the worst rows first: never below the fold
    avail = height - y - 4
    n = len(entries)
    ph = max(PANEL_MIN, min(PANEL_MAX, avail // n)) if n else 0
    fit = n if not n or ph * n <= avail else max(1, (avail - 16) // ph)
    shown, hidden = entries[:fit], n - fit
    pw = max(40, width - LABEL_W - BUTTONS_W - 8)
    px_s = SPAN_S / pw
    # in axis steps, so an idle feed does not repaint every tick; rounded up, so no sample is ever right of "now"
    step = axis_step(width)
    right_q = math.ceil(right / step) * step if right is not None else None
    panels, buttons = [], []
    for name, cid, vt, ring in shown:
        top = y
        x0, y0, h = LABEL_W, top + 2, ph - 6
        bottom = y0 + h - 2

        def X(m: float) -> int:
            return int(round(x0 + pw - (right_q - m) / px_s))

        def Y(v: float) -> int:
            return int(round(bottom - scale_value(v, scale) * (h - 4)))

        def clip(a: int, b: int) -> Tuple[int, int]:
            return max(a, x0), min(b, x0 + pw)
        exited = (ring is not None and ring.state == "exited") or (vt is not None and vt["line"].endswith("— exited"))
        items += [Text(8, top + 4, name or "?", INK["text"], 12, True)]
        if vt is not None:
            items.append(Text(8, top + 21, vt["line"][len(name or ""):][:LABEL_W // 6].lstrip(": "), INK["dim"], 10))
        else:
            items.append(Text(8, top + 21, "no longer in the feed", INK["dim"], 10))
        if exited:
            items.append(Text(8, top + 35, "exited", INK["dim"], 10, True))
        if vt is not None and vt.get("pending"):
            items.append(Text(8, top + 35 + 12 * exited, f"{vt.get('pending_cmd')}: timed out (unconfirmed)",
                              rb.PALETTE["red"], 10, True))
        items.append(Rect(x0, y0, pw, h, INK["plot"]))
        runs, curves, coarse, gaps, marks = [], [], [], [], []
        badge = None
        if ring is not None and right_q is not None:
            for run in _runs(ring):
                band, thr = band_of(run[0].psi_state), run[0].threshold
                a, b = clip(X(run[0].mono), X(run[-1].mono))
                if b < a:
                    continue
                ty = Y(thr[1] / thr[2]) if band == "armed" and thr is not None else None
                runs.append((a, b, band, ty))
                if band != "armed":
                    items.append(Rect(a, y0, max(b - a, 1), h, BAND_FILL[band]))
            segs = build_stall_segments(ring.samples, CURVE_WINDOW_S, now_mono=right_q, span_s=SPAN_S)
            samples = [p for p in ring.samples if isinstance(p, Sample)]
            for seg in segs:
                if not seg.coarse:
                    continue
                first = seg.points[0][0]
                before = [s.mono for s in samples if s.mono < first]
                start = before[-1] if before and not _hole_between(ring, before[-1], first) else first
                a, b = clip(X(start), X(seg.points[-1][0]))
                if b > a:
                    coarse.append((a, b))
                    items.append(Hatch(a, y0, b - a, h, INK["hatch"]))
            for key, ink, dash in (("some_avg60", "avg60", True), ("some_avg10", "avg10", False)):
                for series in build_avg_series(ring.samples, key, now_mono=right_q, span_s=SPAN_S):
                    pts = tuple((X(m), Y(v)) for m, v in series if X(m) >= x0)
                    if len(pts) > 1:
                        items.append(Line(pts, INK[ink], 1, dash))
            for a, b, band, ty in runs:
                if ty is not None:
                    items.append(Line(((a, ty), (b, ty)), INK["threshold"], 1, True))
            for seg in segs:
                if seg.coarse:
                    continue                      # never a line under the threshold where a peak may hide
                pts = tuple((X(m), Y(v)) for m, v in seg.points if X(m) >= x0)
                if len(pts) == 1:                         # one point: a short dash back over its interval
                    pts = ((max(pts[0][0] - 2, x0), pts[0][1]), pts[0])
                if pts:
                    curves.append(pts)
                    items.append(Line(pts, INK["curve"], 2))
            for a, b in _holes(ring, right_q, step):
                a, b = clip(X(a), X(b))
                if b > a + 1:
                    gaps.append((a + 1, b - 1))
            label_x = -10**9
            for m in ring.marks:
                mx = X(m.mono)
                if not x0 <= mx <= x0 + pw:
                    continue
                marks.append((mx, m.kind, m.detail))
                if m.kind == "trip":
                    items.append(Line(((mx, y0), (mx, y0 + 9)), INK["trip"], 2))
                    if mx - label_x >= 16:              # every tick is drawn; labels only where they fit
                        items.append(Text(mx + 2, y0 + 1, m.detail, INK["trip"], 9))
                        label_x = mx
                else:
                    items += [Line(((mx, y0), (mx, bottom)), INK["breaker"], 1, True),
                              Text(mx + 2, bottom - 12, m.detail, INK["breaker"], 9)]
            if ring.pressure_active:
                badge = "tripped ≤ 10 s ago"
        latest = runs[-1][2] if runs else ((vt or {}).get("psi_state") or "unknown")
        if latest != "armed":
            items.append(Text(x0 + pw - 150, y0 + 2, BAND_LABEL.get(latest, "unknown"), INK["text"], 10, True))
        elif not curves and not coarse:
            items.append(Text(x0 + 6, y0 + 2, "waiting for data", INK["dim"], 10))
        if badge:
            items.append(Text(x0 + pw - 150, y0 + h - 16, badge, INK["badge"], 11, True))
        mine = []
        if vt is not None and type(cid) is int:
            for i, cmd in enumerate(ALLOWED):
                mine.append(Button(cmd, name, cid, width - BUTTONS_W + 4, top + 4 + 25 * i, BUTTONS_W - 12, 22,
                                   BREAKER_LABEL[cmd], vt[f"can_{cmd}"] is True))
        items += mine
        buttons += mine
        panels.append(Panel(name, cid, (x0, y0, pw, h), tuple(runs), tuple(curves), tuple(coarse), tuple(gaps),
                            tuple(marks), badge, exited, tuple(mine)))
        y += ph
    footer = None
    if hidden:
        name, _, vt, _ = max(entries[fit:], key=lambda e: RANK.get(task_state(e[2]), 0))
        footer = f"+{hidden} more task{'s' * (hidden > 1)} (worst: {task_state(vt)} on {name})"
        worst_ink = rb.PALETTE[uiclient_colour(task_state(vt))]
        items.append(Text(8, y + 2, footer, worst_ink if task_state(vt) != "clear" else INK["dim"], 10, True))
    if not entries and view["status"] not in ("unreachable", "connecting"):
        items.append(Text(8, y + 4, "no sandboxed tasks running", INK["dim"], 11))
    return Scene(width, height, tuple(items), tuple(banners), header, hist, tuple(panels), tuple(buttons), hidden, footer)


def task_state(vt: Optional[dict]) -> str:
    """The client's own per-task status (uiclient.task_status); a ring no longer in the feed has none: "gone"."""
    return vt.get("status", "clear") if vt is not None else "gone"


def severity_key(entry) -> tuple:
    name, _, vt, _ = entry
    return (-RANK.get(task_state(vt), 0), vt is None, name or "")


def uiclient_colour(state: str) -> str:
    from cora_sentinel.uiclient import COLOURS
    return COLOURS.get(state, "grey")


def fit_height(n_tasks: int, banners: int = 2, notice: bool = True) -> int:
    """The window height that shows n tasks without hiding any (each row at its smallest)."""
    top = 24 * banners + 30 + 20 + 18 * notice + 20
    return top + 4 + n_tasks * PANEL_MIN


def grow_to_fit(scene: Scene) -> Optional[int]:
    """The height a benchmark window (--frame-times) must grow to so no task is hidden, or None if none is."""
    if not scene.hidden:
        return None
    return max(scene.height + 1, fit_height(len(scene.panels) + scene.hidden, len(scene.banners)))


def _hole_between(ring, a: float, b: float) -> bool:
    return any(isinstance(p, (Gap, Epoch)) and a < p.mono <= b for p in ring.samples)


def hit(scene: Scene, x: float, y: float) -> Optional[Button]:
    for b in scene.buttons:
        if b.x <= x < b.x + b.w and b.y <= y < b.y + b.h:
            return b
    return None


# ---------------------------------------------------------------------------------------------- the model (no GUI)
class HudModel:
    """The client, the ring buffer, and what a press is allowed to do. A GUI calls tick() up to MAX_HZ times a second
    and draws scene()."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time, scale: str = "sqrt", client: Optional[StatusClient] = None):
        self.socket_path, self.clock, self.wall, self.scale = socket_path, clock, wall, scale
        self.client = client or StatusClient(socket_path, clock=clock)
        self.store = RingStore()
        self.client.on_state = self._on_state
        self._frames = 0
        self._cache: Optional[tuple] = None          # (key, view, scene) of the last scene built
        self.replay: Optional[str] = None        # latched: once a replay, always flagged in this window
        self.pending: dict = {}                  # tag -> (cmd, task, cgroup_id)
        self.notice: Optional[str] = None
        self.view = self.client.view()
        self._next_try = 0.0
        self._linked = False

    def _on_state(self, frame: dict) -> None:
        self.store.feed(frame, self.clock())
        self._frames += 1

    def tick(self) -> None:
        now = self.clock()
        if self.client.sock is None:
            if self._linked:
                self.store.link_lost()
                self._linked = False
            if now >= self._next_try:
                self._next_try = now + RECONNECT_S
                self._linked = self.client.connect()
        if self.client.sock is not None:
            self.client.poll()
        for tag, (cmd, task, cid) in list(self.pending.items()):
            r = self.client.results.get(tag)
            if r is None:
                continue
            ok = r.get("ok") is True
            self.store.mark_breaker(cid, cmd, "ok" if ok else "failed", now)
            self.notice = f"{cmd} on {task}: " + (str(r.get("action", "done")) if ok else f"refused: {r.get('error')}")
            del self.pending[tag]
        self.view = self.client.view()
        if self.view.get("replay"):
            self.replay = self.view["replay"]

    def scene(self, width: int, height: int) -> Scene:
        """build_scene(), reused while nothing it draws can have changed: no frame, the same view, the same axis step."""
        right = self.store.right_edge(self.clock())
        key = (self._frames, None if right is None else math.ceil(right / axis_step(width)), width, height, self.scale,
               self.replay, self.notice)
        if self._cache is not None and self._cache[0] == key and self._cache[1] == self.view:
            return self._cache[2]
        scene = build_scene(self.view, self.store, self.clock(), self.wall(), width, height, self.scale,
                            self.socket_path, self.replay, self.notice)
        self._cache = (key, self.view, scene)
        return scene

    def toggle_scale(self) -> None:
        self.scale = "symlog" if self.scale == "sqrt" else "sqrt"

    def _task(self, task: str, cgroup_id) -> Optional[dict]:
        return next((t for t in self.view.get("tasks") or [] if t["name"] == task and t["cgroup_id"] == cgroup_id), None)

    def eligible(self, cmd: str, task: str, cgroup_id) -> bool:
        t = self._task(task, cgroup_id)
        return cmd in ALLOWED and t is not None and t.get(f"can_{cmd}") is True

    def confirm(self, cmd: str, task: str, cgroup_id) -> Tuple[str, str]:
        return confirm_text(cmd, task, (self._task(task, cgroup_id) or {}).get("mem_bytes"))

    def press(self, cmd: str, task: str, cgroup_id) -> Optional[str]:
        """Send one breaker, after the dialog said yes. Refused here too unless the view offers it right now."""
        if not self.eligible(cmd, task, cgroup_id):
            self.notice = f"{cmd} on {task}: not offered right now"
            return None
        tag = self.client.send(cmd, task, cgroup_id)
        if tag is None:
            self.notice = f"{cmd} on {task}: could not send ({self.client.error})"
            return None
        self.pending[tag] = (cmd, task, cgroup_id)
        self.store.mark_breaker(cgroup_id, cmd, "sent", self.clock())
        self.notice = f"{cmd} on {task}: sent, waiting for cora-sentinel"
        return tag


# ---------------------------------------------------------------------------------------------- a pixel raster (tests)
def _rgb(c: str) -> bytes:
    return bytes(int(c[i:i + 2], 16) for i in (1, 3, 5))


class Raster:
    """The scene in pixels without any GUI library: rectangles, hatching, lines, and text as solid blocks. What the
    pixel tests read where Qt is not installed; never shown to anyone."""

    def __init__(self, scene: Scene):
        self.w, self.h = scene.width, scene.height
        self.buf = bytearray(_rgb(INK["bg"]) * (self.w * self.h))
        for it in scene.items:
            if isinstance(it, Rect):
                self.fill(it.x, it.y, it.w, it.h, _rgb(it.fill))
            elif isinstance(it, Hatch):
                c = _rgb(it.colour)
                for yy in range(max(it.y, 0), min(it.y + it.h, self.h)):
                    for xx in range(max(it.x, 0), min(it.x + it.w, self.w)):
                        if (xx + yy) % 6 == 0:
                            self.set(xx, yy, c)
            elif isinstance(it, Line):
                c = _rgb(it.colour)
                n = 0
                for (ax, ay), (bx, by) in zip(it.pts, it.pts[1:]):
                    for xx, yy in _bresenham(ax, ay, bx, by):
                        n += 1
                        if it.dash and (n // 4) % 2:
                            continue
                        for k in range(it.width):
                            self.set(xx, yy + k, c)
            elif isinstance(it, Text):
                self.fill(it.x, it.y + 2, min(len(it.text) * 6, self.w), max(it.size - 4, 2), _rgb(it.colour))
            elif isinstance(it, Button):
                self.fill(it.x, it.y, it.w, it.h, _rgb(INK["button"] if it.enabled else INK["button_off"]))
                self.fill(it.x + 6, it.y + 8, min(len(it.label) * 6, it.w - 12), 6,
                          _rgb(INK["text"] if it.enabled else INK["dim"]))

    def fill(self, x: int, y: int, w: int, h: int, c: bytes) -> None:
        x0, x1 = max(x, 0), min(x + w, self.w)
        if x1 <= x0:
            return
        for yy in range(max(y, 0), min(y + h, self.h)):
            i = (yy * self.w + x0) * 3
            self.buf[i:i + (x1 - x0) * 3] = c * (x1 - x0)

    def set(self, x: int, y: int, c: bytes) -> None:
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 3
            self.buf[i:i + 3] = c

    def px(self, x: int, y: int) -> str:
        i = (y * self.w + x) * 3
        return "#%02x%02x%02x" % tuple(self.buf[i:i + 3])


def _bresenham(x0: int, y0: int, x1: int, y1: int):
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
    err = dx + dy
    while True:
        yield x0, y0
        if x0 == x1 and y0 == y1:
            return
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy


# ---------------------------------------------------------------------------------------------- Qt
def paint_qt(scene: Scene, painter) -> None:
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import QBrush, QColor, QPen, QPolygonF
    painter.fillRect(QRectF(0, 0, scene.width, scene.height), QColor(INK["bg"]))
    for it in scene.items:
        if isinstance(it, Rect):
            painter.fillRect(QRectF(it.x, it.y, it.w, it.h), QColor(it.fill))
        elif isinstance(it, Hatch):
            painter.fillRect(QRectF(it.x, it.y, it.w, it.h), QBrush(QColor(it.colour), Qt.BDiagPattern))
        elif isinstance(it, Line):
            pen = QPen(QColor(it.colour))
            pen.setWidth(it.width)
            if it.dash:
                pen.setStyle(Qt.DashLine)
            painter.setPen(pen)
            painter.drawPolyline(QPolygonF([QPointF(x, y) for x, y in it.pts]))
        elif isinstance(it, Text):
            f = painter.font()
            f.setPixelSize(it.size)
            f.setBold(it.bold)
            painter.setFont(f)
            painter.setPen(QColor(it.colour))
            painter.drawText(QPointF(it.x, it.y + it.size), it.text)
        elif isinstance(it, Button):
            painter.fillRect(QRectF(it.x, it.y, it.w, it.h), QColor(INK["button"] if it.enabled else INK["button_off"]))
            painter.setPen(QColor(INK["text"] if it.enabled else INK["dim"]))
            painter.drawText(QRectF(it.x, it.y, it.w, it.h), int(Qt.AlignCenter), it.label)


def render_qt_image(scene: Scene):
    from PySide6.QtGui import QImage, QPainter
    img = QImage(scene.width, scene.height, QImage.Format_RGB32)
    p = QPainter(img)
    paint_qt(scene, p)
    p.end()
    return img


def frame_report(build_ms: List[float], paint_ms: List[float], tasks: int, seconds: float) -> str:
    def q(v: List[float], f: float) -> float:
        return sorted(v)[min(len(v) - 1, int(f * len(v)))] if v else float("nan")
    return (f"cora-hud frame times over {seconds:.0f} s, {tasks} task(s): {len(paint_ms)} repaints "
            f"({len(paint_ms) / seconds:.1f}/s); build ms median {q(build_ms, .5):.2f} p95 {q(build_ms, .95):.2f} "
            f"max {max(build_ms, default=float('nan')):.2f}; paint ms median {q(paint_ms, .5):.2f} "
            f"p95 {q(paint_ms, .95):.2f} max {max(paint_ms, default=float('nan')):.2f}")


def confirm_box(cmd: str, head: str, body: str, parent=None):
    """(dialog, its confirm button). Cancel is the default (Enter cancels) and the escape button; closing the window
    from the title bar ([X], on Wayland drawn by the compositor) rejects exactly as Escape does."""
    from PySide6.QtWidgets import QMessageBox

    class ConfirmBox(QMessageBox):
        def closeEvent(self, e):
            self.reject()
            e.accept()

    box = ConfirmBox(QMessageBox.Warning, "cora-hud", head, parent=parent)
    box.setInformativeText(body)
    cancel = box.addButton(QMessageBox.Cancel)
    ok = box.addButton({"sever": "Sever network", "cap": "Cap memory"}[cmd], QMessageBox.DestructiveRole)
    box.setDefaultButton(cancel)                     # Enter must not sever by accident
    box.setEscapeButton(cancel)
    return box, ok


def confirmed(box, ok) -> bool:
    """Only a click on the confirm button confirms: Cancel, Escape, Enter (Cancel is the default) and [X] do not."""
    return box.clickedButton() is ok


def run_qt(model: HudModel, size: Tuple[int, int], frame_times: Optional[float] = None) -> int:
    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QPainter
    from PySide6.QtWidgets import QApplication, QWidget

    class Window(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("cora-hud")
            self.resize(*size)
            self.scene_ = model.scene(*size)
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.tick)
            self.timer.start(1000 // MAX_HZ)

        def tick(self):
            model.tick()
            if frame_times:                              # a benchmark window shows every task: grow until none is hidden
                h = grow_to_fit(model.scene(self.width(), self.height()))
                if h is not None:
                    self.resize(self.width(), h)
            t0 = time.perf_counter()
            s = model.scene(self.width(), self.height())
            if s != self.scene_:
                build_ms.append((time.perf_counter() - t0) * 1e3)
                self.scene_ = s
                self.update()

        def paintEvent(self, e):
            t0 = time.perf_counter()
            p = QPainter(self)
            paint_qt(self.scene_, p)
            p.end()
            paint_ms.append((time.perf_counter() - t0) * 1e3)

        def keyPressEvent(self, e):
            if e.text() == "s":
                model.toggle_scale()

        def mousePressEvent(self, e):
            b = hit(self.scene_, e.position().x(), e.position().y())
            if b is None or not b.enabled:
                return
            head, body = model.confirm(b.cmd, b.task, b.cgroup_id)
            box, ok = confirm_box(b.cmd, head, body, self)
            box.exec()
            if confirmed(box, ok):
                model.press(b.cmd, b.task, b.cgroup_id)

    build_ms: List[float] = []
    paint_ms: List[float] = []
    app = QApplication.instance() or QApplication(sys.argv[:1])
    w = Window()
    w.show()
    if frame_times:
        def report():
            print(frame_report(build_ms, paint_ms, len(w.scene_.panels), frame_times), flush=True)
            app.quit()
        QTimer.singleShot(int(frame_times * 1000), report)
    return app.exec()


# ---------------------------------------------------------------------------------------------- main
def have_qt() -> bool:
    try:
        return importlib.util.find_spec("PySide6") is not None and importlib.util.find_spec("PySide6.QtWidgets") is not None
    except ImportError:
        return False


_APP = None                                       # the offscreen QApplication --snapshot needs, kept alive


def snapshot(model: HudModel, size: Tuple[int, int], after: float, path: str) -> int:
    end = time.monotonic() + after
    while time.monotonic() < end:
        model.tick()
        time.sleep(1.0 / MAX_HZ)
    model.tick()
    scene = model.scene(*size)
    from PySide6.QtWidgets import QApplication
    global _APP
    _APP = QApplication.instance() or QApplication(sys.argv[:1])
    if not render_qt_image(scene).save(path):
        sys.exit(f"cora-hud: could not write {path}")
    print(f"cora-hud: {model.view['title']} | {len(scene.panels)} task(s) | {scene.history}"
          + "".join(f" | {b}" for b in scene.banners) + f" -> {path}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cora-hud", description="memory-stall curves and breakers for cora-sentinel")
    ap.add_argument("--socket", default=DEFAULT_SOCKET)
    ap.add_argument("--scale", choices=("sqrt", "symlog"), default="sqrt")
    ap.add_argument("--size", default="960x640", help="WIDTHxHEIGHT")
    ap.add_argument("--height", type=int, default=None, help="the window height (overrides --size's); with "
                    "--frame-times the window also grows by itself until every task fits")
    ap.add_argument("--snapshot", metavar="FILE", help="write one frame of the window after --after seconds, and exit")
    ap.add_argument("--after", type=float, default=5.0)
    ap.add_argument("--frame-times", type=float, metavar="SECONDS", default=None,
                    help="open the window, print build and paint times per scene for SECONDS, then exit")
    a = ap.parse_args(argv)
    try:
        size = tuple(int(v) for v in a.size.lower().split("x"))
        assert len(size) == 2 and min(size) >= 200
    except (ValueError, AssertionError):
        ap.error("--size must be WIDTHxHEIGHT, each at least 200")
    if a.height is not None:
        if a.height < 200:
            ap.error("--height must be at least 200")
        size = (size[0], a.height)
    if not have_qt():
        sys.exit('cora-hud: needs PySide6: pip install "cora-sentinel[hud]" (or pip install PySide6-Essentials)')
    model = HudModel(a.socket, scale=a.scale)
    if a.snapshot:
        return snapshot(model, size, a.after, a.snapshot)
    return run_qt(model, size, frame_times=a.frame_times)


if __name__ == "__main__":
    sys.exit(main())
