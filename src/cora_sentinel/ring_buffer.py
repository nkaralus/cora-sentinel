"""
cora_sentinel.ring_buffer - per-task history of the status feed, and the stall curves drawn from it. Stdlib only, and no
GUI: cora-tray, cora-hud and tests share it.

The daemon keeps no history (every frame is built from live kernel reads), so a client that wants curves keeps its own:

    store = RingStore()
    store.feed(frame, recv_time=client_clock())          # every state frame, in order
    store.link_lost()                                    # the socket went away: the next sample starts a new run
    store.mark_breaker(cgroup_id, "sever", "sent", client_clock())      # and "ok" / "failed" when the reply comes
    for cid, ring in store.rings.items():
        for seg in build_stall_segments(ring.samples, window_s=1.0, now_mono=store.right_edge(client_clock())):
            draw(seg.points, band=seg.band, threshold=seg.threshold, coarse=seg.coarse)
        for mark in ring.marks: ...

Rules
  * Keyed strictly by cgroup_id (an int), never by name: a name is reused by a relaunch, a cgroup id is not.
  * A ring stores Sample(mono, some_total_us, full_total_us, pids, psi_state, threshold, pressure_count): raw
    counters (None, never 0, when the frame has no psi: not measured is not 'no stall'), at most WINDOW_S (120 s) of
    daemon time and MAX_SAMPLES (2000).
  * Resets: a ring starts over when a cumulative stall counter goes DOWN or the name under that cgroup id changes;
    every ring starts over when the frame seq or the daemon's mono goes backwards; a seq already seen is ignored.
  * Gaps: a Gap marker before the next sample when the link was lost or frames are more than GAP_S (4.5 s) apart.
  * Epochs and bands: an Epoch marker whenever psi_state or the armed threshold changes for the cgroup. A curve is
    never drawn across one, and each segment carries the band of its epoch: "armed" (a threshold to draw against),
    "refused" (asked for, refused: no tripwire), "disabled" (launched with off), "unmonitored" (none configured),
    "unknown" (a feed that does not say).
  * Coarse: a point whose interval (the samples it is computed from) is at least 2 x the window (the armed
    threshold's window when there is one, else window_s) is coarse, and segments split where that changes. A coarse
    stretch may hide a short peak: it must never be read as "under threshold".
  * Marks: a "trip" mark when pressure.count rises under the same cgroup id (a count that falls resets the baseline,
    without a mark; a count already above 0 when first seen is history we did not see, also without a mark); a
    "breaker" mark when the client sends a breaker or gets its reply (mark_breaker).
  * Exited: a task with pids == 0, or missing from the frames, draws no more curve; it is kept for EXITED_HOLD_S
    (10 s of daemon time), then dropped, and a pids == 0 report after that does not bring it back.
  * Curves use the DAEMON's clock: stall fraction = d(total_us) / (d(mono) * 1e6), over the trailing window, or the
    interval back to the previous sample when no sample lies inside the window (that interval is what makes a point
    coarse). Undefined (left out, never 0) when the interval is under half the window; above 1 + ANOMALY_EPS it is a
    counter anomaly and is skipped; between 1 and 1 + eps it is clamped to 1.
  * Time axis: the right edge is last_mono + (client_now - last_recv), so a silent feed visibly falls behind.
"""
from __future__ import annotations

import collections
from typing import Deque, Dict, Iterable, List, NamedTuple, Optional, Tuple, Union

WINDOW_S = 120.0
MAX_SAMPLES = 2000
MAX_MARKS = 500
GAP_S = 4.5
EXITED_HOLD_S = 10.0
ANOMALY_EPS = 0.02
COARSE_FACTOR = 2.0
STALL_WINDOW_S = 10.0                     # cora-tray's "stall" column: the exact fraction over about this much time
PALETTE = {"green": "#2e7d32", "amber": "#f9a825", "indigo": "#3949ab", "red": "#c62828", "grey": "#757575"}
BANDS = ("armed", "refused", "disabled", "unmonitored")


# ---------------------------------------------------------------------------------------------- formatting
def human_bytes(n: Optional[int], signed: bool = False) -> str:
    if n is None:
        return "?"
    sign = ("+" if n >= 0 else "-") if signed else ("-" if n < 0 else "")
    v = float(abs(n))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if v < 1024 or unit == "GiB":
            return f"{sign}{v:.0f} {unit}" if unit == "B" else f"{sign}{v:.1f} {unit}"
        v /= 1024
    return f"{sign}{v:.1f} GiB"


def fmt_pct(v) -> str:
    return "-" if v is None else f"{v:.2f}%"


# ---------------------------------------------------------------------------------------------- the rings
Threshold = Tuple[str, int, int]          # (kind, stall_us, window_us) of an armed tripwire


class Sample(NamedTuple):
    mono: float
    some_total_us: Optional[int]
    full_total_us: Optional[int]
    pids: Optional[int]
    psi_state: str
    threshold: Optional[Threshold]
    pressure_count: Optional[int]


class Gap(NamedTuple):
    mono: float                           # where the hole ends (the daemon time of the frame after it)


class Epoch(NamedTuple):
    mono: float                           # where the new epoch starts
    psi_state: str
    threshold: Optional[Threshold]


class Mark(NamedTuple):
    mono: float
    kind: str                             # "trip" | "breaker"
    detail: str                           # "+N" trips | "sever:sent" / "cap:ok" / "sever:failed"


class Segment(NamedTuple):
    points: List[Tuple[float, float]]     # (mono, fraction), to draw as one connected line
    band: str
    threshold: Optional[Threshold]
    coarse: bool


Point = Union[Sample, Gap, Epoch]


def band_of(psi_state: Optional[str]) -> str:
    return psi_state if psi_state in BANDS else "unknown"


def threshold_key(thr) -> Optional[Threshold]:
    if not isinstance(thr, dict):
        return None
    kind, stall, window = thr.get("kind"), thr.get("stall_us"), thr.get("window_us")
    if kind in ("some", "full") and type(stall) is int and type(window) is int and window > 0:
        return (kind, stall, window)
    return None


class TaskRing:
    def __init__(self, cgroup_id: int, name: Optional[str]):
        self.cgroup_id, self.name = cgroup_id, name
        self.samples: Deque[Point] = collections.deque()
        self.marks: Deque[Mark] = collections.deque()
        self.exited_at: Optional[float] = None    # daemon mono when it was first seen exited (pids 0, or missing)
        self.resets = 0
        self._count_base: Optional[int] = None    # the pressure.count the next trip mark is measured from

    @property
    def state(self) -> str:
        return "exited" if self.exited_at is not None else "live"

    def last(self) -> Optional[Sample]:
        for p in reversed(self.samples):
            if isinstance(p, Sample):
                return p
        return None

    def epochs(self) -> List[Epoch]:
        """The epochs still in the ring, the first one included (it starts at the oldest sample)."""
        out: List[Epoch] = []
        for p in self.samples:
            if isinstance(p, Sample) and not out:
                out.append(Epoch(p.mono, p.psi_state, p.threshold))
            elif isinstance(p, Epoch):
                out.append(p)
        return out

    def reset(self) -> None:
        self.samples.clear()
        self.marks.clear()
        self._count_base = None
        self.resets += 1

    def trim(self, now_mono: float, window_s: float, max_samples: int) -> None:
        while self.samples and (self.samples[0].mono < now_mono - window_s or len(self.samples) > max_samples):
            self.samples.popleft()
        while self.samples and not isinstance(self.samples[0], Sample):
            self.samples.popleft()                # a run starts with a sample, never a hole or a boundary
        while self.marks and (self.marks[0].mono < now_mono - window_s or len(self.marks) > MAX_MARKS):
            self.marks.popleft()


class RingStore:
    def __init__(self, window_s: float = WINDOW_S, max_samples: int = MAX_SAMPLES, gap_s: float = GAP_S,
                 exited_hold_s: float = EXITED_HOLD_S):
        self.window_s, self.max_samples, self.gap_s, self.exited_hold_s = window_s, max_samples, gap_s, exited_hold_s
        self.rings: Dict[int, TaskRing] = {}
        self.last_seq: Optional[int] = None
        self.last_mono: Optional[float] = None
        self.last_recv: Optional[float] = None
        self.global_resets = 0
        self._link_gap = False
        self._dropped: set = set()                # cgroup ids dropped while still reported with pids 0

    def link_lost(self) -> None:
        """The connection dropped: whatever comes next is after a hole."""
        self._link_gap = True

    def reset_all(self) -> None:
        self.rings.clear()
        self._dropped.clear()
        self.last_seq = self.last_mono = self.last_recv = None
        self.global_resets += 1
        self._link_gap = False

    def right_edge(self, client_now: float) -> Optional[float]:
        """Daemon time 'now', as far as this client can tell: the last frame's mono, plus the client time since it."""
        if self.last_mono is None or self.last_recv is None:
            return None
        return self.last_mono + max(0.0, client_now - self.last_recv)

    def mark_breaker(self, cgroup_id: int, cmd: str, phase: str, client_now: float) -> bool:
        """A breaker the client sent ("sent") or the daemon's reply ("ok" / "failed"), on that task's timeline."""
        ring, mono = self.rings.get(cgroup_id), self.right_edge(client_now)
        if ring is None or mono is None:
            return False
        ring.marks.append(Mark(mono, "breaker", f"{cmd}:{phase}"))
        return True

    def feed(self, state: dict, recv_time: float) -> bool:
        """Take one state frame. False if it was ignored (malformed, or a seq already seen)."""
        if not isinstance(state, dict):
            return False
        seq, mono = state.get("seq"), state.get("mono")
        if type(seq) is not int or type(mono) not in (int, float):
            return False
        if self.last_seq is not None:
            if seq == self.last_seq:
                return False
            if seq < self.last_seq or mono < self.last_mono:
                self.reset_all()                  # a restarted daemon (or a replay that went back): start over
        mono = float(mono)
        gap = self._link_gap or (self.last_mono is not None and mono - self.last_mono > self.gap_s)
        self._link_gap = False
        seen, exited_now = set(), set()
        for t in state.get("tasks") or []:
            if not isinstance(t, dict):
                continue
            cid, name = t.get("cgroup_id"), t.get("name")
            if type(cid) is not int:
                continue                          # no id, no history: a name is not a key
            pids = _int(t.get("pids"))
            if cid in self._dropped:
                if pids == 0:
                    continue                      # held its 10 s already: do not bring it back
                self._dropped.discard(cid)
            ring = self.rings.get(cid)
            if ring is None or ring.name != name:
                old = ring
                ring = self.rings[cid] = TaskRing(cid, name)
                if old is not None:
                    ring.resets = old.resets + 1
            psi = t.get("psi") if isinstance(t.get("psi"), dict) else {}
            pressure = t.get("pressure") if isinstance(t.get("pressure"), dict) else {}
            state_ = t.get("psi_state") if isinstance(t.get("psi_state"), str) else "unknown"
            s = Sample(mono, _int(psi.get("some_total_us")), _int(psi.get("full_total_us")), pids,
                       state_, threshold_key(t.get("psi_threshold")) if state_ == "armed" else None,
                       _int(pressure.get("count")))
            prev = ring.last()
            if prev is not None and (_went_down(prev.some_total_us, s.some_total_us)
                                     or _went_down(prev.full_total_us, s.full_total_us)):
                ring.reset()
                prev = None
            if prev is not None:
                if gap:
                    ring.samples.append(Gap(mono))
                if (prev.psi_state, prev.threshold) != (s.psi_state, s.threshold):
                    ring.samples.append(Epoch(mono, s.psi_state, s.threshold))
            self._trip_marks(ring, s)
            if pids == 0:
                exited_now.add(cid)
                if ring.exited_at is None:
                    ring.exited_at = mono
            else:
                ring.exited_at = None
            ring.samples.append(s)
            ring.trim(mono, self.window_s, self.max_samples)
            seen.add(cid)
        for cid in list(self.rings):
            ring = self.rings[cid]
            if cid not in seen and ring.exited_at is None:
                ring.exited_at = mono
            if ring.exited_at is not None and mono - ring.exited_at > self.exited_hold_s:
                del self.rings[cid]
                if cid in exited_now:
                    self._dropped.add(cid)
        self.last_seq, self.last_mono, self.last_recv = seq, mono, float(recv_time)
        return True

    @staticmethod
    def _trip_marks(ring: TaskRing, s: Sample) -> None:
        count = s.pressure_count if s.pressure_count is not None else 0    # no pressure record: no trip yet
        if ring._count_base is None:
            ring._count_base = count              # first sight: trips before it are history we did not see
            return
        if count > ring._count_base:
            ring.marks.append(Mark(s.mono, "trip", f"+{count - ring._count_base}"))
        ring._count_base = count                  # a count that fell (the hub forgot the record) is a new baseline


def _int(v) -> Optional[int]:
    return v if type(v) is int else None


def _went_down(a: Optional[int], b: Optional[int]) -> bool:
    return a is not None and b is not None and b < a


# ---------------------------------------------------------------------------------------------- curves
def build_stall_segments(samples: Iterable[Point], window_s: float, now_mono: Optional[float] = None,
                         which: str = "some", span_s: float = WINDOW_S) -> List[Segment]:
    """Stall fraction at each sample, as Segments (points, band, threshold, coarse). Pure.

    A Gap, an Epoch, an exited sample (pids 0), a sample without the counter, an undefined point and an anomaly all
    end the current segment, and so does a change between coarse and fine: the curve shows an empty stretch there,
    never a 0. Points older than now_mono - span_s are left out."""
    if which not in ("some", "full"):
        raise ValueError(which)
    key = f"{which}_total_us"
    runs: List[List[Sample]] = [[]]
    for p in samples:
        if not isinstance(p, Sample) or p.pids == 0 or getattr(p, key) is None:
            if runs[-1]:
                runs.append([])
            continue
        runs[-1].append(p)
    segments: List[Segment] = []
    for run in runs:
        if not run:
            continue
        band, thr = band_of(run[0].psi_state), run[0].threshold
        coarse_window = thr[2] / 1e6 if thr is not None else window_s
        cur: List[Tuple[float, float]] = []
        cur_coarse = False
        j = 0
        for i, s in enumerate(run):
            while j < i and s.mono - run[j].mono > window_s:
                j += 1
            k = j if j < i else i - 1             # nothing inside the window: back to the previous sample
            frac, coarse = None, False
            if k >= 0:
                d_mono = s.mono - run[k].mono
                coarse = d_mono >= COARSE_FACTOR * coarse_window
                if d_mono >= window_s / 2:
                    f = (getattr(s, key) - getattr(run[k], key)) / (d_mono * 1e6)
                    if 0 <= f <= 1 + ANOMALY_EPS:
                        frac = min(f, 1.0)
            if frac is None or (now_mono is not None and s.mono < now_mono - span_s):
                if cur:
                    segments.append(Segment(cur, band, thr, cur_coarse))
                    cur = []
                continue
            if cur and coarse != cur_coarse:
                segments.append(Segment(cur, band, thr, cur_coarse))
                cur = []
            cur_coarse = coarse
            cur.append((s.mono, frac))
        if cur:
            segments.append(Segment(cur, band, thr, cur_coarse))
    return segments


# ---------------------------------------------------------------------------------------------- cora-tray's meter
class StallMeter:
    """Exact stall fractions from the cumulative PSI counters. Keyed by (task, cgroup id): a relaunch starts over,
    and so does a counter that went backwards (a new cgroup we were not told about). (cora-tray's table column.)"""

    def __init__(self, window: float = STALL_WINDOW_S):
        self.window = window
        self.samples: dict = {}                          # (name, cgroup_id) -> deque[(mono, some_us, full_us)]

    def feed(self, state: dict) -> None:
        mono = state.get("mono")
        seen = set()
        for t in state.get("tasks", []):
            key = (t.get("name"), t.get("cgroup_id"))
            seen.add(key)
            psi = t.get("psi") or {}
            some, full = psi.get("some_total_us"), psi.get("full_total_us")
            if mono is None or some is None:
                self.samples.pop(key, None)
                continue
            q = self.samples.setdefault(key, collections.deque())
            if q and (mono <= q[-1][0] or some < q[-1][1]):
                if mono == q[-1][0]:
                    continue                             # the same update twice
                q.clear()
            q.append((mono, some, full))
            while len(q) > 2 and mono - q[1][0] >= self.window:
                q.popleft()
        for key in list(self.samples):
            if key not in seen:
                del self.samples[key]

    def fraction(self, name, cgroup_id) -> tuple:
        """(some, full) as fractions of wall time, or (None, None) before there are two samples."""
        q = self.samples.get((name, cgroup_id))
        if not q or len(q) < 2:
            return None, None
        (m0, s0, f0), (m1, s1, f1) = q[0], q[-1]
        dt = (m1 - m0) * 1e6
        if dt <= 0:
            return None, None
        return (s1 - s0) / dt, (None if f0 is None or f1 is None else (f1 - f0) / dt)
