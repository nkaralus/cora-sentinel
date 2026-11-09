"""
cora_sentinel.ring_buffer - per-task history of the status feed, and the stall curves drawn from it. Stdlib only, and no
GUI: cora-tray, cora-hud and tests share it.

The daemon keeps no history (every frame is built from live kernel reads), so a client that wants curves keeps its own:

    store = RingStore()
    store.feed(frame, recv_time=client_clock())          # every state frame, in order
    store.link_lost()                                    # the socket went away: the next sample starts a new run
    for cid, ring in store.rings.items():
        segs = build_stall_segments(ring.samples, window_s=10.0, now_mono=store.right_edge(client_clock()))

Rules
  * Keyed strictly by cgroup_id (an int), never by name: a name is reused by a relaunch, a cgroup id is not.
  * A ring stores raw counters, Sample(mono, some_total_us, full_total_us, some_avg10, full_avg10, mem_bytes), at most
    WINDOW_S (120 s) of daemon time and MAX_SAMPLES (2000) of them.
  * A ring starts over when a cumulative stall counter goes DOWN (a new cgroup we were not told about) or when the
    task under that cgroup id has another name. Every ring starts over when the frame seq or the daemon's mono clock
    goes backwards (a restarted daemon). A frame with the seq already seen is ignored.
  * A Gap marker goes in before the next sample when the link was lost, or when daemon time between two frames
    exceeds GAP_S (4.5 s; the heartbeat is 2 s): a curve is never drawn across a hole.
  * A task missing from the frames is kept, marked exited, for EXITED_HOLD_S (10 s of daemon time), then purged.
  * Curves use the DAEMON's clock (`mono` in each frame): stall fraction = d(total_us) / (d(mono) * 1e6). A point
    whose window covers less than half of window_s is undefined and is left out (an empty stretch, never 0); a point
    above 1 + ANOMALY_EPS is a counter anomaly and is skipped; between 1 and 1 + eps it is clamped to 1.
  * Time axis: the right edge is last_mono + (client_now - last_recv), so a silent feed visibly falls behind instead
    of a frozen curve looking current.
"""
from __future__ import annotations

import collections
from typing import Deque, Dict, Iterable, List, NamedTuple, Optional, Tuple, Union

WINDOW_S = 120.0
MAX_SAMPLES = 2000
GAP_S = 4.5
EXITED_HOLD_S = 10.0
ANOMALY_EPS = 0.02
STALL_WINDOW_S = 10.0                     # cora-tray's "stall" column: the exact fraction over about this much time
PALETTE = {"green": "#2e7d32", "amber": "#f9a825", "indigo": "#3949ab", "red": "#c62828", "grey": "#757575"}


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
class Sample(NamedTuple):
    mono: float
    some_total_us: Optional[int]
    full_total_us: Optional[int]
    some_avg10: Optional[float]
    full_avg10: Optional[float]
    mem_bytes: Optional[int]


class Gap(NamedTuple):
    mono: float                           # where the hole starts (the daemon time of the frame after it)


Point = Union[Sample, Gap]
Segment = List[Tuple[float, float]]       # (mono, fraction) points to draw as one connected line


class TaskRing:
    def __init__(self, cgroup_id: int, name: Optional[str]):
        self.cgroup_id, self.name = cgroup_id, name
        self.samples: Deque[Point] = collections.deque()
        self.exited_at: Optional[float] = None    # daemon mono of the first frame without this task
        self.resets = 0

    @property
    def state(self) -> str:
        return "exited" if self.exited_at is not None else "live"

    def last(self) -> Optional[Sample]:
        for p in reversed(self.samples):
            if isinstance(p, Sample):
                return p
        return None

    def reset(self) -> None:
        self.samples.clear()
        self.resets += 1

    def trim(self, now_mono: float, window_s: float, max_samples: int) -> None:
        while self.samples and (self.samples[0].mono < now_mono - window_s or len(self.samples) > max_samples):
            self.samples.popleft()
        while self.samples and isinstance(self.samples[0], Gap):
            self.samples.popleft()                # a run cannot start with a hole


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

    def link_lost(self) -> None:
        """The connection dropped: whatever comes next is after a hole."""
        self._link_gap = True

    def reset_all(self) -> None:
        self.rings.clear()
        self.last_seq = self.last_mono = self.last_recv = None
        self.global_resets += 1
        self._link_gap = False

    def right_edge(self, client_now: float) -> Optional[float]:
        """Daemon time 'now', as far as this client can tell: the last frame's mono, plus the client time since it."""
        if self.last_mono is None or self.last_recv is None:
            return None
        return self.last_mono + max(0.0, client_now - self.last_recv)

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
        gap = self._link_gap or (self.last_mono is not None and mono - self.last_mono > self.gap_s)
        self._link_gap = False
        seen = set()
        for t in state.get("tasks") or []:
            if not isinstance(t, dict):
                continue
            cid, name = t.get("cgroup_id"), t.get("name")
            if type(cid) is not int:
                continue                          # no id, no history: a name is not a key
            ring = self.rings.get(cid)
            if ring is None or ring.name != name:
                old = ring
                ring = self.rings[cid] = TaskRing(cid, name)
                if old is not None:
                    ring.resets = old.resets + 1
            psi = t.get("psi") if isinstance(t.get("psi"), dict) else {}
            s = Sample(float(mono), _int(psi.get("some_total_us")), _int(psi.get("full_total_us")),
                       _num(psi.get("some_avg10")), _num(psi.get("full_avg10")), _int(t.get("mem_bytes")))
            prev = ring.last()
            if prev is not None and (_went_down(prev.some_total_us, s.some_total_us)
                                     or _went_down(prev.full_total_us, s.full_total_us)):
                ring.reset()
            elif gap and ring.samples:
                ring.samples.append(Gap(float(mono)))
            ring.exited_at = None
            ring.samples.append(s)
            ring.trim(float(mono), self.window_s, self.max_samples)
            seen.add(cid)
        for cid in list(self.rings):
            ring = self.rings[cid]
            if cid in seen:
                continue
            if ring.exited_at is None:
                ring.exited_at = float(mono)
            if mono - ring.exited_at > self.exited_hold_s:
                del self.rings[cid]
        self.last_seq, self.last_mono, self.last_recv = seq, float(mono), float(recv_time)
        return True


def _int(v) -> Optional[int]:
    return v if type(v) is int else None


def _num(v) -> Optional[float]:
    return float(v) if type(v) in (int, float) else None


def _went_down(a: Optional[int], b: Optional[int]) -> bool:
    return a is not None and b is not None and b < a


# ---------------------------------------------------------------------------------------------- curves
def build_stall_segments(samples: Iterable[Point], window_s: float, now_mono: Optional[float] = None,
                         which: str = "some", span_s: float = WINDOW_S) -> List[Segment]:
    """Stall fraction over a trailing window_s at each sample, as connected segments. Pure.

    A Gap, a sample without the counter, an undefined point (its window covers less than window_s / 2 of daemon time)
    and an anomaly (> 1 + ANOMALY_EPS, or negative) all end the current segment: the curve shows an empty stretch
    there, never a 0. Points older than now_mono - span_s are left out."""
    if which not in ("some", "full"):
        raise ValueError(which)
    key = f"{which}_total_us"
    runs: List[List[Sample]] = [[]]
    for p in samples:
        if isinstance(p, Gap) or getattr(p, key) is None:
            if runs[-1]:
                runs.append([])
            continue
        runs[-1].append(p)
    segments: List[Segment] = []
    for run in runs:
        cur: Segment = []
        j = 0
        for i, s in enumerate(run):
            while s.mono - run[j].mono > window_s:
                j += 1
            d_mono = s.mono - run[j].mono
            frac = None
            if d_mono >= window_s / 2:
                f = (getattr(s, key) - getattr(run[j], key)) / (d_mono * 1e6)
                if 0 <= f <= 1 + ANOMALY_EPS:
                    frac = min(f, 1.0)
            if frac is None or (now_mono is not None and s.mono < now_mono - span_s):
                if cur:
                    segments.append(cur)
                    cur = []
                continue
            cur.append((s.mono, frac))
        if cur:
            segments.append(cur)
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
