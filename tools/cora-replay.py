#!/usr/bin/env python3
"""
cora-replay - a stand-in cora-sentinel status feed, for driving cora-tray and cora-hud without a daemon, a kernel or
root. Stdlib only (and cora_sentinel itself).

    cora-replay file PATH [--speed 1.0] [--loop] [--socket PATH]
    cora-replay scenario NAME [--speed 1.0] [--loop] [--socket PATH]
    cora-replay fixture NAME [--speed 1.0] [--loop] [--socket PATH]
    cora-replay sanitize CAPTURE OUT --keep PREFIX [--keep PREFIX ...] [--seq FIRST:LAST]
    cora-replay list

  file       replays a recorded feed: raw newline-delimited JSON, or capture lines "<iso time> {json}" (what the live
             checks under cora_scratch recorded). Timing follows the frames' daemon clock (mono), else the capture
             times, scaled by --speed. Within one pass seq and mono are kept as recorded (a daemon restart in the log
             replays as one); with --loop each new pass is shifted forward so the wrap is not mistaken for a restart.
  fixture    replays a sanitized real capture shipped in tools/replay-fixtures/ (NAME.ndjson): psiw_trip (a live
             tripwire trip on Dimgeon) and psir_refused_healed (a refused tripwire across a daemon restart, re-armed by
             the retry without one).
  sanitize   makes such a fixture from a capture: only the tasks whose names start with a --keep prefix, session
             counters zeroed (they are the host's blocklist history), ts rebased to 2026-01-01 on the daemon clock.
  scenario   generates a feed. Frames come from the REAL Hub.snapshot() over a scripted world (tasks, tripwires, the
             scope registry), so every field, status and precedence rule is what the daemon would send; only mono,
             ts and seq come from the scenario's virtual clock (so --speed compresses time without changing it).

The socket speaks the daemon's contract: each client gets the latest frame at once, then every frame; a client may
send {"cmd": "sever"|"cap", "task", "cgroup_id", "id"} and gets {"type": "result", "id", "ok", ...} with the hub's
refusals word for word (unknown command, one command per second, no such task, not the task you saw). An accepted
breaker shows up in force in the next frame, except in the ack_not_reflected scenario, which acknowledges and
changes nothing (cora_sentinel.uiclient then raises ACK_NOT_REFLECTED).

Every frame sent carries "replay": {"source": "<mode>:<name>"}, so a client can say loudly that it is not watching
the daemon (cora-hud shows a REPLAY banner). Nothing in the daemon's own feed ever has that key.

Scenarios (cora-replay list): steady, burst, refusal_recovery, blind_recovery, coarse_stretch, mid_trip_start,
unmonitored, exited_refused, breaker_rate_limit, ack_not_reflected; transport faults: closed_connection, silence,
garbage, split_frames, duplicate_frames; state faults: seq_regression, mono_regression, counter_reset,
relaunch_new_cgroup, many_tasks, unknown_status.

The default socket is ui.sock in a private directory: $XDG_RUNTIME_DIR/cora-replay (made 0700, and refused unless it
is ours and 0700), else a fresh tempfile.mkdtemp(prefix="cora-replay-"). Never a fixed name in /tmp, where another
user could squat it. The socket itself is created 0600.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import socket
import stat
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
import tempfile
from typing import Callable, Dict, Iterator, List, NamedTuple, Optional, Tuple, Union

try:
    from cora_sentinel.uihub import COMMAND_INTERVAL_S, COMMANDS, SCHEMA, Hub
except ImportError:
    sys.exit("cora-replay: cannot import cora_sentinel (install it, or run with PYTHONPATH=/path/to/cora-sentinel/src)")

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay-fixtures")
TRANSPORT = ("closed_connection", "silence", "garbage", "split_frames", "duplicate_frames")
TRIGGER = "some 150000 1000000"
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
MAX_LINE_IN = 1024
CAPTURE_RE = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:.]+)\s+(\{.*\})\s*$")


# ---------------------------------------------------------------------------------------------- the scripted world
class World:
    """The facts a hub reads, as a scenario sets them. It is also the hub's tripwire watcher (armed, refused) and
    scope registry (check, describe), so Hub.snapshot() runs unchanged over it."""

    def __init__(self, mono: float = 1000.0):
        self.mono = mono
        self.tasks: Dict[str, dict] = {}
        self.recs: Dict[str, dict] = {}
        self._armed: Dict[str, str] = {}
        self._refused: set = set()
        self.registry_error: Optional[str] = None
        self.evaluating = 0
        self.policy = "accept"                    # "accept": a breaker takes effect; "ack_only": it does not
        self.status_override: Optional[str] = None   # a status the daemon would never send
        self.next_seq: Optional[int] = None       # the seq of the next frame (a restarted daemon starts again at 1)
        self.lock = threading.RLock()
        self.hub = Hub("/nonexistent/cora-replay.sock", mode="enforce", tasks=lambda: copy.deepcopy(self.tasks),
                       evaluating=lambda: self.evaluating, psi=self, scopes=self, act=lambda v, t: "unused",
                       log=lambda m: None, clock=lambda: self.mono)

    # the watcher and the registry, as the hub sees them
    def armed(self) -> Dict[str, str]:
        return dict(self._armed)

    def refused(self) -> set:
        return set(self._refused)

    def check(self) -> Optional[str]:
        return self.registry_error

    def describe(self, name: str) -> Optional[dict]:
        if self.registry_error is not None or name not in self.recs:
            return None
        return dict(self.recs[name], name=name)

    # what scenarios change
    def add_task(self, name: str, cid: int, trigger: Optional[str] = TRIGGER, scope: bool = True,
                 memory_max: Optional[int] = 512 << 20, memory_high: Optional[int] = None, pids: int = 1,
                 refused: bool = False) -> None:
        limits = {"cpu_max": None, "memory_high": memory_high if scope else None, "memory_max": memory_max if scope else None}
        self.tasks[name] = {"pids": pids, "mem_bytes": 64 << 20, "id": cid, "unknown": [], "errors": [],
                            "enforced": ["THROTTLE"] if limits["memory_high"] is not None else [],   # the kernel's reading
                            "limits": limits,
                            "psi": {"some_avg10": 0.0, "some_avg60": 0.0, "some_total_us": 0,
                                    "full_avg10": 0.0, "full_avg60": 0.0, "full_total_us": 0}}
        if scope:
            self.recs[name] = {"app": name.rsplit("-", 1)[0], "uid": 1000, "profile": "app", "memory_max": memory_max,
                               "memory_high": memory_high, "psi_memory": trigger}
            if trigger and refused:
                self._refused.add(name)
            elif trigger:
                self._armed[name] = trigger

    def arm(self, name: str) -> None:
        self._refused.discard(name)
        self._armed[name] = self.recs[name]["psi_memory"]

    def stall(self, name: str, us: int, avg10: Optional[float] = None) -> None:
        p = self.tasks[name]["psi"]
        p["some_total_us"] += us
        p["full_total_us"] += us
        if avg10 is not None:
            p["some_avg10"] = p["full_avg10"] = avg10

    def trip(self, name: str) -> None:
        p = self.tasks[name]["psi"]
        self.hub.note_pressure(name, {"some_avg10": p["some_avg10"], "full_avg10": p["full_avg10"]})

    def breaker(self, cmd: str, name: str) -> None:
        if self.policy != "accept":
            return
        t = self.tasks[name]
        if cmd == "sever" and "ISOLATE" not in t["enforced"]:
            t["enforced"].append("ISOLATE")
        if cmd == "cap":
            t["limits"]["cpu_max"], t["limits"]["memory_high"] = "20000 100000", t["mem_bytes"]
            if "THROTTLE" not in t["enforced"]:
                t["enforced"].append("THROTTLE")

    def frame(self) -> dict:
        with self.lock:
            snap = self.hub.snapshot()
        snap["mono"] = round(self.mono, 6)
        snap["ts"] = (T0 + timedelta(seconds=self.mono)).isoformat(timespec="seconds")
        if self.status_override is not None:
            snap["status"] = self.status_override
        return snap


# ---------------------------------------------------------------------------------------------- scenarios
# A scenario sets up the world, then yields the virtual seconds to wait before each next frame (it may change the
# world first). The runner emits a frame at the start and after every yield. A scenario may also yield an Op, a
# transport event with no frame of its own.
class Op(NamedTuple):
    kind: str                                     # "close" | "raw" | "split" | "dup" | "silence"
    arg: object = None                            # raw: bytes; split: pieces; silence: virtual seconds


Step = Union[float, Op]
Scenario = Callable[[World], Iterator[float]]


def _steady(w: World, name: str = "steady-a1b2c3", seconds: float = 60.0, step: float = 2.0) -> Iterator[float]:
    w.add_task(name, 101)
    for _ in range(int(seconds / step)):
        w.stall(name, int(step * 5_000), avg10=0.5)
        yield step


def steady(w: World) -> Iterator[float]:
    """A clean 2 s heartbeat, one live task, no pressure: clear."""
    yield from _steady(w)


def burst(w: World) -> Iterator[float]:
    """10 s clear, then 10 s of 30 % stall (over the 15 % trigger) that trips every second, then recovery: the trip
    flag clears PRESSURE_HOLD_S (10 s) after the last trip."""
    n = "burst-b2c3d4"
    w.add_task(n, 102)
    for _ in range(20):
        w.stall(n, 5_000, avg10=0.5)
        yield 0.5
    for i in range(20):
        w.stall(n, 150_000, avg10=min(30.0, 3.0 * (i + 1)))
        if i % 2 == 1:
            w.trip(n)
        yield 0.5
    for i in range(30):
        w.stall(n, 0, avg10=max(0.0, 30.0 - 2.0 * (i + 1)))
        yield 0.5


def refusal_recovery(w: World) -> Iterator[float]:
    """A scope whose tripwire the kernel refused (psi_refused), then re-armed by the retry: armed, clear."""
    n = "refused-c3d4e5"
    w.add_task(n, 103, refused=True)
    for _ in range(5):
        yield 2.0
    w.arm(n)
    for _ in range(5):
        yield 2.0


def blind_recovery(w: World) -> Iterator[float]:
    """An unreadable scope registry: blind, limits.source unknown, Cap still offered; then it reads cleanly again."""
    n = "blind-d4e5f6"
    w.add_task(n, 104, memory_high=400 << 20)
    for _ in range(3):
        yield 2.0
    w.registry_error = "/var/lib/cora-sentinel/scopes.json: not valid JSON (Expecting value at line 1 column 15)"
    for _ in range(5):
        yield 2.0
    w.registry_error = None
    for _ in range(5):
        yield 2.0


def coarse_stretch(w: World) -> Iterator[float]:
    """Frames 2.0 s apart on a 1 s trigger window, a steady 10 % stall: a HUD must hatch it as coarse."""
    n = "coarse-e5f6a7"
    w.add_task(n, 105)
    for _ in range(15):
        w.stall(n, 200_000, avg10=10.0)
        yield 2.0


def mid_trip_start(w: World) -> Iterator[float]:
    """The feed starts mid-trip: the first frame already says pressure.count 3, active. A HUD shows the badge and
    marks none of that history; later trips are marked."""
    n = "midtrip-f6a7b8"
    w.add_task(n, 106)
    w.stall(n, 600_000, avg10=25.0)
    for _ in range(3):
        w.trip(n)
    for i in range(10):
        w.stall(n, 150_000)
        if i % 2 == 1:
            w.trip(n)
        yield 0.5
    for _ in range(26):
        yield 0.5


def unmonitored(w: World) -> Iterator[float]:
    """A task that is not a launch scope (a root cora-run task): no scope key, psi_state unmonitored, source none."""
    w.add_task("plain", 107, scope=False)
    for _ in range(10):
        yield 2.0


def exited_refused(w: World) -> Iterator[float]:
    """A refused scope whose processes all end (pids 0): the psi_refused light drops; then the task is gone."""
    n = "exiting-a7b8c9"
    w.add_task(n, 108, refused=True)
    for _ in range(4):
        yield 2.0
    w.tasks[n]["pids"] = 0
    for _ in range(5):
        yield 2.0
    del w.tasks[n]
    for _ in range(3):
        yield 2.0


def breaker_rate_limit(w: World) -> Iterator[float]:
    """A task to press breakers on: a second command within a second gets the hub's 'slow down' refusal."""
    yield from _steady(w, name="ratelimit-b8c9d0")


def ack_not_reflected(w: World) -> Iterator[float]:
    """Breakers are acknowledged (ok: true) and nothing changes: the client must raise ACK_NOT_REFLECTED."""
    w.policy = "ack_only"
    yield from _steady(w, name="ackonly-c9d0e1")


# ------------------------------------------------ transport faults
def closed_connection(w: World) -> Iterator[Step]:
    """The daemon closes every connection mid-feed, then carries on: a client shows unreachable, reconnects, and is
    handed the latest frame at once."""
    w.add_task("closed-d0e1f2", 109)
    for _ in range(4):
        yield 2.0
    yield Op("close")
    for _ in range(6):
        yield 2.0


def silence(w: World) -> Iterator[Step]:
    """The socket stays open and says nothing for 10 s (over STALE_AFTER_S): a wedged daemon, never "clear"."""
    w.add_task("silent-e1f2a3", 110)
    for _ in range(3):
        yield 2.0
    yield Op("silence", 10.0)
    for _ in range(4):
        yield 2.0


def garbage(w: World) -> Iterator[Step]:
    """Junk between frames: not JSON, half an object, another schema, a bare list. A client skips them all."""
    w.add_task("garbage-f2a3b4", 111)
    junk = b'not json at all\n{"schema": "cora.sentinel.ui/v1", "type": "sta\n{"schema": "other/v9", "type": ' \
           b'"state", "status": "clear"}\n[1, 2, 3]\n\n'
    for _ in range(3):
        yield 2.0
        yield Op("raw", junk)
    for _ in range(3):
        yield 2.0


def split_frames(w: World) -> Iterator[Step]:
    """Each frame arrives in pieces over separate writes (7 of them, the last one the newline)."""
    w.add_task("split-a3b4c5", 112)
    for _ in range(6):
        yield Op("split", 7)
        yield 2.0


def duplicate_frames(w: World) -> Iterator[Step]:
    """Every frame is sent twice, byte for byte: a ring buffer ignores a seq already seen."""
    w.add_task("dup-b4c5d6", 113)
    for _ in range(6):
        w.stall("dup-b4c5d6", 20_000, avg10=1.0)
        yield 2.0
        yield Op("dup")


# ------------------------------------------------ state faults
def seq_regression(w: World) -> Iterator[Step]:
    """The daemon restarts: seq starts again at 1 (its clock carries on). Clients start their history over."""
    yield from _steady(w, name="seqreg-c5d6e7", seconds=10.0)
    w.next_seq = 1
    yield from _stalls(w, "seqreg-c5d6e7", 5)


def mono_regression(w: World) -> Iterator[Step]:
    """The daemon clock goes back 100 s with seq still rising: treated as a restart too."""
    yield from _steady(w, name="monoreg-d6e7f8", seconds=10.0)
    w.mono -= 100.0
    yield from _stalls(w, "monoreg-d6e7f8", 5)


def counter_reset(w: World) -> Iterator[Step]:
    """The cumulative stall counters fall to 0 under the same cgroup id: that ring starts over, never a negative
    stall."""
    yield from _steady(w, name="reset-e7f8a9", seconds=10.0)
    p = w.tasks["reset-e7f8a9"]["psi"]
    p["some_total_us"] = p["full_total_us"] = 0
    yield from _stalls(w, "reset-e7f8a9", 5)


def relaunch_new_cgroup(w: World) -> Iterator[Step]:
    """The same name relaunched under a new cgroup id: a new task, a new history; a breaker aimed at the old id is
    refused ("not the task you saw")."""
    n = "relaunch-f8a9b0"
    yield from _steady(w, name=n, seconds=10.0)
    del w.tasks[n]
    yield 2.0
    w.add_task(n, 214)
    yield from _stalls(w, n, 5)


def many_tasks(w: World) -> Iterator[Step]:
    """20 concurrent tasks in every state: armed, refused, disabled (launched with off), unmonitored, exited."""
    for i in range(20):
        name, kind = f"many{i:02d}-{i:06x}", i % 5
        w.add_task(name, 300 + i, trigger=None if kind == 2 else TRIGGER, scope=kind != 3, refused=kind == 1,
                   pids=0 if kind == 4 else 1)
    for k in range(15):
        for i in range(20):
            if i % 5 in (0, 1):
                w.stall(f"many{i:02d}-{i:06x}", 1_000 * (i + 1) * (k % 4), avg10=0.1 * i)
        yield 2.0


def unknown_status(w: World) -> Iterator[Step]:
    """A status string this client does not know ("meltdown"), then a known one again: loud, never green."""
    w.add_task("status-a9b0c1", 115)
    for _ in range(3):
        yield 2.0
    w.status_override = "meltdown"
    for _ in range(4):
        yield 2.0
    w.status_override = None
    for _ in range(3):
        yield 2.0


def _stalls(w: World, name: str, n: int, step: float = 2.0) -> Iterator[Step]:
    for _ in range(n):
        w.stall(name, int(step * 5_000), avg10=0.5)
        yield step


SCENARIOS: Dict[str, Scenario] = {f.__name__: f for f in (steady, burst, refusal_recovery, blind_recovery, coarse_stretch,
                                                         mid_trip_start, unmonitored, exited_refused, breaker_rate_limit,
                                                         ack_not_reflected, closed_connection, silence, garbage,
                                                         split_frames, duplicate_frames, seq_regression, mono_regression,
                                                         counter_reset, relaunch_new_cgroup, many_tasks, unknown_status)}


def scenario_frames(name: str, world: Optional[World] = None) -> Iterator[Tuple[float, Union[dict, Op]]]:
    """(virtual seconds since the previous item, frame or Op), the first frame at 0. A "split" Op is followed by the
    frame it splits; a "silence" Op advances the virtual clock by its seconds."""
    w = world or World()
    gen = SCENARIOS[name](w)
    seq = 0

    def emit(dt):
        nonlocal seq
        f = w.frame()
        if w.next_seq is not None:
            seq, w.next_seq = w.next_seq - 1, None
        seq += 1
        f["seq"] = seq
        return dt, f
    try:
        step = next(gen)
    except StopIteration:
        step = None
    yield emit(0.0)
    while step is not None:
        if isinstance(step, Op):
            if step.kind == "silence":
                with w.lock:
                    w.mono += float(step.arg)
                yield float(step.arg), step
            else:
                yield 0.0, step                   # a "split" applies to the next frame the scenario makes
        else:
            with w.lock:
                w.mono += step
            yield emit(step)
        try:
            step = next(gen)
        except StopIteration:
            step = None


# ---------------------------------------------------------------------------------------------- recorded feeds
def read_log(path: str) -> List[Tuple[Optional[float], dict]]:
    """[(capture time in s or None, frame)] of the state frames in a recorded feed, in order."""
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        when = None
        m = CAPTURE_RE.match(line)
        if m:
            when, line = datetime.fromisoformat(m.group(1)).timestamp(), m.group(2)
        if not line.startswith("{"):
            continue
        try:
            f = json.loads(line)
        except ValueError:
            continue
        if isinstance(f, dict) and f.get("schema") == SCHEMA and f.get("type") == "state":
            out.append((when, f))
    return out


def log_frames(path: str, loop: bool = False) -> Iterator[Tuple[float, dict]]:
    frames = read_log(path)
    if not frames:
        raise SystemExit(f"cora-replay: no state frames in {path}")
    seq_off, mono_off, top_seq, top_mono, passes = 0, 0.0, None, None, 0
    while True:
        if passes:                                # start the pass above everything sent so far
            first = frames[0][1]
            if isinstance(first.get("seq"), int) and top_seq is not None:
                seq_off = top_seq + 1 - first["seq"]
            if isinstance(first.get("mono"), (int, float)) and top_mono is not None:
                mono_off = top_mono + 2.0 - first["mono"]
        prev = None
        for when, f in frames:
            dt = 0.0
            if prev is not None:
                pw, pf = prev
                m0, m1 = pf.get("mono"), f.get("mono")
                if isinstance(m0, (int, float)) and isinstance(m1, (int, float)) and 0 <= m1 - m0 < 3600:
                    dt = m1 - m0
                elif when is not None and pw is not None:
                    dt = max(0.0, when - pw)
            prev = (when, f)
            g = copy.deepcopy(f)
            if isinstance(g.get("seq"), int):
                g["seq"] += seq_off
                top_seq = g["seq"] if top_seq is None else max(top_seq, g["seq"])
            if isinstance(g.get("mono"), (int, float)):
                g["mono"] = round(g["mono"] + mono_off, 6)
                top_mono = g["mono"] if top_mono is None else max(top_mono, g["mono"])
            yield dt, g
        if not loop:
            return
        passes += 1


def sanitize(frames: List[dict], keep: List[str], seq_range: Optional[Tuple[int, int]] = None) -> List[dict]:
    """A capture made shareable: only tasks named with a kept prefix, session counters zeroed, ts on the daemon clock
    from 2026-01-01. With seq_range (FIRST, LAST) only the frames from the LAST frame with seq FIRST to the next frame
    with seq LAST are kept (a capture across a daemon restart repeats seq numbers)."""
    lo, hi = 0, len(frames) - 1
    if seq_range is not None:
        starts = [i for i, f in enumerate(frames) if f.get("seq") == seq_range[0]
                  and any(g.get("seq") == seq_range[1] for g in frames[i:])]
        if not starts:
            return []
        lo = starts[-1]
        hi = next(j for j in range(lo, len(frames)) if frames[j].get("seq") == seq_range[1])
    out = []
    for f in frames[lo:hi + 1]:
        g = copy.deepcopy(f)
        g["tasks"] = [t for t in g.get("tasks") or [] if isinstance(t, dict)
                      and any(str(t.get("name", "")).startswith(k) for k in keep)]
        if isinstance(g.get("session"), dict):
            g["session"] = {k: (0 if isinstance(v, (int, float)) and not isinstance(v, bool) else None)
                            for k, v in g["session"].items() if k != "started"}
        if isinstance(g.get("mono"), (int, float)):
            g["ts"] = (T0 + timedelta(seconds=g["mono"])).isoformat(timespec="seconds")
        g.pop("replay", None)
        out.append(g)
    return out


def fixture_path(name: str) -> str:
    if not re.fullmatch(r"[a-z0-9_]+", name):
        raise SystemExit(f"cora-replay: bad fixture name {name!r}")
    return os.path.join(FIXTURES, f"{name}.ndjson")


def fixtures() -> List[str]:
    try:
        return sorted(f[:-7] for f in os.listdir(FIXTURES) if f.endswith(".ndjson"))
    except OSError:
        return []


# ---------------------------------------------------------------------------------------------- the socket
def private_dir(base: Optional[str] = None) -> str:
    """A directory only we can use, for the default socket: $XDG_RUNTIME_DIR/cora-replay, else a fresh mkdtemp."""
    base = os.environ.get("XDG_RUNTIME_DIR") if base is None else base
    if base and os.path.isdir(base):
        d = os.path.join(base, "cora-replay")
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise SystemExit(f"cora-replay: {d} is not a 0700 directory of ours: refusing to use it")
        return d
    return tempfile.mkdtemp(prefix="cora-replay-")


def default_socket() -> str:
    return os.path.join(private_dir(), "ui.sock")



class ReplayServer:
    def __init__(self, path: str, world: Optional[World] = None, clock: Callable[[], float] = time.monotonic,
                 source: str = "replay"):
        self.path, self.world, self.clock, self.source = path, world, clock, source
        self.inserted = 0                         # frames sent in reply to a breaker, between the scripted ones
        self.sock: Optional[socket.socket] = None
        self.clients: Dict[socket.socket, dict] = {}
        self.latest: Optional[dict] = None
        self.lock = threading.Lock()
        self._stop = threading.Event()

    def start(self) -> None:
        try:
            if stat.S_ISSOCK(os.lstat(self.path).st_mode):
                os.unlink(self.path)              # a stale socket of ours
            else:
                raise SystemExit(f"cora-replay: {self.path} exists and is not a socket: refusing to replace it")
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            old = os.umask(0o177)
            try:
                s.bind(self.path)
            finally:
                os.umask(old)
            s.listen(16)
        except BaseException:
            s.close()
            raise
        self.sock = s
        threading.Thread(target=self._accept, name="replay-accept", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        with self.lock:
            for c in list(self.clients):
                self._drop(c)
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)   # wakes the accept thread (a bare close may not)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            try:
                os.unlink(self.path)
            except OSError:
                pass

    def close(self) -> None:
        self.stop()

    def connected(self) -> int:
        with self.lock:
            return len(self.clients)

    def _line(self, frame: dict) -> bytes:
        return (json.dumps(dict(frame, replay={"source": self.source}), separators=(",", ":")) + "\n").encode()

    def broadcast(self, frame: dict, pieces: int = 1, pause: float = 0.02) -> None:
        line = self._line(frame)
        with self.lock:
            self.latest = frame
        if pieces <= 1:
            self.send_raw(line)
            return
        cuts = [len(line) * i // pieces for i in range(pieces)] + [len(line)]
        for a, b in zip(cuts, cuts[1:]):
            self.send_raw(line[a:b])
            time.sleep(pause)

    def send_raw(self, data: bytes) -> None:
        with self.lock:
            for c in list(self.clients):
                self._send(c, data)

    def drop_all(self) -> None:
        """Close every client connection, and keep listening."""
        with self.lock:
            for c in list(self.clients):
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self._drop(c)

    def _send(self, c: socket.socket, data: bytes) -> None:
        try:
            c.sendall(data)
        except OSError:
            self._drop(c)

    def _drop(self, c: socket.socket) -> None:
        self.clients.pop(c, None)
        try:
            c.close()
        except OSError:
            pass

    def _accept(self) -> None:
        sock = self.sock                          # stop() clears self.sock; this thread keeps its own reference
        while not self._stop.is_set():
            try:
                c, _ = sock.accept()
            except OSError:
                return
            c.settimeout(2.0)
            with self.lock:
                self.clients[c] = {"last_cmd": -1e9}
                if self.latest is not None:
                    self._send(c, self._line(self.latest))
            threading.Thread(target=self._read, args=(c,), name="replay-client", daemon=True).start()

    def _read(self, c: socket.socket) -> None:
        buf = b""
        while not self._stop.is_set():
            try:
                data = c.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if len(line) > MAX_LINE_IN:
                    with self.lock:
                        self._drop(c)
                    return
                reply = self.command(c, line)
                with self.lock:
                    if c in self.clients:
                        self._send(c, (json.dumps(reply, separators=(",", ":")) + "\n").encode())
        with self.lock:
            self._drop(c)

    def command(self, c: socket.socket, line: bytes) -> dict:
        """The hub's breaker contract, refusals word for word (cora_sentinel.uihub._command)."""
        try:
            msg = json.loads(line)
        except ValueError:
            msg = None
        tag = msg.get("id") if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int)) else None
        tag = str(tag)[:64] if tag is not None else None

        def refuse(why: str) -> dict:
            return {"schema": SCHEMA, "type": "result", "id": tag, "ok": False, "error": why}
        if not isinstance(msg, dict):
            return refuse("not a JSON object")
        cmd, task = msg.get("cmd"), msg.get("task")
        if cmd not in COMMANDS:
            return refuse(f"unknown command {cmd!r}: the tray can only tighten ({', '.join(sorted(COMMANDS))}), "
                          "and launch places only the caller itself; releasing is root-only: cora-firewall release / cora-cgroup")
        if self.world is None:
            return refuse("breakers unavailable: this is a recorded feed")
        now = self.clock()
        with self.lock:
            st = self.clients.get(c, {"last_cmd": -1e9})
            if now - st["last_cmd"] < COMMAND_INTERVAL_S:
                return refuse("slow down: one command per second")
        w = self.world
        with w.lock:
            t = w.tasks.get(task) if isinstance(task, str) else None
            if t is None:
                return refuse(f"no live task named {task!r}")
            if t["id"] != msg.get("cgroup_id"):
                return refuse(f"{task} is not the task you saw (it exited or was relaunched): look again")
            with self.lock:
                st["last_cmd"] = now
            w.breaker(cmd, task)
            frame = w.frame()
        frame["seq"] = (self.latest or {}).get("seq", 0) + 1
        self.inserted += 1
        self.broadcast(frame)                     # the hub shows an accepted breaker at once
        verb = COMMANDS[cmd]
        return {"schema": SCHEMA, "type": "result", "id": tag, "ok": True,
                "action": f"done:{verb}@cgroup:{task}[replay{'' if w.policy == 'accept' else ': acknowledged only'}]"}


def run(server: ReplayServer, frames: Iterator[Tuple[float, Union[dict, Op]]], speed: float = 1.0,
        sleep: Callable[[float], None] = time.sleep) -> int:
    """Emit frames at their (scaled) pace, and carry out transport Ops. Every scripted seq is shifted up by the frames
    a breaker reply inserted, so the feed stays in order and a scripted regression still regresses."""
    n, pieces = 0, 1
    for dt, f in frames:
        if dt > 0:
            sleep(dt / speed)
        if isinstance(f, Op):
            if f.kind == "close":
                server.drop_all()
            elif f.kind == "raw":
                server.send_raw(f.arg)
            elif f.kind == "dup" and server.latest is not None:
                server.send_raw(server._line(server.latest))
            elif f.kind == "split":
                pieces = int(f.arg)
            continue
        if server.inserted and isinstance(f.get("seq"), int):
            f = dict(f, seq=f["seq"] + server.inserted)
        server.broadcast(f, pieces=pieces)
        pieces = 1
        n += 1
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cora-replay", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    for mode in ("file", "scenario", "fixture"):
        p = sub.add_parser(mode)
        p.add_argument("path" if mode == "file" else "name")
        p.add_argument("--speed", type=float, default=1.0)
        p.add_argument("--loop", action="store_true")
        p.add_argument("--socket", default=None, help="default: ui.sock in a private 0700 directory")
    p = sub.add_parser("sanitize")
    p.add_argument("capture")
    p.add_argument("out")
    p.add_argument("--keep", action="append", required=True, help="a task name prefix to keep (repeatable)")
    p.add_argument("--seq", default=None, help="FIRST:LAST, the recorded seq of the first and last frame to keep")
    sub.add_parser("list")
    a = ap.parse_args(argv)
    if a.mode == "list":
        for name, f in SCENARIOS.items():
            print(f"{name:<20} {(f.__doc__ or '').strip().splitlines()[0]}")
        for name in fixtures():
            print(f"{name:<20} (fixture) a sanitized Dimgeon capture")
        return 0
    if a.mode == "sanitize":
        rng = tuple(int(x) for x in a.seq.split(":")) if a.seq else None
        out = sanitize([f for _, f in read_log(a.capture)], a.keep, rng)
        if not out:
            raise SystemExit("cora-replay: nothing left to write")
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(f, separators=(",", ":")) + "\n" for f in out)
        print(f"cora-replay: {len(out)} frames written to {a.out}", file=sys.stderr)
        return 0
    if a.speed <= 0:
        ap.error("--speed must be above 0")
    if a.mode == "scenario" and a.name not in SCENARIOS:
        ap.error(f"unknown scenario {a.name!r}: {', '.join(SCENARIOS)}")
    if a.mode == "fixture":
        if a.name not in fixtures():
            ap.error(f"unknown fixture {a.name!r}: {', '.join(fixtures()) or 'none installed'}")
        a.mode, a.path = "file", fixture_path(a.name)
        source = f"fixture:{a.name}"
    else:
        source = f"{a.mode}:{getattr(a, 'path', None) or a.name}"
    a.socket = a.socket or default_socket()
    world = World() if a.mode == "scenario" else None
    server = ReplayServer(a.socket, world, source=source)
    server.start()
    print(f"cora-replay: serving {a.mode} {getattr(a, 'path', None) or a.name} on {a.socket} (speed {a.speed:g}"
          f"{', looping' if a.loop else ''}); point a client at it with --socket {a.socket}", file=sys.stderr)
    try:
        while True:
            frames = log_frames(a.path, loop=a.loop) if a.mode == "file" else scenario_frames(a.name, world)
            n = run(server, frames, a.speed)
            if a.mode == "file" or not a.loop:
                print(f"cora-replay: {n} frames sent", file=sys.stderr)
                break
            world = server.world = World()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
