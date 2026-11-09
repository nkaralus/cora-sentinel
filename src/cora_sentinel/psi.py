"""
cora_sentinel.psi - memory-pressure (PSI) tripwires on launch scopes. Stdlib only. SIGNAL ONLY: a tripped wire is
reported (the feed turns the tray amber, the journal gets a line); nothing is throttled, frozen or killed.

The kernel's mechanism (Documentation/accounting/psi.rst): write "some|full <stall us> <window us>" to a cgroup's
memory.pressure, keep that fd open, and poll it for POLLPRI. The kernel wakes the poller when tasks in the cgroup
stalled on memory for at least <stall> within any <window>. The fd IS the trigger: closing it removes the trigger.

    w = PressureWatcher(cg, on_trip=lambda name, stats: ...)
    w.start(); w.add("steam-570-1a2b3c", "some 150000 1000000"); ...; w.remove(name); w.stop()

Window 0.5 s to 10 s and stall no longer than the window: the kernel's own limits, checked here first so a bad
--psi-memory is refused with a reason instead of an EINVAL.
"""
from __future__ import annotations

import os
import re
import select
import sys
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

DEFAULT_TRIGGER = "some 150000 1000000"          # 150 ms of memory stall within any 1 s
TRIGGER_RE = re.compile(r"(some|full) (\d+) (\d+)", re.ASCII)
MIN_WINDOW_US, MAX_WINDOW_US = 500_000, 10_000_000


class PsiError(Exception):
    pass


def parse_trigger(v) -> Optional[str]:
    """None or "off" -> no tripwire. Otherwise a validated "some|full STALL WINDOW" (microseconds)."""
    if v is None:
        return DEFAULT_TRIGGER
    if not isinstance(v, str):
        raise PsiError(f"not a pressure trigger: {v!r}")
    t = " ".join(v.split())
    if t.lower() == "off":
        return None
    m = TRIGGER_RE.fullmatch(t)
    if not m:
        raise PsiError(f"pressure trigger {v!r}: expected 'some|full STALL_US WINDOW_US', e.g. '{DEFAULT_TRIGGER}'")
    stall, window = int(m.group(2)), int(m.group(3))
    if not MIN_WINDOW_US <= window <= MAX_WINDOW_US:
        raise PsiError(f"pressure window {window} us: the kernel takes 500000 to 10000000")
    if not 0 < stall <= window:
        raise PsiError(f"pressure stall {stall} us must be above 0 and at most the window ({window} us)")
    return t


def threshold(trigger: Optional[str]) -> Optional[Dict[str, object]]:
    """The feed's psi_threshold for an ARMED trigger: kind, stall_us, window_us, fraction (stall / window: the share of
    any one window that must be stalled to trip) and the trigger text. None for no trigger."""
    if not trigger:
        return None
    m = TRIGGER_RE.fullmatch(trigger)
    if not m:
        return None
    stall, window = int(m.group(2)), int(m.group(3))
    return {"kind": m.group(1), "stall_us": stall, "window_us": window, "fraction": round(stall / window, 6),
            "trigger": trigger}


def retry_refused(watcher: "PressureWatcher", trigger_of: Callable[[str], Optional[str]]) -> List[str]:
    """Try every refused trigger again whose scope still wants one (trigger_of(name) -> its trigger, or None when the
    scope is gone or launched with off). A refusal can heal without a restart: PSI switched back on for the cgroup
    (cgroup.pressure = 1), the PSI files back. Returns the names that are armed now; the rest stay refused."""
    armed = []
    for name in sorted(watcher.refused()):
        trigger = trigger_of(name)
        if not trigger:
            continue
        try:
            watcher.add(name, trigger)
        except PsiError:
            continue
        armed.append(name)
    return armed


def read_pressure(text: str, totals: bool = False) -> Dict[str, float]:
    """'some avg10=1.23 avg60=... total=...' lines -> {'some_avg10': 1.23, 'full_avg10': ...}. totals=True also
    returns the cumulative stall counters, 'some_total_us' / 'full_total_us' (integers, microseconds): two of them a
    known time apart give the EXACT stall fraction of that window, which a rolling average cannot."""
    out: Dict[str, float] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("some", "full"):
            continue
        for kv in parts[1:]:
            k, _, val = kv.partition("=")
            try:
                if k in ("avg10", "avg60"):
                    out[f"{parts[0]}_{k}"] = float(val)
                elif k == "total" and totals:
                    out[f"{parts[0]}_total_us"] = int(val)
            except ValueError:
                pass
    return out


class PressureWatcher:
    def __init__(self, cg, on_trip: Callable[[str, Dict[str, float]], None],
                 log: Callable[[str], None] = lambda m: print(f"[psi] {m}", file=sys.stderr, flush=True),
                 poller: Callable[[], object] = select.poll):
        self.cg, self.on_trip, self.log = cg, on_trip, log
        self._lock = threading.Lock()
        self._fds: Dict[int, str] = {}            # fd -> scope name (owned by the poll thread once applied)
        self._names: Dict[str, int] = {}
        self._triggers: Dict[str, str] = {}       # name -> trigger, only once the kernel accepted it
        self._refused: Dict[str, str] = {}        # name -> why the last attempt could not arm it
        self._pending: List[Tuple[str, str, Optional[int]]] = []   # ("add", name, fd) / ("remove", name, None)
        self._poll = poller()
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        self._poll.register(self._wake_r, select.POLLIN)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ called from other threads
    def add(self, name: str, trigger: str) -> None:
        """Arm `trigger` on the scope. Raises PsiError with the kernel's reason if it is refused."""
        path = self.cg._dir(name) / "memory.pressure"
        try:
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as e:
            raise self._refuse(name, f"cannot open {path}: {e.strerror} (is PSI enabled? psi=1 on the kernel command line)")
        try:
            os.write(fd, trigger.encode() + b"\0")
        except OSError as e:
            os.close(fd)
            raise self._refuse(name, f"the kernel refused the pressure trigger {trigger!r} on {name}: {e.strerror}")
        with self._lock:
            self._triggers[name] = trigger            # only now: the kernel took it
            self._refused.pop(name, None)
            self._pending.append(("add", name, fd))
        self._kick()

    def _refuse(self, name: str, why: str) -> PsiError:
        with self._lock:
            self._triggers.pop(name, None)            # a refused re-add does not leave the old trigger claimed
            self._refused[name] = why
        return PsiError(why)

    def armed(self) -> Dict[str, str]:
        """name -> trigger for every scope whose trigger the kernel accepted (a copy)."""
        with self._lock:
            return dict(self._triggers)

    def refused(self) -> Set[str]:
        """Scopes whose last trigger could not be armed (a copy)."""
        with self._lock:
            return set(self._refused)

    def remove(self, name: str) -> None:
        with self._lock:
            self._triggers.pop(name, None)
            self._refused.pop(name, None)
            self._pending.append(("remove", name, None))
        self._kick()

    def watching(self) -> List[str]:
        with self._lock:
            return sorted(self._names)

    def _kick(self) -> None:
        if self._wake_w is None:
            return                                # stopped: the pipe is closed
        try:
            os.write(self._wake_w, b"x")
        except OSError:
            pass

    # ------------------------------------------------------------------ the poll thread
    def _apply(self) -> None:
        with self._lock:
            todo, self._pending = self._pending, []
            for op, name, fd in todo:
                old = self._names.pop(name, None)
                if old is not None:
                    self._poll.unregister(old)
                    self._fds.pop(old, None)
                    os.close(old)
                if op == "add":
                    self._names[name], self._fds[fd] = fd, name
                    self._poll.register(fd, select.POLLPRI)

    def poll_once(self, timeout_ms: int = 1000) -> None:
        self._apply()
        for fd, ev in self._poll.poll(timeout_ms):
            if fd == self._wake_r:
                try:
                    os.read(self._wake_r, 4096)
                except BlockingIOError:
                    pass
                continue
            with self._lock:
                name = self._fds.get(fd)
            if name is None:
                continue
            if ev & (select.POLLERR | select.POLLNVAL | select.POLLHUP):
                self.remove(name)                    # the cgroup went away under us
                continue
            if ev & select.POLLPRI:
                try:
                    stats = read_pressure(os.pread(fd, 4096, 0).decode(errors="replace"))
                except OSError:
                    stats = {}
                try:
                    self.on_trip(name, stats)
                except Exception as e:
                    self.log(f"on_trip failed for {name}: {e!r}")
        self._apply()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once(1000)
            except Exception as e:                   # never let one bad fd end the watcher
                self.log(f"poll failed: {e!r}")

    def start(self) -> None:
        if self._wake_r is None:                  # stopped earlier: stop() closed the wake pipe
            self._wake_r, self._wake_w = os.pipe()
            os.set_blocking(self._wake_r, False)
            self._poll.register(self._wake_r, select.POLLIN)
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="psi-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._kick()
        if self._thread:
            self._thread.join(timeout=2)
        with self._lock:
            for fd in list(self._fds):
                os.close(fd)
            self._fds.clear()
            for op, name, fd in self._pending:    # opened, but never handed to the poll thread
                if fd is not None and fd not in self._fds:
                    os.close(fd)
            self._pending.clear()
            self._names.clear()
            self._triggers.clear()
            for fd in (self._wake_r, self._wake_w):  # the wake pipe goes too: stop() leaves no descriptor behind
                if fd is not None:
                    try:
                        self._poll.unregister(fd)
                    except (KeyError, ValueError, OSError):
                        pass
                    os.close(fd)
            self._wake_r = self._wake_w = None
