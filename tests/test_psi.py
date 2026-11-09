"""Memory-pressure tripwires (cora_sentinel.psi) and their place in the launch path and the feed. SIGNAL ONLY.
Unit tests drive the watcher with a scripted poller (a temp file cannot raise POLLPRI); the last test makes real
memory pressure under the real kernel (root, cgroup v2, PSI)."""
import json
import os
import select
import socket
import subprocess
import sys
import time

import pytest

from cora_sentinel import psi, uihub
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.psi import DEFAULT_TRIGGER, PressureWatcher, PsiError, parse_trigger, read_pressure
from cora_sentinel.scope import Scopes

KERNEL_TEXT = "some avg10=12.34 avg60=3.21 avg300=0.50 total=123456\nfull avg10=4.00 avg60=1.00 avg300=0.10 total=4567\n"


# ---------------------------------------------------------------- triggers

@pytest.mark.parametrize("v,want", [
    (None, DEFAULT_TRIGGER), ("off", None), ("OFF", None),
    ("some 150000 1000000", "some 150000 1000000"), ("full  50000   2000000 ", "full 50000 2000000"),
    ("some 500000 500000", "some 500000 500000"), ("some 1 10000000", "some 1 10000000"),
])
def test_parse_trigger(v, want):
    assert parse_trigger(v) == want


@pytest.mark.parametrize("v,why", [
    ("medium 1 1000000", "expected"), ("some 150ms 1s", "expected"), ("some 150000", "expected"),
    ("some 100 400000", "500000 to 10000000"), ("some 100 20000000", "500000 to 10000000"),
    ("some 0 1000000", "above 0"), ("some 2000000 1000000", "at most the window"), (7, "not a pressure trigger"),
])
def test_bad_triggers(v, why):
    with pytest.raises(PsiError, match=why):
        parse_trigger(v)


def test_read_pressure():
    assert read_pressure(KERNEL_TEXT) == {"some_avg10": 12.34, "some_avg60": 3.21, "full_avg10": 4.0, "full_avg60": 1.0}
    assert read_pressure("garbage\nsome avg10=x\n") == {}


# ---------------------------------------------------------------- the watcher

class ScriptedPoll:
    """select.poll stand-in: register/unregister for real, poll() returns what the test queues."""
    def __init__(self):
        self.fds, self.queue = {}, []

    def register(self, fd, ev):
        self.fds[fd] = ev

    def unregister(self, fd):
        self.fds.pop(fd)

    def poll(self, timeout=None):
        out, self.queue = [e for e in self.queue if e[0] in self.fds], []
        return out


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "cora"
    root.mkdir()
    (root / "game-abcdef").mkdir()
    (root / "game-abcdef" / "memory.pressure").write_text("")
    return CgroupRoot(str(root))


@pytest.fixture
def watcher(tree):
    trips, logs = [], []
    p = ScriptedPoll()
    w = PressureWatcher(tree, on_trip=lambda n, s: trips.append((n, s)), log=logs.append, poller=lambda: p)
    w.trips, w.logs, w.p = trips, logs, p
    yield w
    w.stop()


def test_add_writes_the_trigger_and_watches_for_priority_events(watcher, tree):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.poll_once(0)
    assert watcher.watching() == ["game-abcdef"]
    assert (tree.root / "game-abcdef" / "memory.pressure").read_bytes() == DEFAULT_TRIGGER.encode() + b"\0"
    fd = watcher._names["game-abcdef"]
    assert watcher.p.fds[fd] == select.POLLPRI


def test_a_trip_reports_the_kernels_numbers(watcher, tree):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.poll_once(0)
    (tree.root / "game-abcdef" / "memory.pressure").write_text(KERNEL_TEXT)   # what the kernel shows on read
    watcher.p.queue = [(watcher._names["game-abcdef"], select.POLLPRI)]
    watcher.poll_once(0)
    assert watcher.trips == [("game-abcdef", read_pressure(KERNEL_TEXT))]


def test_ordinary_readiness_is_not_a_trip(watcher):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.poll_once(0)
    watcher.p.queue = [(watcher._names["game-abcdef"], select.POLLIN | select.POLLOUT)]
    watcher.poll_once(0)
    assert watcher.trips == []


def test_a_vanished_cgroup_is_dropped(watcher):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.poll_once(0)
    fd = watcher._names["game-abcdef"]
    watcher.p.queue = [(fd, select.POLLERR)]
    watcher.poll_once(0)
    assert watcher.watching() == [] and watcher.trips == []
    with pytest.raises(OSError):
        os.fstat(fd)                                               # closed: the kernel trigger is gone with it


def test_remove_closes_the_fd(watcher):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.poll_once(0)
    fd = watcher._names["game-abcdef"]
    watcher.remove("game-abcdef")
    watcher.poll_once(0)
    assert watcher.watching() == []
    with pytest.raises(OSError):
        os.fstat(fd)


def test_re_adding_replaces_the_old_trigger(watcher):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.poll_once(0)
    old = watcher._names["game-abcdef"]
    watcher.add("game-abcdef", "some 50000 1000000")
    watcher.poll_once(0)
    assert watcher._names["game-abcdef"] != old and len(watcher.p.fds) == 2      # the new one + the wake pipe


def test_a_failing_callback_does_not_stop_the_watcher(tree):
    p = ScriptedPoll()
    logs = []
    w = PressureWatcher(tree, on_trip=lambda n, s: 1 / 0, log=logs.append, poller=lambda: p)
    try:
        w.add("game-abcdef", DEFAULT_TRIGGER)
        w.poll_once(0)
        p.queue = [(w._names["game-abcdef"], select.POLLPRI)]
        w.poll_once(0)
        assert any("on_trip failed" in l for l in logs) and w.watching() == ["game-abcdef"]
    finally:
        w.stop()


def test_add_explains_a_missing_pressure_file(watcher):
    with pytest.raises(PsiError, match="psi=1"):
        watcher.add("nosuch-abcdef", DEFAULT_TRIGGER)


def test_add_explains_a_refused_trigger(watcher, monkeypatch):
    real = psi.os.write

    def write(fd, data):
        if fd == watcher._wake_w:
            return real(fd, data)
        raise OSError(22, "Invalid argument")
    monkeypatch.setattr(psi.os, "write", write)
    with pytest.raises(PsiError, match="refused the pressure trigger"):
        watcher.add("game-abcdef", DEFAULT_TRIGGER)
    monkeypatch.setattr(psi.os, "write", real)
    watcher.poll_once(0)
    assert watcher.watching() == []


def test_stop_closes_everything(tree):
    p = ScriptedPoll()
    w = PressureWatcher(tree, on_trip=lambda n, s: None, poller=lambda: p)
    w.add("game-abcdef", DEFAULT_TRIGGER)
    w.poll_once(0)
    fd = w._names["game-abcdef"]
    w.stop()
    with pytest.raises(OSError):
        os.fstat(fd)


# ---------------------------------------------------------------- launch + feed

import grp

GROUP = grp.getgrgid(os.getgid()).gr_name


class FakePsi:
    def __init__(self, refuse=None):
        self.added, self.refuse = [], refuse

    def add(self, name, trigger):
        if self.refuse:
            raise PsiError(self.refuse)
        self.added.append((name, trigger))


@pytest.fixture
def hub_world(tmp_path, monkeypatch):
    monkeypatch.setattr(uihub, "HEARTBEAT_S", 0.3)
    root = tmp_path / "cg"
    root.mkdir()
    cg = CgroupRoot(str(root))
    scopes = Scopes(cg)
    run = tmp_path / "run"
    run.mkdir(mode=0o755)
    made = {}

    def make(psi_obj=FakePsi()):
        clock = [100.0]
        logs = []
        h = Hub(str(run / f"ui{len(made)}.sock"), group=GROUP, tasks=uihub.cgroup_tasks(cg, None), scopes=scopes,
                psi=psi_obj, log=logs.append, clock=lambda: clock[0])
        h.clock_ref, h.logs = clock, logs
        h.start()
        made[len(made)] = h
        return h
    yield make, cg, scopes
    for h in made.values():
        h.stop()


from cora_sentinel.uihub import Hub


def ask(hub, **msg):
    s = socket.socket(socket.AF_UNIX)
    s.connect(str(hub.path))
    s.settimeout(5)
    f = s.makefile("rb")
    s.sendall((json.dumps(dict(msg, id="t")) + "\n").encode())
    while True:
        m = json.loads(f.readline())
        if m.get("type") == "result":
            s.close()
            return m


def test_launch_arms_the_default_tripwire(hub_world):
    make, _, scopes = hub_world
    fake = FakePsi()
    h = make(fake)
    r = ask(h, cmd="launch", app="game")
    assert r["ok"] and r["psi_memory"] == DEFAULT_TRIGGER and r["psi_error"] is None
    assert fake.added == [(r["scope"], DEFAULT_TRIGGER)]
    assert scopes.owned[r["scope"]]["psi_memory"] == DEFAULT_TRIGGER                 # re-armed after a restart


def test_launch_with_a_custom_or_no_tripwire(hub_world):
    make, _, _ = hub_world
    fake = FakePsi()
    h = make(fake)
    assert ask(h, cmd="launch", app="a", psi_memory="full 50000 2000000")["psi_memory"] == "full 50000 2000000"
    time.sleep(1.05)
    r = ask(h, cmd="launch", app="b", psi_memory="off")
    assert r["ok"] and r["psi_memory"] is None and [t for _, t in fake.added] == ["full 50000 2000000"]


def test_a_bad_tripwire_is_refused_before_anything_is_made(hub_world):
    make, cg, _ = hub_world
    h = make()
    r = ask(h, cmd="launch", app="game", psi_memory="some 9 9")
    assert not r["ok"] and "500000 to 10000000" in r["error"] and list(cg.root.iterdir()) == []


def test_a_refused_tripwire_fails_open_and_says_so(hub_world):
    """Signal only: losing it changes what you are TOLD, not what is enforced. The ceiling still fails closed."""
    make, _, scopes = hub_world
    h = make(FakePsi(refuse="the kernel refused the pressure trigger: Operation not supported"))
    r = ask(h, cmd="launch", app="game", memory_max="1G")
    assert r["ok"] and r["psi_memory"] is None and "Operation not supported" in r["psi_error"]
    assert any("pressure UNAVAILABLE" in l for l in h.logs) and scopes.owned[r["scope"]]["entered"]


def test_no_watcher_is_reported_too(hub_world):
    make, _, _ = hub_world
    r = ask(make(None), cmd="launch", app="game")
    assert r["ok"] and "unavailable" in r["psi_error"]


def test_a_trip_turns_the_feed_amber_then_clears(hub_world):
    make, cg, _ = hub_world
    h = make()
    r = ask(h, cmd="launch", app="game")
    h.note_pressure(r["scope"], read_pressure(KERNEL_TEXT))
    snap = h.snapshot()
    t = next(t for t in snap["tasks"] if t["name"] == r["scope"])
    assert snap["status"] == "pressure" and t["pressure"]["active"] and t["pressure"]["some_avg10"] == 12.34
    assert any("signal only, nothing was changed" in l for l in h.logs)
    from cora_sentinel.uiclient import StatusClient
    c = StatusClient("/x")
    c.sock, c.last_rx, c.clock, c.state = object(), 0.0, (lambda: 0.0), snap
    v = c.view()
    assert v["colour"] == "amber" and r["scope"] in v["title"] and "[PRESSURE some 12.34%]" in v["tasks"][0]["line"]
    h.clock_ref[0] += uihub.PRESSURE_HOLD_S + 1
    snap = h.snapshot()
    assert snap["status"] == "clear" and next(t for t in snap["tasks"] if t["name"] == r["scope"])["pressure"]["active"] is False


def test_containment_and_alarm_outrank_pressure(hub_world):
    make, cg, _ = hub_world
    h = make()
    r = ask(h, cmd="launch", app="game")
    h.note_pressure(r["scope"], {})
    assert h.snapshot()["status"] == "pressure"
    (cg.root / r["scope"] / "cpu.max").write_text("20000 100000\n")   # THROTTLE really in force (kernel truth)
    assert h.snapshot()["status"] == "contained"
    h.note_decision({"final": "DROPPED", "action": "dropped:queue-full", "queue_dropped": True})
    assert h.snapshot()["status"] == "alarm"


def test_a_scope_that_ends_forgets_its_pressure(hub_world):
    make, cg, _ = hub_world
    h = make()
    r = ask(h, cmd="launch", app="game")
    h.note_pressure(r["scope"], {})
    import shutil
    shutil.rmtree(cg.root / r["scope"])
    h.snapshot()
    assert r["scope"] not in h._pressure


def test_cora_run_passes_the_flag_and_warns_when_it_was_refused(hub_world, monkeypatch, capsys):
    from cora_sentinel import run
    make, _, _ = hub_world
    h = make(FakePsi(refuse="no PSI here"))
    monkeypatch.delenv("SUDO_UID", raising=False)
    started = []
    monkeypatch.setattr(run.os, "execvp", lambda f, a: started.append(a))
    monkeypatch.setattr(run, "in_scope", lambda s: bool(s))
    monkeypatch.setattr("sys.argv", ["cora-run", "--app", "game", "--psi-memory", "some 50000 1000000",
                                     "--socket", str(h.path), "true"])
    run.main()
    err = capsys.readouterr().err
    assert started == [["true"]] and "WARNING: no pressure tripwire: no PSI here" in err


# ---------------------------------------------------------------- the real kernel

def _real():
    if os.geteuid() != 0 or not os.path.isfile("/sys/fs/cgroup/cgroup.controllers"):
        return None
    try:
        p = f"/sys/fs/cgroup/cora-psi-probe-{os.getpid()}"
        os.mkdir(p)
        ok = os.path.exists(f"{p}/memory.pressure") or os.path.exists("/proc/pressure/memory")
        os.rmdir(p)
        return ok or None
    except OSError:
        return None


@pytest.mark.skipif(_real() is None, reason="needs root, a writable cgroup v2 tree and PSI")
def test_real_kernel_pressure_trips_the_wire():
    root = CgroupRoot(f"/sys/fs/cgroup/cora-psitest-{os.getpid()}", "/sys/fs/cgroup")
    if "memory" not in root.ensure(("memory",)):
        os.rmdir(root.root)
        pytest.skip("the memory controller cannot be enabled here")
    trips = []
    w = PressureWatcher(root, on_trip=lambda n, s: trips.append((n, s)))
    s = Scopes(root)
    p = None
    try:
        name = s.create_scope("psitest", uid=0, memory_max="512M", memory_high="64M")
        w.add(name, "some 50000 1000000")                          # 50 ms of stall in any 1 s
        w.start()
        hog = ("import time\nb=[]\nfor _ in range(40):\n    b.append(bytearray(8<<20))\n"
               "    for i in range(0,len(b[-1]),4096): b[-1][i]=1\ntime.sleep(5)\n")
        p = subprocess.Popen([sys.executable, "-c", hog])
        s.enter(name, pid=p.pid, uid=0)
        end = time.monotonic() + 20
        while not trips and time.monotonic() < end:
            time.sleep(0.1)
        assert trips and trips[0][0] == name, "320 MiB squeezed under memory.high=64M should stall on memory"
    finally:
        if p:
            p.kill(); p.wait()
        w.stop()
        for d in sorted(root.root.glob("*"), reverse=True):
            try:
                os.rmdir(d)
            except OSError:
                pass
        try:
            os.rmdir(root.root)
        except OSError:
            pass


# ---------------------------------------------------------------- armed / refused: what the feed may claim
def refuse_writes(monkeypatch, watcher, errno_=22):
    real = psi.os.write

    def write(fd, data):
        if fd == watcher._wake_w:
            return real(fd, data)
        raise OSError(errno_, os.strerror(errno_))
    monkeypatch.setattr(psi.os, "write", write)
    return real


def test_a_trigger_is_armed_only_once_the_kernel_accepted_it(watcher):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    assert watcher.armed() == {"game-abcdef": DEFAULT_TRIGGER} and watcher.refused() == set()


def test_a_trigger_the_kernel_refuses_is_refused_and_never_armed(watcher, monkeypatch):
    """The mutant 'record the trigger before the kernel write' fails here."""
    refuse_writes(monkeypatch, watcher)
    with pytest.raises(PsiError):
        watcher.add("game-abcdef", DEFAULT_TRIGGER)
    assert watcher.armed() == {} and watcher.refused() == {"game-abcdef"}


def test_a_missing_pressure_file_is_refused_too(watcher):
    with pytest.raises(PsiError):
        watcher.add("nosuch-abcdef", DEFAULT_TRIGGER)
    assert watcher.refused() == {"nosuch-abcdef"} and watcher.armed() == {}


def test_armed_and_refused_return_copies(watcher, monkeypatch):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    a = watcher.armed()
    a.clear()
    a["evil"] = "some 1 500000"
    assert watcher.armed() == {"game-abcdef": DEFAULT_TRIGGER}
    refuse_writes(monkeypatch, watcher)
    with pytest.raises(PsiError):
        watcher.add("game-abcdef", DEFAULT_TRIGGER)
    r = watcher.refused()
    r.clear()
    assert watcher.refused() == {"game-abcdef"}


def test_remove_cleans_both(watcher, monkeypatch):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.remove("game-abcdef")
    assert watcher.armed() == {} and watcher.refused() == set()
    refuse_writes(monkeypatch, watcher)
    with pytest.raises(PsiError):
        watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.remove("game-abcdef")
    assert watcher.refused() == set()


def test_a_refused_re_add_does_not_leave_the_old_trigger_claimed_and_a_good_one_clears_the_refusal(watcher, monkeypatch):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    real = refuse_writes(monkeypatch, watcher)
    with pytest.raises(PsiError):
        watcher.add("game-abcdef", "some 300000 2000000")
    assert watcher.armed() == {} and watcher.refused() == {"game-abcdef"}
    monkeypatch.setattr(psi.os, "write", real)
    watcher.add("game-abcdef", "some 300000 2000000")
    assert watcher.armed() == {"game-abcdef": "some 300000 2000000"} and watcher.refused() == set()


def test_a_vanished_cgroup_is_no_longer_armed(watcher):
    watcher.add("game-abcdef", DEFAULT_TRIGGER)
    watcher.poll_once(0)
    fd = watcher._names["game-abcdef"]
    watcher.p.queue.append((fd, select.POLLERR))
    watcher.poll_once(0)
    assert watcher.armed() == {}


@pytest.mark.parametrize("trigger, want", [
    ("some 150000 1000000", {"kind": "some", "stall_us": 150000, "window_us": 1000000, "fraction": 0.15,
                             "trigger": "some 150000 1000000"}),
    ("full 300000 2000000", {"kind": "full", "stall_us": 300000, "window_us": 2000000, "fraction": 0.15,
                             "trigger": "full 300000 2000000"}),
    (None, None), ("", None), ("garbage", None),
])
def test_threshold(trigger, want):
    assert psi.threshold(trigger) == want


@pytest.mark.parametrize("kernel_says", ["yes", "no"])
def test_a_snapshot_taken_while_the_kernel_decides_never_sees_the_trigger_armed(watcher, monkeypatch, kernel_says):
    """The hub snapshots from another thread. Recording the trigger before the kernel write (then undoing it on a
    refusal) would show a tripwire as armed that the kernel is about to refuse: observe armed() DURING the write."""
    real = psi.os.write
    seen = []

    def write(fd, data):
        if fd == watcher._wake_w:
            return real(fd, data)
        seen.append(dict(watcher.armed()))                       # what a concurrent snapshot would read right now
        if kernel_says == "no":
            raise OSError(22, "Invalid argument")
        return real(fd, data)
    monkeypatch.setattr(psi.os, "write", write)
    try:
        watcher.add("game-abcdef", DEFAULT_TRIGGER)
    except PsiError:
        pass
    assert seen == [{}]
    assert watcher.armed() == ({"game-abcdef": DEFAULT_TRIGGER} if kernel_says == "yes" else {})


def test_a_refused_trigger_heals_without_a_restart_when_retried(watcher, monkeypatch):
    real = refuse_writes(monkeypatch, watcher)
    with pytest.raises(PsiError):
        watcher.add("game-abcdef", DEFAULT_TRIGGER)
    want = {"game-abcdef": DEFAULT_TRIGGER, "gone-abcdef": None}
    assert psi.retry_refused(watcher, want.get) == [] and watcher.refused() == {"game-abcdef"}   # still refused
    monkeypatch.setattr(psi.os, "write", real)                             # e.g. cgroup.pressure back to 1
    assert psi.retry_refused(watcher, want.get) == ["game-abcdef"]
    assert watcher.armed() == {"game-abcdef": DEFAULT_TRIGGER} and watcher.refused() == set()


def test_retry_skips_scopes_that_are_gone_or_launched_with_off(watcher):
    with pytest.raises(PsiError):
        watcher.add("nosuch-abcdef", DEFAULT_TRIGGER)
    calls = []
    assert psi.retry_refused(watcher, lambda n: calls.append(n)) == [] and calls == ["nosuch-abcdef"]
    assert watcher.refused() == {"nosuch-abcdef"}                          # untouched: nothing to arm


def test_the_daemon_retries_refused_tripwires_on_its_reaper_tick():
    src = (__import__("pathlib").Path(psi.__file__).parent / "daemon.py").read_text()
    reap = src[src.index("for name in scopes.reap():"):]
    assert "retry_refused(psi, lambda n: (scopes.describe(n) or {}).get(\"psi_memory\"))" in reap[:900]


def test_retry_skips_a_live_scope_that_no_longer_wants_a_trigger(watcher, monkeypatch):
    real = refuse_writes(monkeypatch, watcher)
    with pytest.raises(PsiError):
        watcher.add("game-abcdef", DEFAULT_TRIGGER)                       # the cgroup exists; the write was refused
    monkeypatch.setattr(psi.os, "write", real)
    assert psi.retry_refused(watcher, lambda n: None) == []               # no crash, nothing armed
    assert watcher.armed() == {} and watcher.refused() == {"game-abcdef"}
