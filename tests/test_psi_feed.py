"""Continuous memory pressure on the status feed: every update carries each task's PSI, not only a tripwire's
moment. The harness computes exact stall over its VERIFY window from two updates' total_us and mono."""
import json
import os
import socket

import pytest

from cora_sentinel import uihub
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.psi import read_pressure
from cora_sentinel.uihub import Hub, cgroup_tasks


def kernel(some_avg10=0.0, some_total=0, full_avg10=0.0, full_total=0):
    return (f"some avg10={some_avg10:.2f} avg60=0.00 avg300=0.00 total={some_total}\n"
            f"full avg10={full_avg10:.2f} avg60=0.00 avg300=0.00 total={full_total}\n")


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "cora"
    for n in ("minecraft-1a2b3c", "build"):
        (root / n).mkdir(parents=True)
        (root / n / "memory.current").write_text("1000\n")
    (root / "minecraft-1a2b3c" / "memory.pressure").write_text(kernel(1.5, 2_000_000, 0.5, 400_000))
    (root / "build" / "memory.pressure").write_text(kernel())
    return CgroupRoot(str(root))


def task(snap, name):
    return next(t for t in snap["tasks"] if t["name"] == name)


def hub(tmp_path, cg):
    run = tmp_path / "run"
    run.mkdir(exist_ok=True)
    return Hub(str(run / "ui.sock"), tasks=cgroup_tasks(cg, None), log=lambda m: None)


# ---------------------------------------------------------------- the parser

def test_totals_are_opt_in_and_integers():
    t = kernel(1.5, 2_000_000, 0.5, 400_000)
    assert "some_total_us" not in read_pressure(t)                              # the tripwire path is unchanged
    p = read_pressure(t, totals=True)
    assert p["some_total_us"] == 2_000_000 and isinstance(p["some_total_us"], int) and p["full_total_us"] == 400_000
    assert p["some_avg10"] == 1.5 and p["full_avg10"] == 0.5


def test_a_garbled_total_is_dropped_not_guessed():
    assert "some_total_us" not in read_pressure("some avg10=1.0 avg60=0 total=lots\n", totals=True)


# ---------------------------------------------------------------- every task, every update

def test_every_task_carries_its_pressure(tmp_path, tree):
    s = hub(tmp_path, tree).snapshot()
    mc = task(s, "minecraft-1a2b3c")["psi"]
    assert mc["some_avg10"] == 1.5 and mc["some_total_us"] == 2_000_000 and mc["full_total_us"] == 400_000
    assert task(s, "build")["psi"]["some_avg10"] == 0.0                        # agent tasks too


def test_pressure_is_read_fresh_on_each_update_without_any_trip(tmp_path, tree):
    h = hub(tmp_path, tree)
    assert task(h.snapshot(), "minecraft-1a2b3c")["psi"]["some_avg10"] == 1.5
    (tree.root / "minecraft-1a2b3c" / "memory.pressure").write_text(kernel(7.25, 9_000_000))
    assert task(h.snapshot(), "minecraft-1a2b3c")["psi"]["some_avg10"] == 7.25
    assert "pressure" not in task(h.snapshot(), "minecraft-1a2b3c")            # no tripwire was involved


def test_no_psi_is_none_not_zero(tmp_path, tree):
    """'Not measured' must never read as 'no pressure': a harness would take 0% as a pass."""
    (tree.root / "build" / "memory.pressure").unlink()
    (tree.root / "minecraft-1a2b3c" / "memory.pressure").write_text("garbage\n")
    s = hub(tmp_path, tree).snapshot()
    assert task(s, "build")["psi"] is None and task(s, "minecraft-1a2b3c")["psi"] is None


def test_exact_stall_over_a_window_from_two_updates(tmp_path, tree, monkeypatch):
    """The VERIFY computation: (total_b - total_a) / (mono_b - mono_a) / 1e6."""
    h = hub(tmp_path, tree)
    clock = [500.0]
    monkeypatch.setattr(uihub.time, "monotonic", lambda: clock[0])
    a = h.snapshot()
    clock[0] += 60.0                                                            # a 60 s VERIFY window
    (tree.root / "minecraft-1a2b3c" / "memory.pressure").write_text(kernel(4.0, 2_000_000 + 1_800_000))
    b = h.snapshot()
    ta, tb = task(a, "minecraft-1a2b3c")["psi"], task(b, "minecraft-1a2b3c")["psi"]
    frac = (tb["some_total_us"] - ta["some_total_us"]) / ((b["mono"] - a["mono"]) * 1e6)
    assert b["mono"] - a["mono"] == 60.0 and frac == pytest.approx(0.03)        # 1.8 s stalled in 60 s = 3%


def test_mono_is_the_daemons_monotonic_clock(tmp_path, tree):
    h = hub(tmp_path, tree)
    a, b = h.snapshot()["mono"], h.snapshot()["mono"]
    assert isinstance(a, float) and b >= a


def test_the_feed_on_the_socket_carries_it(tmp_path, tree):
    h = hub(tmp_path, tree)
    h.start()
    try:
        s = socket.socket(socket.AF_UNIX)
        s.connect(str(h.path))
        s.settimeout(5)
        msg = json.loads(s.makefile("rb").readline())
        assert "mono" in msg and task(msg, "minecraft-1a2b3c")["psi"]["some_total_us"] == 2_000_000
        s.close()
    finally:
        h.stop()
