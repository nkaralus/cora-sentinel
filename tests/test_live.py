"""The helpers that keep the live sentinel tests from depending on how fast the machine starts an interpreter.
No kernel, no root (loopback only). Run: pytest -q tests/test_live.py"""
import inspect
import socket
import time

import pytest

import _live
import test_blocklist
import test_net


def listener():
    lis = socket.socket()
    lis.bind(("127.0.0.1", 0))
    lis.listen(4)
    lis.settimeout(5)
    return lis, lis.getsockname()[1]


def test_spawn_connector_returns_only_after_the_child_has_connected():
    lis, port = listener()
    p = _live.spawn_connector("127.0.0.1", port, "CORA_TEST_MARK", hold=10)
    try:
        assert p.poll() is None
        conn, _ = lis.accept()                                 # it really did connect before we were handed it
        conn.close()
        assert "CORA_TEST_MARK" in open(f"/proc/{p.pid}/cmdline").read()      # and the marker is in its argv
    finally:
        p.kill(); p.wait(); lis.close()


def test_the_slow_start_switch_delays_the_connect_and_the_helper_still_waits_for_it(monkeypatch):
    monkeypatch.setenv("CORA_TEST_SLOW_START", "1.2")
    lis, port = listener()
    t0 = time.monotonic()
    p = _live.spawn_connector("127.0.0.1", port, "CORA_TEST_MARK", hold=10)
    try:
        assert time.monotonic() - t0 >= 1.2 and p.poll() is None
    finally:
        p.kill(); p.wait(); lis.close()


def test_a_child_that_cannot_connect_fails_the_test_at_setup_with_a_clear_message():
    lis, port = listener()
    lis.close()                                                # nothing is listening: the child gets ConnectionRefused and exits
    with pytest.raises(pytest.fail.Exception, match="never connected"):
        _live.spawn_connector("127.0.0.1", port, "CORA_TEST_MARK", ready_timeout=10)


def test_a_child_that_is_too_slow_is_killed_and_reported_not_left_running(monkeypatch):
    monkeypatch.setenv("CORA_TEST_SLOW_START", "5")
    made, real = [], _live.subprocess.Popen
    monkeypatch.setattr(_live.subprocess, "Popen", lambda *a, **k: made.append(real(*a, **k)) or made[-1])     # keep the child it makes
    lis, port = listener()
    t0 = time.monotonic()
    with pytest.raises(pytest.fail.Exception, match="within 0.5s"):
        _live.spawn_connector("127.0.0.1", port, "CORA_TEST_SLOW_KILLED", ready_timeout=0.5)
    assert time.monotonic() - t0 < 5
    assert len(made) == 1 and made[0].poll() is not None, "the child must be dead (and reaped) when the helper gives up"
    lis.close()


class FakeSentinel:
    def __init__(self, script):
        self.script, self.events = list(script), []

    def tick(self):
        if self.script:
            self.events.append({"anomaly": {"kind": self.script.pop(0)}})


def test_tick_until_waits_for_the_kind_asked_for_not_just_any_event():
    s = FakeSentinel(["path_violation", "memory_spike", "unauthorized_connection"])
    got = _live.tick_until(s, s.events, "unauthorized_connection", timeout=5, step=0.01)
    assert [e["anomaly"]["kind"] for e in got] == ["unauthorized_connection"] and len(s.events) == 3


def test_tick_until_gives_up_after_the_timeout_and_returns_nothing_of_that_kind():
    s = FakeSentinel(["path_violation"])
    t0 = time.monotonic()
    assert _live.tick_until(s, s.events, "unauthorized_connection", timeout=0.3, step=0.05) == []
    assert 0.25 <= time.monotonic() - t0 < 2


def test_the_two_live_tests_wait_for_the_child_before_they_start_the_clock():
    for fn in (test_net.test_live_outbound_flagged, test_blocklist.test_live_listed_address_trips_even_when_allowlisted):
        src = inspect.getsource(fn)
        assert "spawn_connector" in src and "tick_until" in src, fn.__name__
        assert "monotonic() + 5" not in src, f"{fn.__name__} is back to a fixed 5 s window that includes the child's start-up"
