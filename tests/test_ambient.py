"""The helpers the real-kernel tap tests use to stay correct on a busy host. No kernel, no root.
Run: pytest -q tests/test_ambient.py"""
import socket
import threading
import time

import pytest

import _ambient


class FakeMonitor:
    """Just enough of NetMonitor: a _log_slip that rate-limits, like the real one."""

    def __init__(self):
        self.logged = []
        self._seen = {}

    def _log_slip(self, rec, key):
        if key in self._seen:                                   # the real method drops repeats of a destination
            return None
        self._seen[key] = True
        self.logged.append((rec, key))


def test_watch_slips_counts_by_remote_port_and_still_calls_the_original():
    nm = FakeMonitor()
    tally = _ambient.watch_slips(nm)
    nm._log_slip({"remote_port": 4000}, ("10.0.0.1", 4000))
    nm._log_slip({"remote_port": 5000}, ("10.0.0.1", 5000))
    assert tally == {4000: 1, 5000: 1}
    assert [k for _, k in nm.logged] == [("10.0.0.1", 4000), ("10.0.0.1", 5000)]


def test_watch_slips_counts_every_call_even_when_the_monitor_rate_limits_its_logging():
    nm = FakeMonitor()
    tally = _ambient.watch_slips(nm)
    for _ in range(60):
        nm._log_slip({"remote_port": 4000}, ("10.0.0.1", 4000))     # the burst test's 60 connections to one destination
    assert tally[4000] == 60 and len(nm.logged) == 1                # logging was limited; the count was not


def test_a_port_nobody_used_reads_zero():
    nm = FakeMonitor()
    tally = _ambient.watch_slips(nm)
    nm._log_slip({"remote_port": 1}, ("x", 1))
    assert tally[99999] == 0


def test_the_noise_makes_connections_from_outside_any_task_and_stops_cleanly():
    n = _ambient.AmbientNoise("127.0.0.1").start()
    try:
        deadline = time.time() + 5
        while n.made < 20 and time.time() < deadline:
            time.sleep(0.05)
        assert n.made >= 20 and n.port > 0
    finally:
        n.stop()
    assert not any(t.is_alive() for t in n._threads)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", n.port), timeout=0.5)       # the listener is closed


def test_noise_is_off_unless_asked_for(monkeypatch):
    monkeypatch.delenv("CORA_TEST_AMBIENT", raising=False)
    assert _ambient.maybe_noise("127.0.0.1") is None
    monkeypatch.setenv("CORA_TEST_AMBIENT", "1")
    n = _ambient.maybe_noise("127.0.0.1")
    try:
        assert isinstance(n, _ambient.AmbientNoise)
    finally:
        n.stop()


def test_the_two_tap_test_files_scope_their_slip_assertions():
    """A regression guard on the tests themselves: a global `nm.stats["slips"]` assertion is the flake this module exists to prevent."""
    import re
    from pathlib import Path
    here = Path(__file__).parent
    for name in ("test_sockdiag.py", "test_nflog.py"):
        text = (here / name).read_text()
        bad = [l.strip() for l in text.splitlines()
               if re.search(r'assert .*stats\["slips"\]', l) and "slips_by_port" not in l]       # comparing it WITH a scoped count is fine
        assert bad == [], f"{name} asserts on the host-wide slip counter: {bad}"
