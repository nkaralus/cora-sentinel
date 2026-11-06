"""Helpers for the real-kernel tap tests (test_sockdiag.py, test_nflog.py).

The sock_diag destroy-event stream is HOST-WIDE by design: it audits every TCP socket on the machine and carries no cgroup id.
A "slip" is therefore any blocklisted destination a socket closed on without being attributed, whoever owned that socket. These
tests blocklist the host's own LAN address, so anything else on the host that talks to that address while a test runs
(a browser, a monitoring agent, another daemon) is counted too. Per-task counters (syn, udp, live_hits) are not affected: the
tap matches on the task's cgroup and live hits require a task's cgroup id.

So an assertion about the test's own traffic must be scoped to the test's own flow, which is what `watch_slips` gives:
slips by remote port, and every test listens on its own ephemeral port.

CORA_TEST_AMBIENT=1 turns on deliberate noise (a non-task process connecting to the blocklisted address all the time) so the
scoping can be shown to hold, and so a regression to a global assertion fails at once instead of once a month.
"""
from __future__ import annotations

import collections
import os
import socket
import threading
import time
from typing import Optional


def watch_slips(nm) -> collections.Counter:
    """Count slips by remote port, at the call, before the monitor's per-destination logging rate limit.
    The monitor's own `stats["slips"]` stays host-wide; use this one for assertions about a test's own listener."""
    tally: collections.Counter = collections.Counter()
    orig = nm._log_slip

    def spy(rec: dict, key: tuple) -> None:
        tally[rec.get("remote_port")] += 1
        return orig(rec, key)
    nm._log_slip = spy
    return tally


class AmbientNoise:
    """Connections to `ip` from a process that is not a task, at about 100 a second, for as long as it runs."""

    def __init__(self, ip: str):
        self.lis = socket.socket()
        self.lis.bind((ip, 0))
        self.lis.listen(256)
        self.lis.settimeout(0.05)
        self.ip, self.port, self.made = ip, self.lis.getsockname()[1], 0
        self._stop = threading.Event()
        self._threads = [threading.Thread(target=self._drain, daemon=True), threading.Thread(target=self._hammer, daemon=True)]

    def _drain(self) -> None:
        while not self._stop.is_set():
            try:
                self.lis.accept()[0].close()
            except (socket.timeout, OSError):
                pass

    def _hammer(self) -> None:
        while not self._stop.is_set():
            try:
                socket.create_connection((self.ip, self.port), timeout=1).close()
                self.made += 1
            except OSError:
                pass
            time.sleep(0.01)

    def start(self) -> "AmbientNoise":
        for t in self._threads:
            t.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(2)
        self.lis.close()


def maybe_noise(ip: str) -> Optional[AmbientNoise]:
    return AmbientNoise(ip).start() if os.environ.get("CORA_TEST_AMBIENT") else None
