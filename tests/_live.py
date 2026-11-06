"""Helpers for tests that start a child process and wait for the sentinel to notice it.

A test that starts a child and then polls for "at most 5 seconds" is measuring the wrong thing: the window also has to cover
the child's interpreter start-up and its connect, which a loaded shared runner can stretch past the deadline (two such tests
failed once each, on a busy workstation and on a hosted runner, and passed when run alone). So the child says `ready` once it
has connected, the caller waits for that, and only then does the polling window start: it measures detection latency and
nothing else.

CORA_TEST_SLOW_START=<seconds> makes the child wait that long before it connects, to pretend the machine is slow:
    CORA_TEST_SLOW_START=7 python -m pytest -q tests/test_net.py tests/test_blocklist.py
"""
from __future__ import annotations

import os
import select
import subprocess
import sys
import time
from typing import List

import pytest


def spawn_connector(host: str, port: int, marker: str, hold: float = 30.0, ready_timeout: float = 60.0) -> subprocess.Popen:
    """A child (its argv carries `marker`) that connects to (host, port), says `ready`, and holds the connection open.
    Returns once it has said so. If it never does, the test FAILS HERE with a setup message, not later with a detection failure."""
    delay = float(os.environ.get("CORA_TEST_SLOW_START", "0") or 0)
    code = (f"import socket,sys,time;time.sleep({delay!r});c=socket.create_connection(({host!r},{port!r}));"
            f"print('ready',flush=True);time.sleep({hold!r})")
    p = subprocess.Popen([sys.executable, "-c", code, marker], stdout=subprocess.PIPE, text=True)
    readable, _, _ = select.select([p.stdout], [], [], ready_timeout)
    if not readable or p.stdout.readline().strip() != "ready":
        p.kill()
        p.wait()
        pytest.fail(f"the child never connected to {host}:{port} within {ready_timeout:g}s "
                    f"(a test-setup problem, not a detection failure)")
    return p


def tick_until(sentinel, events: list, kind: str, timeout: float = 10.0, step: float = 0.1) -> List[dict]:
    """Tick `sentinel` until an event of `kind` has arrived (an event of another kind does not end the wait) and return the
    events of that kind. The timeout counts from NOW, after the child is already connected."""
    end = time.monotonic() + timeout
    while True:
        sentinel.tick()
        got = [e for e in events if e["anomaly"]["kind"] == kind]
        if got or time.monotonic() >= end:
            return got
        time.sleep(step)
