"""The `launch` command: the daemon makes an ephemeral scope and moves THE CALLER (its SO_PEERCRED pid) into it.
Real socket, real Scopes over a temp tree; the test process itself is the launcher."""
import grp
import json
import os
import socket
import time

import pytest

from cora_sentinel import uihub
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.scope import Scopes
from cora_sentinel.uiclient import StatusClient
from cora_sentinel.uihub import Hub, cgroup_tasks

GiB = 1 << 30
RUNNER_GROUP = grp.getgrgid(os.getgid()).gr_name


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(uihub, "HEARTBEAT_S", 0.3)
    monkeypatch.setattr(uihub, "MIN_INTERVAL_S", 0.05)


@pytest.fixture
def world(tmp_path):
    root = tmp_path / "cora"
    root.mkdir()
    cg = CgroupRoot(str(root))
    scopes = Scopes(cg, state_path=str(tmp_path / "scopes.json"))
    run = tmp_path / "run"
    run.mkdir(mode=0o755)
    logs = []
    h = Hub(str(run / "ui.sock"), group=RUNNER_GROUP, tasks=cgroup_tasks(cg, None), cgroup_id=cg.cgroup_id,
            scopes=scopes, log=logs.append)
    h.logs = logs
    h.start()
    yield h, cg, scopes
    h.stop()


class Conn:
    def __init__(self, hub):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(str(hub.path))
        self.s.settimeout(5)
        self.f = self.s.makefile("rb")

    def ask(self, tag="a", **msg):
        self.s.sendall((json.dumps(dict(msg, id=tag)) + "\n").encode())
        end = time.monotonic() + 5
        while time.monotonic() < end:
            m = json.loads(self.f.readline())
            if m.get("type") == "result" and m.get("id") == tag:
                return m
        raise AssertionError("no result")


def launch(c, tag="a", **kw):
    return c.ask(tag, cmd="launch", **{"app": "steam-570", **kw})


# ---------------------------------------------------------------- the path that works

def test_launch_moves_the_caller_into_a_new_capped_scope(world):
    hub, cg, scopes = world
    r = launch(Conn(hub), memory_max="8G", memory_high="7G")
    assert r["ok"] and r["scope"].startswith("steam-570-") and len(r["scope"]) == len("steam-570-") + 6
    assert r["memory_max"] == 8 * GiB and r["memory_high"] == 7 * GiB
    d = cg.root / r["scope"]
    assert (d / "cgroup.procs").read_text() == str(os.getpid())          # the CALLER, from SO_PEERCRED
    assert (d / "memory.max").read_text() == str(8 * GiB)
    rec = scopes.describe(r["scope"])
    assert rec["entered"] and rec["uid"] == os.getuid()
    assert any(f"launched pid {os.getpid()} into {r['scope']}" in l for l in hub.logs)


def test_a_pid_in_the_request_is_ignored(world):
    hub, cg, _ = world
    r = launch(Conn(hub), pid=1)
    assert r["ok"] and (cg.root / r["scope"] / "cgroup.procs").read_text() == str(os.getpid())


def test_each_launch_gets_its_own_scope(world):
    hub, _, _ = world
    a = launch(Conn(hub), tag="a")
    b = launch(Conn(hub), tag="b")                                       # another connection: its own rate limit
    assert a["ok"] and b["ok"] and a["scope"] != b["scope"]


def test_the_feed_shows_the_scope_and_its_ceiling(world):
    hub, _, _ = world
    r = launch(Conn(hub), memory_max="8G")
    t = next(t for t in hub.snapshot()["tasks"] if t["name"] == r["scope"])
    assert t["scope"] == {"app": "steam-570", "uid": os.getuid(), "profile": "app", "memory_max": 8 * GiB,
                          "memory_high": None}
    c = StatusClient("/x")
    c.sock, c.last_rx, c.clock = object(), 0.0, (lambda: 0.0)
    c.state = hub.snapshot()
    line = next(x["line"] for x in c.view()["tasks"] if x["name"] == r["scope"])
    assert " / 8.0 GiB" in line


# ---------------------------------------------------------------- what is refused

def test_a_non_member_cannot_launch(world, monkeypatch):
    hub, cg, _ = world
    monkeypatch.setattr(uihub, "peer_uid", lambda conn: 65534)
    r = launch(Conn(hub))
    assert not r["ok"] and "not in the --ui-group" in r["error"]
    assert list(cg.root.iterdir()) == []


def test_without_cgroups_launch_is_unavailable(tmp_path):
    run = tmp_path / "run"
    run.mkdir(mode=0o755)
    h = Hub(str(run / "ui.sock"), group=RUNNER_GROUP, log=lambda m: None)
    h.start()
    try:
        r = launch(Conn(h))
        assert not r["ok"] and "without --cgroup-root" in r["error"]
    finally:
        h.stop()


@pytest.mark.parametrize("kw,why", [
    ({"app": "../etc"}, "bad app name"),
    ({"app": "Steam"}, "bad app name"),
    ({"memory_max": "4G", "memory_high": "6G"}, "must not exceed"),
    ({"memory_max": "1M"}, "floor"),
    ({"memory_max": "lots"}, "not a size"),
])
def test_bad_requests_are_refused_and_make_nothing(world, kw, why):
    hub, cg, _ = world
    r = launch(Conn(hub), **kw)
    assert not r["ok"] and why in r["error"]
    assert list(cg.root.iterdir()) == []


def test_a_reused_pid_is_never_moved(world, monkeypatch):
    """The launcher that connected is gone and its pid now names another process: nothing is moved."""
    hub, cg, _ = world
    c = Conn(hub)
    time.sleep(0.2)                                                      # accepted, its start time recorded
    real = uihub.proc_starttime
    monkeypatch.setattr(uihub, "proc_starttime", lambda pid: (real(pid) or 0) + 1)
    r = launch(c)
    assert not r["ok"] and "no longer the same process" in r["error"]
    assert list(cg.root.iterdir()) == []


def test_one_launch_per_second_per_connection(world):
    hub, _, _ = world
    c = Conn(hub)
    assert launch(c, tag="a")["ok"]
    r = launch(c, tag="b")
    assert not r["ok"] and "slow down" in r["error"]


def test_a_failed_enter_leaves_an_unentered_scope_for_the_reaper(world, monkeypatch):
    hub, cg, scopes = world
    from cora_sentinel.scope import ScopeError

    def boom(*a, **kw):
        raise ScopeError("could not move pid: EBUSY")
    monkeypatch.setattr(scopes, "enter", boom)
    r = launch(Conn(hub))
    assert not r["ok"] and "EBUSY" in r["error"]
    (name,) = scopes.owned
    assert scopes.owned[name]["entered"] is False                        # reaped once ENTER_TTL_S lapses


def test_launch_does_not_open_the_breakers_to_anything_new(world):
    hub, _, _ = world
    r = Conn(hub).ask(cmd="release", task="steam-570-abcdef")
    assert not r["ok"] and "only tighten" in r["error"] and "places only the caller" in r["error"]


# ---------------------------------------------------------------- the peer reader

def test_peer_pid_and_start_time_are_the_kernels():
    a, b = socket.socketpair(socket.AF_UNIX)
    try:
        assert uihub.peer_pid(a) == os.getpid()
        assert uihub.proc_starttime(os.getpid()) == uihub.proc_starttime(os.getpid()) is not None
        assert uihub.proc_starttime(None) is None and uihub.proc_starttime(2 ** 22 + 7) is None
    finally:
        a.close(), b.close()
