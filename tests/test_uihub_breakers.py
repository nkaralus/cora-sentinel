"""Emergency breakers over the status feed: a one-way ratchet. Real Unix sockets; the executor is a fake."""
import grp
import json
import os
import pwd
import socket
import threading
import time

import pytest

from cora_sentinel import uihub
from cora_sentinel.uihub import Hub
from cora_sentinel.uiclient import StatusClient


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(uihub, "HEARTBEAT_S", 0.3)
    monkeypatch.setattr(uihub, "MIN_INTERVAL_S", 0.05)


class World:
    def __init__(self):
        self.tasks = {"game": {"pids": 4, "mem_bytes": 1 << 30, "id": 77}}
        self.calls, self.records = [], []
        self.delay, self.result, self.raise_ = 0.0, None, None

    def act(self, verdict, task):
        self.calls.append((verdict, task))
        if self.delay:
            time.sleep(self.delay)
        if self.raise_:
            raise self.raise_
        return self.result or f"done:{verdict}@cgroup:{task}[fake]"


@pytest.fixture
def world():
    return World()


RUNNER_GROUP = grp.getgrgid(os.getgid()).gr_name   # the test runner stands in for a --ui-group member
USE_RUNNER = object()


def make(tmp_path, world, mode="enforce", act=True, group=USE_RUNNER):
    """By default the runner's own primary group is the --ui-group, so presses are permitted whether pytest runs as
    root (CI's sudo) or as uid 1000 on a workstation. Pass group=None for a root-only hub."""
    if group is USE_RUNNER:
        group = RUNNER_GROUP
    d = tmp_path / "run"
    d.mkdir(mode=0o755, exist_ok=True)
    logs = []
    h = Hub(str(d / "ui.sock"), group=group, mode=mode, tasks=lambda: {k: dict(v) for k, v in world.tasks.items()},
            cgroup_id=lambda n: world.tasks.get(n, {}).get("id"), act=world.act if act else None,
            record=world.records.append, log=logs.append)
    h.logs = logs
    h.start()
    return h


@pytest.fixture
def hub(tmp_path, world):
    h = make(tmp_path, world)
    yield h
    h.stop()


class Conn:
    def __init__(self, hub):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(str(hub.path))
        self.s.settimeout(5)
        self.f = self.s.makefile("rb")

    def send(self, **msg):
        self.s.sendall((json.dumps(msg) + "\n").encode())

    def next(self, pred, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            line = self.f.readline()
            if not line:
                raise AssertionError("closed")
            m = json.loads(line)
            if pred(m):
                return m
        raise AssertionError("timeout")

    def result(self, tag):
        return self.next(lambda m: m.get("type") == "result" and m.get("id") == tag)


def press(c, cmd="sever", task="game", cid=77, tag="a"):
    c.send(cmd=cmd, task=task, cgroup_id=cid, id=tag)
    return c.result(tag)


# ---------------------------------------------------------------- the two breakers

def test_sever_isolates_and_is_recorded_as_a_manual_override(hub, world):
    c = Conn(hub)
    r = press(c)
    assert r["ok"] and r["action"] == "done:ISOLATE@cgroup:game[fake]"
    assert world.calls == [("ISOLATE", "game")]
    d = world.records[-1]
    assert d["policy"] == "manual_operator_override" and d["operator_uid"] == os.getuid() and d["task"] == "game"
    m = c.next(lambda m: m.get("type") == "state" and m["status"] == "contained")
    t = m["tasks"][0]
    assert t["enforced"] == ["ISOLATE"] and m["session"]["manual_overrides"] == 1


def test_cap_throttles(hub, world):
    c = Conn(hub)
    assert press(c, "cap")["ok"] and world.calls == [("THROTTLE", "game")]


@pytest.mark.parametrize("cmd", ["release", "unblock", "thaw", "reset", "kill", "terminate", "", None, 7])
def test_nothing_that_loosens_or_kills_exists(hub, world, cmd):
    c = Conn(hub)
    r = press(c, cmd)
    assert not r["ok"] and "only tighten" in r["error"] and "root-only" in r["error"]
    assert world.calls == []


def test_snapshot_advertises_breakers_only_when_they_exist(tmp_path, world):
    h = make(tmp_path, world, act=False)
    try:
        assert h.snapshot()["breakers"] == []
        r = press(Conn(h))
        assert not r["ok"] and "unavailable" in r["error"]
    finally:
        h.stop()


def test_hub_with_breakers_advertises_them(hub):
    assert hub.snapshot()["breakers"] == ["cap", "sever"]


def test_a_root_only_hub_refuses_a_workstation_user(tmp_path, world, monkeypatch):
    """What the 0.9.x tests missed: without a group, only uid 0 may press, so a non-root runner is refused."""
    h = make(tmp_path, world, group=None)
    try:
        monkeypatch.setattr(uihub, "peer_uid", lambda conn: 1000 if os.getuid() == 0 else os.getuid())
        r = press(Conn(h))
        assert not r["ok"] and "not in the --ui-group" in r["error"] and world.calls == []
    finally:
        h.stop()


# ---------------------------------------------------------------- who, what, how often

def test_a_non_member_is_refused(hub, world, monkeypatch):
    nobody = pwd.getpwnam("nobody")
    assert hub._gid not in os.getgrouplist(nobody.pw_name, nobody.pw_gid)   # the premise: nobody is not a member
    monkeypatch.setattr(uihub, "peer_uid", lambda conn: nobody.pw_uid)
    c = Conn(hub)
    r = press(c)
    assert not r["ok"] and "not in the --ui-group" in r["error"] and world.calls == []
    assert any(f"refused sever from uid {nobody.pw_uid}" in l for l in hub.logs)


def test_may_command_rules(tmp_path, world):
    h = make(tmp_path, world, group=None)                          # no group: root only
    try:
        assert h._gid is None
        assert h.may_command(0) and not h.may_command(65534) and not h.may_command(None)
        if os.getuid() != 0:
            assert not h.may_command(os.getuid())                  # a workstation user, with no group configured
        h._gid = os.getgid()
        me = pwd.getpwuid(os.getuid())
        assert h.may_command(os.getuid())
        nobody = pwd.getpwnam("nobody")
        h._gid = 0
        assert not h.may_command(nobody.pw_uid)                    # nobody is not in group root
        assert not h.may_command(4242424)                          # no such user
    finally:
        h.stop()


def test_unknown_task_refused(hub, world):
    r = press(Conn(hub), task="other")
    assert not r["ok"] and "no live task" in r["error"] and world.calls == []


def test_a_relaunched_task_is_not_the_one_you_pressed(hub, world):
    c = Conn(hub)
    world.tasks["game"]["id"] = 78                                 # exited and came back under the same name
    r = press(c, cid=77)
    assert not r["ok"] and "relaunched" in r["error"] and world.calls == []


def test_one_command_per_second(hub, world):
    c = Conn(hub)
    assert press(c, tag="a")["ok"]
    r = press(c, "cap", tag="b")
    assert not r["ok"] and "slow down" in r["error"] and len(world.calls) == 1


def test_busy_limit(tmp_path, world, monkeypatch):
    monkeypatch.setattr(uihub, "MAX_ACTIONS", 1)
    world.delay = 1.0
    h = make(tmp_path, world)
    try:
        a, b = Conn(h), Conn(h)
        a.send(cmd="sever", task="game", cgroup_id=77, id="a")
        time.sleep(0.2)
        r = press(b, "cap", tag="b")
        assert not r["ok"] and "busy" in r["error"]
        assert a.result("a")["ok"]
    finally:
        h.stop()


def test_garbage_lines_get_a_refusal_not_a_crash(hub, world):
    c = Conn(hub)
    c.s.sendall(b"not json\n[1,2]\n")
    c.next(lambda m: m.get("type") == "result" and not m["ok"])
    assert press(c)["ok"]                                          # still alive


# ---------------------------------------------------------------- never stall, never lie

def test_a_slow_breaker_does_not_stall_the_feed(tmp_path, world):
    world.delay = 1.5                                              # an nft call near its timeout
    h = make(tmp_path, world)
    try:
        c = Conn(h)
        first = c.next(lambda m: m.get("type") == "state")
        c.send(cmd="sever", task="game", cgroup_id=77, id="a")
        t0 = time.monotonic()
        c.next(lambda m: m.get("type") == "state" and m["seq"] > first["seq"] + 1)
        assert time.monotonic() - t0 < 1.2                         # heartbeats kept coming during the action
        assert c.result("a")["ok"]
    finally:
        h.stop()


def test_a_breaker_that_raises_reports_and_the_hub_survives(hub, world):
    world.raise_ = RuntimeError("boom")
    c = Conn(hub)
    r = press(c)
    assert not r["ok"] and r["action"] == "failed:RuntimeError@cgroup:game"
    assert hub.snapshot()["status"] != "alarm"                     # a failed button is not a missed threat
    world.raise_ = None
    time.sleep(1.05)
    assert press(c, "cap", tag="b")["ok"]


def test_a_failed_breaker_is_told_to_the_operator_not_turned_into_an_alarm(hub, world):
    world.result = "failed:FirewallError@cgroup:game"
    r = press(Conn(hub))
    assert not r["ok"] and "FirewallError" in r["error"]
    s = hub.snapshot()
    assert s["status"] == "clear" and s["session"]["failed_actions"] == 0 and s["session"]["manual_overrides"] == 0


# ---------------------------------------------------------------- dry-run

def test_breakers_act_in_dry_run(tmp_path, world):
    h = make(tmp_path, world, mode="dry-run")
    try:
        r = press(Conn(h))
        assert r["ok"] and world.calls == [("ISOLATE", "game")]
        assert world.records[-1]["mode"] == "dry-run" and world.records[-1]["policy"] == "manual_operator_override"
        assert h.snapshot()["tasks"][0]["enforced"] == ["ISOLATE"]
    finally:
        h.stop()


def test_dry_run_model_containment_still_offers_the_real_breaker(tmp_path, world):
    h = make(tmp_path, world, mode="dry-run")
    try:
        h.note_decision({"action": "dry-run:ISOLATE@cgroup:game"})
        t = h.snapshot()["tasks"][0]
        assert t["contained"] == ["ISOLATE"] and t["enforced"] == []
        c = StatusClient(str(h.path))
        c.connect()
        end = time.monotonic() + 3
        while time.monotonic() < end and not (c.state and c.state["tasks"] and c.state["tasks"][0]["contained"]):
            c.poll()
            time.sleep(0.02)
        assert c.view()["tasks"][0]["can_sever"] is True           # WOULD-have is not done: the button stays
    finally:
        h.stop()


def test_done_beats_dry_run_never_the_reverse(hub):
    hub.note_decision({"action": "done:ISOLATE@cgroup:game[x]"})
    hub.note_decision({"action": "dry-run:ISOLATE@cgroup:game"})
    assert hub.snapshot()["tasks"][0]["enforced"] == ["ISOLATE"]


# ---------------------------------------------------------------- the client

def test_client_send_and_result(hub, world):
    c = StatusClient(str(hub.path))
    c.connect()
    end = time.monotonic() + 3
    while time.monotonic() < end and c.state is None:
        c.poll()
        time.sleep(0.02)
    v = c.view()
    assert v["tasks"][0]["can_sever"] and v["tasks"][0]["can_cap"]
    tag = c.send("sever", "game", v["tasks"][0]["cgroup_id"])
    end = time.monotonic() + 3
    while time.monotonic() < end and tag not in c.results:
        c.poll()
        time.sleep(0.02)
    assert c.results[tag]["ok"]
    end = time.monotonic() + 3
    while time.monotonic() < end and c.view()["tasks"][0]["can_sever"]:
        c.poll()
        time.sleep(0.02)
    assert not c.view()["tasks"][0]["can_sever"] and c.view()["tasks"][0]["can_cap"]


def test_client_refuses_to_even_ask_for_anything_else(hub):
    c = StatusClient(str(hub.path))
    c.connect()
    assert c.send("release", "game", 77) is None


# ---------------------------------------------------------------- the root-only way back from "Cap memory"

def test_cora_cgroup_reset_undoes_throttle(tmp_path, monkeypatch, capsys):
    from cora_sentinel import cgroup
    root = tmp_path / "cora"
    (root / "game").mkdir(parents=True)
    (root / "game" / "cpu.max").write_text("20000 100000\n")
    (root / "game" / "memory.high").write_text("1073741824\n")
    monkeypatch.setenv("CORA_CGROUP_ROOT", str(root))
    monkeypatch.setattr("sys.argv", ["cora-cgroup", "reset", "game"])
    assert cgroup.main() == 0
    assert (root / "game" / "cpu.max").read_text() == "max 100000"
    assert (root / "game" / "memory.high").read_text() == "max"
    assert "memory.high-reset" in capsys.readouterr().out
    monkeypatch.setattr("sys.argv", ["cora-cgroup", "reset", "game"])
    cgroup.main()
    assert "no THROTTLE limits were set" in capsys.readouterr().out


# ---------------------------------------------------------------- tray menu model (no GTK needed)

from cora_sentinel import uiclient as uc


def view_of(status="clear", mode="enforce", tasks=None, breakers=("cap", "sever")):
    c = StatusClient("/x")
    c.sock, c.last_rx, c.clock = object(), 0.0, (lambda: 0.0)
    c.state = {"schema": uihub.SCHEMA, "type": "state", "status": status, "mode": mode, "breakers": list(breakers),
               "tasks": tasks or [], "session": {}}
    return c.view()


def test_menu_offers_breakers_per_task():
    t = {"name": "game", "cgroup_id": 9, "mem_bytes": 1, "mem_delta_bytes": 0, "contained": [], "enforced": []}
    spec = uc.menu_spec(view_of(tasks=[t]))
    task = [i for i in spec if i[0] == "task"][0]
    assert task[2] == [("sever", "Sever network\u2026", True), ("cap", "Cap memory\u2026", True)]
    assert task[3] == "game" and task[4] == 9 and spec[-1][0] == "quit"


def test_menu_greys_out_a_breaker_already_in_force():
    t = {"name": "game", "cgroup_id": 9, "contained": ["ISOLATE"], "enforced": ["ISOLATE"]}
    task = [i for i in uc.menu_spec(view_of(status="contained", tasks=[t])) if i[0] == "task"][0]
    assert task[2][0][2] is False and task[2][1][2] is True


def test_unreachable_menu_has_no_breakers_at_all():
    v = StatusClient("/nonexistent").view()
    spec = uc.menu_spec(v)
    assert not [i for i in spec if i[0] == "task"] and spec[0] == ("label", "cora: unreachable")


def test_no_breakers_when_the_daemon_has_none():
    t = {"name": "game", "cgroup_id": 9, "contained": [], "enforced": []}
    task = [i for i in uc.menu_spec(view_of(tasks=[t], breakers=())) if i[0] == "task"][0]
    assert [e for _, _, e in task[2]] == [False, False]


def test_dry_run_menu_says_breakers_still_act():
    assert any("breakers still act" in i[1] for i in uc.menu_spec(view_of(mode="dry-run")) if i[0] == "label")


@pytest.mark.parametrize("cmd,undo", [("sever", "sudo cora-firewall release game"), ("cap", "sudo cora-cgroup reset game")])
def test_confirm_text_names_the_root_only_undo(cmd, undo):
    head, body = uc.confirm_text(cmd, "game")
    assert "game" in head and undo in body and "cannot undo" in body


def test_a_manual_sever_in_dry_run_is_not_called_hypothetical():
    """Found by running the real tray: after a manual Sever in dry-run the title said 'nothing was done'."""
    real = {"name": "game", "cgroup_id": 9, "contained": ["ISOLATE"], "enforced": ["ISOLATE"]}
    would = {"name": "game", "cgroup_id": 9, "contained": ["ISOLATE"], "enforced": []}
    assert "manual override" in view_of(status="contained", mode="dry-run", tasks=[real])["title"]
    assert "nothing was done" in view_of(status="contained", mode="dry-run", tasks=[would])["title"]
    assert view_of(status="contained", mode="enforce", tasks=[real])["title"] == "cora: containment active"
