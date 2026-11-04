"""Real-kernel cgroup v2 tests. Need a writable cgroup2 mount (root, or a delegated subtree).
Run: sudo -E $(which python) -m pytest -q tests/test_cgroup.py"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from cora_sentinel.cgroup import CgroupError, CgroupRoot
from cora_sentinel.daemon import Sentinel, VirtualNet, build_payload, read_starttime
from cora_sentinel.verdict import Adjudicator, Executor



def _find_mount():
    for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified"):
        p = Path(m) / f"coraprobe-{os.getpid()}"
        try:
            p.mkdir()
            p.rmdir()
            if (Path(m) / "cgroup.controllers").exists():
                return m
        except OSError:
            continue
    return None


MOUNT = _find_mount()
pytestmark = pytest.mark.skipif(MOUNT is None, reason="no writable cgroup v2 mount")

TREE = ("import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);time.sleep(60)")


@pytest.fixture
def cg():
    root = CgroupRoot(f"{MOUNT}/coraci-{os.getpid()}", MOUNT)
    root.ensure()
    yield root
    for n in root.names():
        try:
            root.kill(n)
        except Exception:
            pass
    for _ in range(40):
        try:
            for n in root.names():
                (root.root / n).rmdir()
            root.root.rmdir()
            break
        except OSError:
            time.sleep(0.1)


def launch(cg, name, code=TREE, want=2):
    env = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT}
    p = subprocess.Popen([sys.executable, "-m", "cora_sentinel.run", name, sys.executable, "-c", code], env=env)
    end = time.monotonic() + 5
    while time.monotonic() < end and len(cg.pids(name)) < want:
        time.sleep(0.1)
    return p


def alive(pid):
    try:
        os.kill(pid, 0)
        return Path(f"/proc/{pid}/status").read_text().split("State:")[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def wait_dead(pids, t=5):
    end = time.monotonic() + t
    while time.monotonic() < end:
        if not any(alive(p) for p in pids):
            return True
        time.sleep(0.1)
    return False


@pytest.mark.parametrize("bad", ["../x", "A", "", "a/b", "a b", "x" * 41, ".hidden"])
def test_names_rejected(cg, bad):
    with pytest.raises(CgroupError):
        cg.create(bad)


def test_children_inherit_membership(cg):
    p = launch(cg, "tree")
    pids = cg.pids("tree")
    assert len(pids) >= 2 and p.pid in pids            # launcher became the task + its child
    assert all(cg.cgroup_of(x) == "tree" for x in pids)
    assert cg.discover() == {x: "tree" for x in pids}


def test_freeze_and_thaw_whole_tree(cg):
    launch(cg, "tree")
    cg.freeze("tree")
    end = time.monotonic() + 3
    while time.monotonic() < end and not cg.is_frozen("tree"):
        time.sleep(0.1)
    assert cg.is_frozen("tree")
    cg.thaw("tree")
    end = time.monotonic() + 3
    while time.monotonic() < end and cg.is_frozen("tree"):
        time.sleep(0.1)
    assert not cg.is_frozen("tree")


def test_kill_takes_the_whole_tree(cg):
    launch(cg, "tree")
    pids = cg.pids("tree")
    cg.kill("tree")
    assert wait_dead(pids)


def test_throttle_reports_what_it_applied(cg):
    p = launch(cg, "tree")
    applied = cg.throttle("tree")
    assert applied
    if "nice+10(fallback)" in applied:
        assert os.getpriority(os.PRIO_PROCESS, p.pid) == 10


def test_sentinel_sees_grandchild_without_marker(cg):
    code = ("import subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-c',\"import time;time.sleep(1);f=open('/etc/hostname');time.sleep(30)\"]);"
            "time.sleep(60)")
    launch(cg, "leaky", code)
    ev = []
    s = Sentinel("UNUSED", ["/tmp"], spike_mb=10**6, window_s=5, emit=ev.append, cgroups=cg)
    end = time.monotonic() + 6
    while time.monotonic() < end and not any(e["anomaly"]["kind"] == "path_violation" for e in ev):
        s.tick(); time.sleep(0.25)
    hit = [e for e in ev if e["anomaly"]["kind"] == "path_violation"]
    assert hit and hit[0]["subject"]["cgroup"] == "leaky"


# ---- verdict stage in cgroup mode ----------------------------------------
class Fake:
    def __init__(self, v): self.v = v
    def judge(self, ev): return json.dumps({"verdict": self.v, "confidence": 0.9, "reason": "t"})


def adj_for(cg, verdict, enforce=True):
    net = VirtualNet()
    return net, Adjudicator(net, Fake(verdict), Executor(enforce, cg), None, 0.6)


def event(net, pid, cgname):
    return build_payload(pid, net.ensure(pid), "x", "path_violation", "high",
                         {"path": "/etc/shadow"}, read_starttime(pid), cgroup=cgname)


def test_terminate_through_gate_kills_tree(cg):
    p = launch(cg, "tree")
    pids = cg.pids("tree")
    net, adj = adj_for(cg, "TERMINATE")
    d = adj.handle(event(net, pids[-1], "tree"))
    assert d["gate"]["ok"] and d["action"] == "done:TERMINATE@cgroup:tree"
    assert wait_dead(pids)


def test_dry_run_leaves_tree_alone(cg):
    launch(cg, "tree")
    pids = cg.pids("tree")
    net, adj = adj_for(cg, "TERMINATE", enforce=False)
    d = adj.handle(event(net, pids[0], "tree"))
    assert d["action"] == "dry-run:TERMINATE@cgroup:tree" and all(alive(x) for x in pids)


def test_gate_blocks_wrong_cgroup(cg):
    launch(cg, "tree")
    launch(cg, "other")
    pid = cg.pids("tree")[0]
    net, adj = adj_for(cg, "TERMINATE")
    d = adj.handle(event(net, pid, "other"))        # event claims a cgroup the pid isn't in
    assert d["action"] == "blocked" and d["gate"]["code"] == "CGROUP_MISMATCH"
    assert all(alive(x) for x in cg.pids("other"))


def test_gate_blocks_cgroup_event_without_config(cg):
    launch(cg, "tree")
    pid = cg.pids("tree")[0]
    net = VirtualNet()
    adj = Adjudicator(net, Fake("TERMINATE"), Executor(True, None), None, 0.6)
    d = adj.handle(event(net, pid, "tree"))
    assert d["gate"]["code"] == "NO_CGROUP" and alive(pid)


def test_launcher_rejects_bad_name(cg):
    env = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT}
    r = subprocess.run([sys.executable, "-m", "cora_sentinel.run", "../evil", "true"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 1 and "cannot enter cgroup" in r.stderr
