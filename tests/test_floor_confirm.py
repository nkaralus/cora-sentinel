"""0.5.1 on a real kernel: the dead-man really takes the floor out, a killed daemon does not strand it, `rollback`
(the unit's ExecStopPost) behaves, the real /proc is decoded correctly, and the daemon wires it all together.

Same lab as test_floor_gate.py (two network namespaces, a throwaway table inside them); skips without root, nft and
`ip netns`. The daemon test also needs a writable cgroup v2 mount (set CORA_TEST_CGROUP_MOUNT to point at one).
Run: sudo -E $(which python) -m pytest -q tests/test_floor_confirm.py
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from cora_sentinel import floorguard
from cora_sentinel.floorguard import FloorGuard
from cora_sentinel.nftsets import FloorSync, NftSets

from test_floor_gate import C_IP, PORT, S_IP, TABLE, Lab, kernel, ns_runner, sh
from test_nftsets import bl_with

NO_PROTECT = lambda: {}                                   # noqa: E731  the host's real routes are not the lab's


@pytest.fixture
def lab(tmp_path):
    lb = Lab(tmp_path)
    yield lb
    lb.close()


def floor_present(lab) -> bool:
    return NftSets(table=TABLE, run=ns_runner(lab.c)).status()["static4"] >= 0


def start_floor(lab, state, seconds):
    """What the daemon does at start, in the client namespace: arm (a real watchdog process), then install."""
    guard = FloorGuard(str(state), spawn_prefix=["ip", "netns", "exec", lab.c])
    fs = FloorSync(NftSets(table=TABLE, run=ns_runner(lab.c)), log=lambda m: None, resolv=lambda: [],
                   protect=NO_PROTECT, guard=guard)
    fs.start(bl_with([f"{S_IP}/32"]), seconds)
    return guard, fs


# ============ the dead-man ============
@kernel
def test_an_unconfirmed_floor_is_removed_and_traffic_resumes(lab, tmp_path):
    guard, fs = start_floor(lab, tmp_path / "st", 3)
    assert lab.connect(5) == 0                            # the floor is on and cutting the listed address
    assert guard.pending()["watchdog_pid"]
    time.sleep(3 + 2.0)
    assert guard.state(fs.token) == "rolledback"
    assert lab.connect(5) == 5, "the floor was not removed at the deadline"
    assert not floor_present(lab)


@kernel
def test_a_confirmed_floor_stays_past_the_deadline(lab, tmp_path):
    guard, fs = start_floor(lab, tmp_path / "st", 3)
    time.sleep(1)
    assert guard.confirm()[0] is True
    time.sleep(3.5)
    assert lab.connect(5) == 0
    assert floor_present(lab) and guard.is_confirmed(fs.fingerprint(bl_with([f"{S_IP}/32"])))


CHILD_DAEMON_PY = r"""
import sys, time
from cora_sentinel.blocklist import Blocklist
from cora_sentinel.floorguard import FloorGuard
from cora_sentinel.nftsets import FloorSync, NftSets
bl = Blocklist(); bl.add_line(sys.argv[2] + "/32", "t")
fs = FloorSync(NftSets(table=sys.argv[3]), log=lambda m: None, resolv=lambda: [], protect=lambda: {},
               guard=FloorGuard(sys.argv[1]))
fs.start(bl, int(sys.argv[4]))
print("armed", flush=True)
time.sleep(600)
"""


@kernel
def test_a_daemon_killed_with_the_floor_unconfirmed_does_not_strand_it(lab, tmp_path):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    st = tmp_path / "st"
    child = subprocess.Popen(["ip", "netns", "exec", lab.c, sys.executable, "-c", CHILD_DAEMON_PY, str(st), S_IP,
                              TABLE, "3"], env=env, stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == "armed"
    assert lab.connect(5) == 0
    child.send_signal(signal.SIGKILL)                     # the daemon dies with the floor unconfirmed
    child.wait()
    time.sleep(3 + 2.0)
    assert lab.connect(5) == 5, "a dead daemon left an unconfirmed floor in place"
    assert FloorGuard(str(st)).pending() is None


@kernel
def test_rollback_is_what_systemd_runs_on_stop(lab, tmp_path):
    """ExecStopPost=cora-floor rollback: removes a floor that is still unconfirmed, leaves a confirmed one alone."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    st = tmp_path / "st"

    def cli(*args):
        return subprocess.run(["ip", "netns", "exec", lab.c, sys.executable, "-m", "cora_sentinel.nftsets",
                               "--table", TABLE, "--state-dir", str(st), *args], env=env, capture_output=True, text=True)
    guard, fs = start_floor(lab, st, 120)
    assert lab.connect(3) == 0
    assert "removed" in cli("rollback").stdout
    assert lab.connect(3) == 3 and not floor_present(lab)
    assert "nothing pending" in cli("rollback").stdout
    guard2, fs2 = start_floor(lab, st, 120)               # again, and this time it is confirmed
    assert "stays" in cli("confirm").stdout
    assert "nothing pending" in cli("rollback").stdout
    assert lab.connect(3) == 0 and floor_present(lab)


# ============ the real /proc ============
@kernel
def test_the_real_proc_is_decoded_correctly(lab, tmp_path):
    sh("ip", "-n", lab.c, "route", "add", "default", "via", S_IP)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    gw = subprocess.run(["ip", "netns", "exec", lab.c, sys.executable, "-c",
                         "import json; from cora_sentinel import floorguard as g; print(json.dumps(g.default_gateways()))"],
                        env=env, capture_output=True, text=True, check=True)
    assert S_IP in json.loads(gw.stdout), gw.stdout
    hold_port = PORT + 20                                   # the lab's own listener closes at once; this one holds
    srv = subprocess.Popen(["ip", "netns", "exec", lab.s, sys.executable, "-c",
                            f"import socket,time; s=socket.socket(); s.bind(('{S_IP}',{hold_port})); s.listen(5); "
                            f"print('listening',flush=True); c,_=s.accept(); time.sleep(8)"],
                           stdout=subprocess.PIPE, text=True)
    holder = None
    try:
        assert srv.stdout.readline().strip() == "listening"
        holder = subprocess.Popen(["ip", "netns", "exec", lab.c, sys.executable, "-c",
                                   f"import socket,time; s=socket.create_connection(('{S_IP}',{hold_port})); "
                                   f"print('up',flush=True); time.sleep(8)"], stdout=subprocess.PIPE, text=True)
        assert holder.stdout.readline().strip() == "up"
        peers = subprocess.run(["ip", "netns", "exec", lab.s, sys.executable, "-c",
                                "import json; from cora_sentinel import floorguard as g; "
                                f"print(json.dumps(g.ssh_peers(ports=({hold_port},), env={{}})))"],
                               env=env, capture_output=True, text=True, check=True)
        assert C_IP in json.loads(peers.stdout), peers.stdout        # the established session's peer, from /proc/net/tcp
    finally:
        for pr in (holder, srv):
            if pr is not None:
                pr.kill()
                pr.wait()


# ============ the daemon, end to end ============
def _cg_mount():
    m = os.environ.get("CORA_TEST_CGROUP_MOUNT")
    cands = [m] if m else ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"]
    for c in cands:
        p = Path(c) / f"cfprobe-{os.getpid()}"
        try:
            p.mkdir()
            p.rmdir()
            if (Path(c) / "cgroup.controllers").exists():
                return c
        except OSError:
            continue


def enter(ns):
    """Run a command inside a network namespace WITHOUT remounting /sys.

    `ip netns exec` gives the command a fresh sysfs, which hides the host's /sys/fs/cgroup mount; the daemon then cannot
    create its cgroup root there ("cannot prepare cgroup root: No such file or directory") even though the probe above,
    run outside the namespace, found a perfectly good cgroup v2. nsenter joins the namespace and leaves the mounts alone,
    which is also how the real service sees the world. (Tests that never touch cgroups can keep using `ip netns exec`.)"""
    return ["nsenter", f"--net=/run/netns/{ns}"]


CG = _cg_mount() if os.geteuid() == 0 and shutil.which("nsenter") else None
daemon_kernel = pytest.mark.skipif(not CG, reason="needs nsenter and a writable cgroup v2 mount (CORA_TEST_CGROUP_MOUNT)")


class Daemon:
    def __init__(self, lab, tmp_path, confirm, extra=()):
        (tmp_path / "bl.txt").write_text(f"{S_IP}/32\n")
        self.root = f"{CG}/cfconf-{os.getpid()}-{time.monotonic_ns() % 100000}"
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
        self.p = subprocess.Popen(
            [*enter(lab.c), sys.executable, "-m", "cora_sentinel.daemon", "--cgroup-root", self.root,
             "--cgroup-mount", CG, "--nft", "--nft-table", TABLE, "--floor", "--floor-confirm", str(confirm),
             "--state-dir", str(tmp_path / "st"), "--blocklist", str(tmp_path / "bl.txt"), "--no-resolve",
             "--net-source", "proc", "--out", str(tmp_path / "events.jsonl"), *extra],
            env=env, stderr=subprocess.PIPE, text=True)
        self.lines, self.env, self.state = [], env, str(tmp_path / "st")
        threading.Thread(target=lambda: [self.lines.append(l) for l in self.p.stderr], daemon=True).start()

    def saw(self, text, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            if any(text in l for l in self.lines):
                return True
            time.sleep(0.1)
        return False

    def stop(self):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        try:
            os.rmdir(self.root)
        except OSError:
            pass


@kernel
@daemon_kernel
def test_the_daemon_asks_for_confirmation_and_keeps_the_floor_when_it_gets_it(lab, tmp_path):
    d = Daemon(lab, tmp_path, 20)
    try:
        assert d.saw("FLOOR NOT YET CONFIRMED"), d.lines
        assert lab.connect(5) == 0
        r = subprocess.run(["ip", "netns", "exec", lab.c, sys.executable, "-m", "cora_sentinel.nftsets",
                            "--state-dir", d.state, "confirm"], env=d.env, capture_output=True, text=True)
        assert "stays" in r.stdout, (r.stdout, r.stderr)
        assert d.saw("floor confirmed"), d.lines
        time.sleep(1)
        assert lab.connect(5) == 0 and d.p.poll() is None
    finally:
        d.stop()


@kernel
@daemon_kernel
def test_the_daemon_survives_a_rollback_and_says_so(lab, tmp_path):
    d = Daemon(lab, tmp_path, 10)
    try:
        assert d.saw("FLOOR NOT YET CONFIRMED"), d.lines
        assert lab.connect(5) == 0
        assert d.saw("FLOOR ROLLED BACK", timeout=20), d.lines
        assert lab.connect(5) == 5
        assert d.p.poll() is None                         # still running, without the floor
    finally:
        d.stop()


@kernel
@daemon_kernel
def test_a_restart_with_the_same_allow_set_needs_no_second_confirmation(lab, tmp_path):
    d = Daemon(lab, tmp_path, 30)
    try:
        assert d.saw("FLOOR NOT YET CONFIRMED"), d.lines
        subprocess.run(["ip", "netns", "exec", lab.c, sys.executable, "-m", "cora_sentinel.nftsets",
                        "--state-dir", d.state, "confirm"], env=d.env, capture_output=True, text=True, check=True)
    finally:
        d.stop()
    d2 = Daemon(lab, tmp_path, 30)
    try:
        assert d2.saw("confirmed before"), d2.lines
        assert not any("NOT YET CONFIRMED" in l for l in d2.lines)
        assert FloorGuard(d2.state).pending() is None
    finally:
        d2.stop()


@kernel
@daemon_kernel
def test_the_daemon_refuses_a_floor_that_would_drop_the_ssh_peer(lab, tmp_path):
    (tmp_path / "bl.txt").write_text(f"{C_IP}/32\n")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p),
               SSH_CONNECTION=f"{C_IP} 40000 {S_IP} 22")        # the daemon was started from a session from C_IP
    (tmp_path / "bl2.txt").write_text(f"{C_IP}/32\n")
    root = f"{CG}/cfrefuse-{os.getpid()}"
    r = subprocess.run([*enter(lab.s), sys.executable, "-m", "cora_sentinel.daemon", "--cgroup-root", root,
                        "--cgroup-mount", CG, "--nft", "--nft-table", TABLE, "--floor", "--state-dir", str(tmp_path / "st"),
                        "--blocklist", str(tmp_path / "bl2.txt"), "--no-resolve", "--net-source", "proc",
                        "--out", str(tmp_path / "e.jsonl")], env=env, capture_output=True, text=True, timeout=30)
    try:
        os.rmdir(root)
    except OSError:
        pass
    assert r.returncode == 1 and "refusing to install" in r.stderr and C_IP in r.stderr, r.stderr
    assert not NftSets(table=TABLE, run=ns_runner(lab.s)).table_exists() or \
        NftSets(table=TABLE, run=ns_runner(lab.s)).status()["static4"] < 0       # nothing was installed
