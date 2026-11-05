"""The 0.5.0 gate: the kernel-side floor, on a real kernel, with real packets.

Needs root, nft and `ip netns`; skips cleanly without them.
Run: sudo -E $(which python) -m pytest -q tests/test_floor_gate.py

Each test builds two network namespaces joined by a veth pair (client 10.77.77.1, server 10.77.77.2) and installs
the floor in a throwaway table INSIDE one of them, so nothing here can touch the host's own network or ruleset.
Traffic is real TCP: a SYN either reaches the listener or it does not.
"""
import ipaddress
import os
import random
import shutil
import signal
import subprocess
import sys
import time
import uuid
from functools import lru_cache
from pathlib import Path

import pytest

from cora_sentinel.nftsets import FLOOR_OUT, NftSets, parse_entries

TABLE = "cora_t"
C_IP, S_IP, PORT = "10.77.77.1", "10.77.77.2", 7777

SERVER_PY = r"""
import os, socket, sys, threading
ip, ports, path = sys.argv[1], [int(p) for p in sys.argv[2].split(",")], sys.argv[3]
n, lock = 0, threading.Lock()
def write():
    open(path + ".tmp", "w").write(str(n)); os.replace(path + ".tmp", path)
def serve(port):
    global n
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port)); s.listen(1024)
    while True:
        c, _ = s.accept(); c.close()
        with lock:
            n += 1; write()
write()
for p in ports:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
"""

CLIENT_PY = r"""
import select, socket, sys, time
ip, port, n, tmo = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
socks = []
for _ in range(n):
    s = socket.socket(); s.setblocking(False); s.connect_ex((ip, port)); socks.append(s)
pending, ok, t0 = list(socks), 0, time.time()
while pending and time.time() - t0 < tmo:
    _, w, _ = select.select([], pending, [], 0.05)
    for s in w:
        ok += s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
        pending.remove(s)
print(ok)
"""

PROBER_PY = r"""
import select, socket, sys, time
ip, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
ok = tries = 0
end = time.time() + secs
while time.time() < end:
    s = socket.socket(); s.setblocking(False); s.connect_ex((ip, port)); tries += 1
    _, w, _ = select.select([], [s], [], 0.03)
    if w and s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
        ok += 1
    s.close()
print(ok, tries)
"""

CHILD_PY = r"""
import sys
from cora_sentinel.nftsets import NftSets
A, B = [l.strip() for l in open(sys.argv[1])], [l.strip() for l in open(sys.argv[2])]
ns = NftSets(table=sys.argv[3])
ns.ensure()
while True:
    ns.sync_static(A)
    ns.sync_static(B)
"""


@lru_cache(maxsize=1)
def _lab_ok() -> bool:
    if os.geteuid() != 0 or not shutil.which("nft") or not shutil.which("ip"):
        return False
    name = f"cfprobe{os.getpid()}"
    try:
        if subprocess.run(["ip", "netns", "add", name], capture_output=True).returncode != 0:
            return False
        r = subprocess.run(["ip", "netns", "exec", name, "nft", "add", "table", "inet", "probe"], capture_output=True)
        return r.returncode == 0
    finally:
        subprocess.run(["ip", "netns", "del", name], capture_output=True)


kernel = pytest.mark.skipif(not _lab_ok(), reason="needs root, nft and `ip netns`")


def sh(*cmd, check=True, **kw):
    return subprocess.run(list(cmd), capture_output=True, text=True, check=check, **kw)


def ns_runner(ns):
    def run(args, stdin):
        p = subprocess.run(["ip", "netns", "exec", ns, "nft", *args], input=stdin, capture_output=True,
                           text=True, timeout=30)
        return p.returncode, p.stdout, p.stderr
    return run


class Lab:
    def __init__(self, tmp_path: Path, ports=(PORT,)):
        u = uuid.uuid4().hex[:6]
        self.c, self.s = f"cfc{u}", f"cfs{u}"
        self.tmp, self.procs = tmp_path, []
        sh("ip", "netns", "add", self.c)
        sh("ip", "netns", "add", self.s)
        vc, vs = f"vc{u}", f"vs{u}"
        sh("ip", "link", "add", vc, "netns", self.c, "type", "veth", "peer", "name", vs, "netns", self.s)
        for ns, dev, addr in ((self.c, vc, C_IP), (self.s, vs, S_IP)):
            sh("ip", "-n", ns, "addr", "add", f"{addr}/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        self.count_file = tmp_path / "accepted"
        srv = subprocess.Popen(["ip", "netns", "exec", self.s, sys.executable, "-c", SERVER_PY, S_IP,
                                ",".join(str(p) for p in ports), str(self.count_file)])
        self.procs.append(srv)
        for _ in range(100):
            if self.count_file.exists():
                break
            time.sleep(0.05)
        assert self.count_file.exists(), "listener did not start"

    def floor(self, ns: str) -> NftSets:
        f = NftSets(table=TABLE, run=ns_runner(ns))
        f.ensure()
        return f

    def accepted(self) -> int:
        time.sleep(0.15)                          # the listener's accept loop runs a moment behind the handshake
        return int(self.count_file.read_text())

    def connect(self, n: int, port: int = PORT, timeout: float = 0.6) -> int:
        """Open n connections from the client at once; returns how many completed a handshake."""
        r = sh("ip", "netns", "exec", self.c, sys.executable, "-c", CLIENT_PY, S_IP, str(port), str(n), str(timeout))
        return int(r.stdout.strip())

    def close(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        for ns in (self.c, self.s):
            sh("ip", "netns", "del", ns, check=False)


@pytest.fixture
def lab(tmp_path):
    lb = Lab(tmp_path)
    yield lb
    lb.close()


# ============ 1. first-packet escape ============
@kernel
@pytest.mark.parametrize("direction", ["out", "in"])
def test_first_packet_escape(lab, direction):
    """Add a dyn element, then at once send N SYNs: not one may reach the listener. Both hooks."""
    ns, victim = (lab.c, S_IP) if direction == "out" else (lab.s, C_IP)
    floor = lab.floor(ns)
    assert lab.connect(20) == 20                  # control: the path works before the element exists
    assert lab.accepted() == 20
    floor.block_ip(victim, ttl_s=120)
    N = 50
    assert lab.connect(N) == 0, "a SYN got through right after the element was added"
    assert lab.accepted() == 20, "the listener accepted a connection from a blocked address"
    assert floor.drop_counts()[direction] >= N, "the floor did not do the dropping"
    assert floor.unblock_ip(victim) is True
    assert lab.connect(5) == 5                    # and the element's removal takes effect at once


@kernel
def test_a_flow_block_stops_one_port_and_spares_the_rest(tmp_path):
    lb = Lab(tmp_path, ports=(PORT, PORT + 1))
    try:
        floor = lb.floor(lb.c)
        floor.block_flow(S_IP, "tcp", PORT, ttl_s=120)
        assert lb.connect(10, PORT) == 0
        assert lb.connect(10, PORT + 1) == 10     # the same address, another port: untouched
    finally:
        lb.close()


# ============ 2. over-limit drop ============
@kernel
def test_drops_continue_past_the_log_rate(lab):
    """A flood far over the log limit must be dropped throughout. (The one-rule `limit ... log drop` form drops only
    the packets UNDER the limit, so everything past it would walk through.)"""
    floor = lab.floor(lab.c)
    floor.sync_static([f"{S_IP}/32"])
    N = 300                                       # >> 10 per second
    assert lab.connect(N, timeout=0.8) == 0
    assert lab.accepted() == 0
    assert floor.drop_counts()["out"] >= N        # every one of them was dropped, not only the logged ones


# ============ 3. allow precedence ============
@kernel
def test_allow_beats_static_dyn_and_flow(lab):
    floor = lab.floor(lab.c)
    floor.sync_allow([S_IP])
    floor.sync_static(["10.77.77.0/24"])          # the whole subnet, allow address inside it
    floor.block_ip(S_IP)
    floor.block_flow(S_IP, "tcp", PORT)
    assert lab.connect(10) == 10
    assert lab.accepted() == 10
    assert floor.drop_counts() == {"in": 0, "out": 0}


# ============ 4. delta sync: no flush gap ============
def _fillers(lo, hi):
    return [f"100.64.{i // 256}.{i % 256}" for i in range(lo, hi)]


@kernel
def test_delta_sync_never_unblocks_a_staying_element(lab):
    floor = lab.floor(lab.c)
    A = [S_IP] + _fillers(0, 1500)
    B = [S_IP] + _fillers(700, 2200)
    assert lab.connect(3) == 3                    # control: not listed yet
    floor.sync_static(A)
    prober = subprocess.Popen(["ip", "netns", "exec", lab.c, sys.executable, "-c", PROBER_PY, S_IP, str(PORT), "4"],
                              stdout=subprocess.PIPE, text=True)
    want, syncs = A, 0
    while prober.poll() is None and syncs < 400:
        want = B if want is A else A
        floor.sync_static(want)
        syncs += 1
    ok, tries = (int(x) for x in prober.communicate()[0].split())
    assert tries > 20, "the prober barely ran"
    assert syncs >= 6, "too few syncs to mean anything"
    assert ok == 0, f"{ok} of {tries} probes got through while a listed address was being re-synced"
    live4, _ = parse_entries(floor.list_set("static4"))
    want4, _ = parse_entries(want)
    assert set(live4) == set(ipaddress.collapse_addresses(want4))   # ends exactly equal to the last list (merged)
    floor.sync_static([])
    assert lab.connect(3) == 3                    # emptying it lifts the block


# ============ 5. reconcile after a kill mid-sync ============
@kernel
def test_kill_mid_sync_then_reconcile(lab, tmp_path):
    A = [S_IP] + _fillers(0, 4000)
    B = [S_IP] + _fillers(2000, 6000)
    fa, fb = tmp_path / "A", tmp_path / "B"
    fa.write_text("\n".join(A)), fb.write_text("\n".join(B))
    setA = set(ipaddress.collapse_addresses(parse_entries(A)[0]))
    setB = set(ipaddress.collapse_addresses(parse_entries(B)[0]))
    floor = lab.floor(lab.c)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    rnd = random.Random(5)
    for rnd_i in range(8):
        child = subprocess.Popen(["ip", "netns", "exec", lab.c, sys.executable, "-c", CHILD_PY, str(fa), str(fb), TABLE],
                                 env=env, start_new_session=True, stderr=subprocess.DEVNULL)
        time.sleep(rnd.uniform(0.3, 1.2))
        os.killpg(child.pid, signal.SIGKILL)      # the daemon, its `ip` wrapper and any nft mid-commit
        child.wait()
        time.sleep(0.4)                           # let an orphaned nft finish or die
        live = set(parse_entries(floor.list_set("static4"))[0])
        assert live in (set(), setA, setB), f"round {rnd_i}: a half-applied set ({len(live)} elements)"
        if live:                                  # once listed, the floor must outlive the daemon
            assert lab.connect(3) == 0, "the floor lifted when the daemon died"
        assert floor.status()["dyn4"] >= 0        # chains and sets still there
    # restart: reconcile to the desired list, then again (a no-op)
    r1 = floor.reconcile(B, [])
    assert set(parse_entries(floor.list_set("static4"))[0]) == setB
    r2 = floor.reconcile(B, [])
    assert r2["static"] == (0, 0) and r2["allow"] == (0, 0), r2
    assert lab.connect(3) == 0
