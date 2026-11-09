"""Part 1: sock_diag library (needs a Linux kernel with sock_diag). Part 2: NetMonitor against a real
cgroup v2 mount. Run: sudo -E $(which python) -m pytest -q tests/test_sockdiag.py"""
import errno
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

import _ambient  # noqa: E402  (tests/_ambient.py: host-noise helpers)

from cora_sentinel.blocklist import Blocklist
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.daemon import Sentinel, read_tcp_table
from cora_sentinel.sockdiag import (LIVE_MASK, NOCOOKIE, TCP_ESTABLISHED, TCP_LISTEN, DestroyListener, SockDiag,
                           available, parse_msg)

needs_diag = pytest.mark.skipif(not available(), reason="sock_diag unavailable")


def inodes(*socks):
    """The kernel's inode of each socket: exactly what sock_diag and /proc/net/tcp report, so a filter on it selects
    the test's own sockets and nothing else. Ports alone do not: any socket on the host that shares a port number with
    ours (CI run #42: an unrelated socket made it 22, not 21) would be counted."""
    return {os.fstat(x.fileno()).st_ino for x in socks}


def pair(n=1):
    """n established loopback connections. Returns (listener, [(client, server)], port)."""
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(512)
    port = lis.getsockname()[1]
    out = []
    for _ in range(n):
        c = socket.create_connection(("127.0.0.1", port)); out.append((c, lis.accept()[0]))
    return lis, out, port


# ============================ part 1: the library ============================
def test_parse_rejects_garbage_without_crashing():
    with pytest.raises(ValueError):
        parse_msg(b"\0" * 10)
    with pytest.raises(ValueError):
        parse_msg(bytes([99, 1]) + b"\0" * 80)                       # unknown family
    ok = bytes([2, 1, 0, 0]) + b"\0" * 68
    assert parse_msg(ok + b"\xff\xff\x15\x00" + b"\0" * 8).cgroup_id is None   # attr claims len 65535: ignored


@needs_diag
def test_dump_agrees_with_proc_net_tcp():
    lis, conns, port = pair(10)
    decoy = socket.socket()                                          # not ours, same port number: must not be counted
    try:
        decoy.bind(("127.0.0.2", port)); decoy.listen(1)
    except OSError:
        decoy.close(); decoy = None
    try:
        ours = inodes(lis, *(x for c, s in conns for x in (c, s)))
        d = SockDiag()
        diag = {(s.local_port, s.remote_port, s.state, s.inode) for s in d.dump() if s.inode in ours}
        live = {TCP_ESTABLISHED, 2, TCP_LISTEN}                       # the states the dump asks the kernel for
        proc = {(r["local_port"], r["remote_port"], int(r["state"], 16), r["inode"]) for r in read_tcp_table()
                if int(r["state"], 16) in live and r["inode"] in ours}
        assert diag == proc and len(diag) == 21                        # 10 pairs + the listener
        assert {(p_, r_) for p_, r_, _, _ in diag} == {(port, 0)} | {(c.getsockname()[1], port) for c, _ in conns} \
            | {(port, c.getsockname()[1]) for c, _ in conns}         # exactly the 4-tuples we made
    finally:
        [x.close() for c, s in conns for x in (c, s)]; lis.close()
        if decoy:
            decoy.close()


@needs_diag
def test_ipv6_sockets_are_dumped():
    try:
        lis = socket.socket(socket.AF_INET6); lis.bind(("::1", 0)); lis.listen(1)
    except OSError:
        pytest.skip("no IPv6 loopback")
    port = lis.getsockname()[1]
    c = socket.create_connection(("::1", port))
    srv = lis.accept()[0]
    try:
        ours = inodes(lis, c, srv)
        rows = [s for s in SockDiag().dump() if s.inode in ours]
        assert {s.family for s in rows} == {socket.AF_INET6} and {s.local_ip for s in rows} == {"::1"} and len(rows) == 3
    finally:
        c.close(); srv.close(); lis.close()


@needs_diag
def test_kernel_side_state_filter():
    lis, conns, port = pair(1)
    conns[0][0].close(); conns[0][1].close()
    time.sleep(0.2)                                                   # now FIN_WAIT/TIME_WAIT/CLOSE_WAIT
    try:
        d = SockDiag()
        assert all(s.state == TCP_LISTEN for s in d.dump(states=1 << TCP_LISTEN, families=(socket.AF_INET,)))
        assert not [s for s in d.dump(states=LIVE_MASK) if s.remote_port == port]
    finally:
        lis.close()


@needs_diag
def test_destroy_event_reports_a_socket_no_poll_ever_saw():
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(8); port = lis.getsockname()[1]
    dl = DestroyListener()
    c = socket.create_connection(("127.0.0.1", port)); c.close()      # opened and closed: no dump can catch this
    got = None
    end = time.monotonic() + 3
    while time.monotonic() < end and not got:
        got = next((k for k in dl.poll(0.2) if k.remote_port == port), None)
    lis.close()
    assert got and got.remote_ip == "127.0.0.1" and got.cookie not in (None, NOCOOKIE)
    assert got.cgroup_id is None and got.inode == 0                  # the documented limit, pinned by a test


@needs_diag
def test_cookie_is_the_same_live_and_at_destruction():
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(8); port = lis.getsockname()[1]
    dl = DestroyListener()
    c = socket.create_connection(("127.0.0.1", port)); lport = c.getsockname()[1]
    live = next(s for s in SockDiag().dump() if s.local_port == lport)
    c.close()
    got = None
    end = time.monotonic() + 3
    while time.monotonic() < end and not got:
        got = next((k for k in dl.poll(0.2) if k.local_port == lport), None)
    lis.close()
    assert got and live.cookie and live.cookie == got.cookie


@needs_diag
def test_burst_of_ephemeral_sockets_none_missed():
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(1024); port = lis.getsockname()[1]
    dl = DestroyListener()
    N = 300
    for _ in range(N):
        socket.create_connection(("127.0.0.1", port)).close()
    seen, end = 0, time.monotonic() + 5
    while time.monotonic() < end and seen < N:
        seen += sum(1 for k in dl.poll(0.2) if k.remote_port == port)
    lis.close()
    assert seen == N and dl.lost == 0


@needs_diag
def test_receive_buffer_overflow_is_counted_never_hidden():
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(4096); port = lis.getsockname()[1]
    dl = DestroyListener(rcvbuf=2048)                                 # absurdly small on purpose
    for _ in range(2000):
        socket.create_connection(("127.0.0.1", port)).close()
    for _ in range(50):
        dl.poll(0.05)
        if dl.lost:
            break
    lis.close()
    assert dl.lost >= 1


# ====================== part 2: NetMonitor on a real cgroup ======================
def _mount():
    for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified"):
        p = Path(m) / f"coraprobe-{os.getpid()}"
        try:
            p.mkdir(); p.rmdir()
            if (Path(m) / "cgroup.controllers").exists():
                return m
        except OSError:
            continue


def _local_ip():
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                gw = socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
                s = socket.socket(2, 2); s.connect((gw, 9)); ip = s.getsockname()[0]; s.close()
                return ip
    except OSError:
        pass


MOUNT, LOCAL = _mount(), _local_ip()
real = pytest.mark.skipif(not (available() and MOUNT and LOCAL), reason="needs root, cgroup v2, a real address")


@pytest.fixture
def env():
    from cora_sentinel.netmon import NetMonitor
    cg = CgroupRoot(f"{MOUNT}/coranm-{os.getpid()}", MOUNT)
    cg.ensure()
    made = []
    noise = _ambient.maybe_noise(LOCAL)             # CORA_TEST_AMBIENT=1: deliberate host noise, see _ambient.py
    yield cg, made
    if noise:
        noise.stop()
    for m in made:
        m.stop()
    for n in cg.names():
        try: cg.kill(n)
        except Exception: pass
    for _ in range(40):
        try:
            for n in cg.names(): (cg.root / n).rmdir()
            cg.root.rmdir(); break
        except OSError:
            time.sleep(0.1)


def task(cg, name, code):
    e = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT}
    return subprocess.Popen([sys.executable, "-m", "cora_sentinel.run", name, sys.executable, "-c", code],
                            env=e, stdout=subprocess.PIPE, text=True)


def monitor(cg, made, events, interval=0.05):
    from cora_sentinel.netmon import NetMonitor
    bl = Blocklist(); bl.add_line(f"{LOCAL}/32", "rogue")
    s = Sentinel("UNUSED", ["/tmp"], spike_mb=10**6, window_s=5, emit=events.append,
                 net_allow=["0.0.0.0/0"], cgroups=cg, blocklist=bl, cooldown_s=0)
    nm = NetMonitor(s, interval=interval)
    nm.slips_by_port = _ambient.watch_slips(nm)    # slips are host-wide; assert on the test's own port (see _ambient.py)
    s.netmon_active = True
    nm.start(); made.append(nm)
    return s, nm


@real
def test_dump_attributes_a_socket_to_its_task_by_kernel_cgroup_id(env):
    cg, made = env
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(4); port = lis.getsockname()[1]
    p = task(cg, "attr", f"import socket,time;c=socket.create_connection(('{LOCAL}',{port}));time.sleep(3)")
    time.sleep(0.8)
    row = next(s for s in SockDiag().dump() if s.remote_port == port and s.local_ip == LOCAL)
    assert row.cgroup_id == os.stat(cg.root / "attr").st_ino          # kernel says which task, no fd scan
    p.kill(); p.wait(); lis.close()


@real
def test_slow_beacon_is_caught_alive_attributed_once_and_not_reported_twice(env):
    cg, made = env
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(4); port = lis.getsockname()[1]
    events = []
    s, nm = monitor(cg, made, events)
    p = task(cg, "slow", f"import socket,time;c=socket.create_connection(('{LOCAL}',{port}));time.sleep(2.5)")
    end = time.monotonic() + 4
    while time.monotonic() < end:
        s.tick(); time.sleep(0.1)                                      # the 1s tick runs alongside: no double events
    p.wait()
    time.sleep(0.5)                                                    # let the destroy event arrive
    ev = [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]
    assert len(ev) == 1 and ev[0]["subject"]["cgroup"] == "slow"
    assert ev[0]["anomaly"]["evidence"]["blocklist"]["list"] == "rogue"
    assert nm.slips_by_port[port] == 0                                 # seen alive, so its destruction is not a slip
    lis.close()


@real
def test_ambient_host_traffic_is_audited_host_wide_and_never_lands_on_a_tests_own_port(env):
    """The destroy stream audits EVERY socket on the host, so noise from outside any task is counted as slips (that is the
    audit working). A test must therefore assert on its own listener's port, which noise can never share."""
    cg, made = env
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(8); port = lis.getsockname()[1]
    s, nm = monitor(cg, made, [])
    noise = _ambient.AmbientNoise(LOCAL).start()                       # a non-task process connecting to the blocklisted address
    try:
        time.sleep(1.5)
    finally:
        noise.stop()
    time.sleep(0.5)
    assert nm.slips_by_port[noise.port] > 0, "the host-wide audit did not see the noise"
    assert nm.stats["slips"] >= nm.slips_by_port[noise.port]
    assert nm.slips_by_port[port] == 0                                 # ... and none of it is attributable to this test's port
    lis.close()


@real
def test_every_connection_in_a_burst_is_accounted_for_live_or_as_a_slip(env):
    cg, made = env
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(1024); port = lis.getsockname()[1]
    events = []
    s, nm = monitor(cg, made, events, interval=0.05)
    N = 60
    p = task(cg, "burst", f"import socket,time\nfor _ in range({N}):\n"
                          f"    socket.create_connection(('{LOCAL}',{port})).close(); time.sleep(0.004)\ntime.sleep(1)")
    p.wait(timeout=30)
    time.sleep(1.0)
    live, slips = nm.stats["live_hits"], nm.slips_by_port[port]    # live hits are task-scoped; slips are scoped to this port
    print(f"\nburst of {N}: {live} caught alive+attributed, {slips} detected as unattributed slips")
    assert live + slips == N                                           # nothing unaccounted for
    assert nm.lost() == 0
    lis.close()


@real
def test_a_bystander_outside_any_task_is_never_actioned(env):
    cg, made = env
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(8); port = lis.getsockname()[1]
    events = []
    s, nm = monitor(cg, made, events)
    held = [socket.create_connection((LOCAL, port)) for _ in range(3)]  # this test process is not a task
    time.sleep(0.6)
    assert events == []
    [h.close() for h in held]; lis.close()


@real
def test_netmon_refuses_to_run_blind():
    from cora_sentinel.netmon import NetMonitor

    class NoCgroupIds:
        def dump(self, **kw):
            real_dump = SockDiag().dump(**kw)
            import dataclasses
            return [dataclasses.replace(k, cgroup_id=None) for k in real_dump]
        def close(self): pass
    s = Sentinel("X", ["/tmp"], 1, 1, emit=lambda p: None, cgroups=CgroupRoot("/x", "/"))
    with pytest.raises(OSError) as e:
        NetMonitor(s, diag=NoCgroupIds())
    assert e.value.errno == errno.ENOTSUP
    with pytest.raises(ValueError):
        NetMonitor(Sentinel("X", ["/tmp"], 1, 1, emit=lambda p: None))   # no cgroup mode


def test_parse_ipv6_message_synthetic():
    import struct
    src, dst = socket.inet_pton(socket.AF_INET6, "2001:db8::1"), socket.inet_pton(socket.AF_INET6, "2001:db8::beef")
    m = bytearray(72)
    m[0], m[1] = socket.AF_INET6, 1
    struct.pack_into("!HH", m, 4, 40000, 443)
    m[8:24], m[24:40] = src, dst
    struct.pack_into("=II", m, 44, 7, 0)
    struct.pack_into("=II", m, 64, 1000, 4242)
    m += struct.pack("=HHQ", 12, 21, 99)                                 # INET_DIAG_CGROUP_ID attribute
    k = parse_msg(bytes(m))
    assert (k.family, k.local_ip, k.local_port, k.remote_ip, k.remote_port) == (10, "2001:db8::1", 40000, "2001:db8::beef", 443)
    assert (k.uid, k.inode, k.cookie, k.cgroup_id) == (1000, 4242, 7, 99)


@real
@pytest.mark.parametrize("lifetime,min_live_frac", [(0.0, 0.0), (0.05, 0.0), (0.15, 0.8)])
def test_where_the_boundary_is_connection_lifetime_vs_poll_interval(env, lifetime, min_live_frac):
    """Documents the trade-off: lifetime >> poll interval => caught alive and attributed;
    lifetime << interval => still detected, but only as an unattributed slip."""
    cg, made = env
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(1024); port = lis.getsockname()[1]
    events = []
    s, nm = monitor(cg, made, events, interval=0.05)
    N = 25
    p = task(cg, "life", f"import socket,time\nfor _ in range({N}):\n"
                         f"    c=socket.create_connection(('{LOCAL}',{port})); time.sleep({lifetime}); c.close(); time.sleep(0.02)\n"
                         f"time.sleep(1)")
    p.wait(timeout=60)
    time.sleep(0.8)
    live, slips = nm.stats["live_hits"], nm.slips_by_port[port]
    print(f"\nlifetime {lifetime*1000:5.0f} ms vs poll 50 ms: {live:2d}/{N} alive+attributed, {slips:2d}/{N} slips")
    assert live + slips == N and nm.lost() == 0                          # detection is complete at every lifetime
    assert live >= min_live_frac * N
    lis.close()
