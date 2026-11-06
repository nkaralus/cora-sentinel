"""Part 1 runs anywhere (synthetic packets, fake nft). Part 2 needs root, nft, nfnetlink_log, cgroup v2.
Run: sudo -E $(which python) -m pytest -q -s tests/test_nflog.py"""
import json
import os
import re
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

import _ambient  # noqa: E402  (tests/_ambient.py: host-noise helpers)

from cora_sentinel.blocklist import Blocklist
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.firewall import Firewall
from cora_sentinel.nflog import (PREFIX, NflogListener, TapRules, TapService, available, parse_ip_tcp_syn, parse_packet_msg,
                        _attr)
from cora_sentinel.nflog import classify_udp, parse_dns_query, parse_ip_flow
from cora_sentinel.daemon import ConnDetector, NetPolicy, Sentinel



# ============================ part 1: no kernel needed ============================
def ipv4(flags=0x02, proto=6, ihl=5, src="10.1.1.5", dst="203.0.113.9", sport=40000, dport=443):
    ip = bytearray(ihl * 4)
    ip[0] = 0x40 | ihl
    ip[9] = proto
    ip[12:16], ip[16:20] = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = bytearray(20)
    struct.pack_into("!HH", tcp, 0, sport, dport)
    tcp[13] = flags
    return bytes(ip + tcp)


def ipv6(flags=0x02, ext=False, src="2001:db8::1", dst="2001:db8::beef", sport=40001, dport=443):
    ip = bytearray(40)
    ip[0] = 0x60
    ip[6] = 0 if ext else 6                                    # hop-by-hop first, if asked
    ip[8:24], ip[24:40] = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
    hdr = bytes([6, 0, 0, 0, 0, 0, 0, 0]) if ext else b""      # next=TCP, len=0 -> 8 bytes
    tcp = bytearray(20)
    struct.pack_into("!HH", tcp, 0, sport, dport)
    tcp[13] = flags
    return bytes(ip) + hdr + bytes(tcp)


def test_parse_ipv4_syn_with_and_without_options():
    assert parse_ip_tcp_syn(ipv4()) == (socket.AF_INET, "10.1.1.5", 40000, "203.0.113.9", 443)
    assert parse_ip_tcp_syn(ipv4(ihl=8))[4] == 443                  # IP options shift the TCP header


def test_parse_ipv6_syn_including_an_extension_header():
    for ext in (False, True):
        fam, src, sport, dst, dport = parse_ip_tcp_syn(ipv6(ext=ext))
        assert (fam, src, dst, dport) == (socket.AF_INET6, "2001:db8::1", "2001:db8::beef", 443) and sport == 40001


@pytest.mark.parametrize("pkt", [ipv4(flags=0x12), ipv4(flags=0x10), ipv4(flags=0x00), ipv4(proto=17),
                                 ipv6(flags=0x12), b"", b"\x45" * 5, ipv4()[:22], bytes([0x90]) + b"\0" * 60])
def test_anything_that_is_not_a_bare_syn_is_rejected(pkt):
    with pytest.raises(ValueError):
        parse_ip_tcp_syn(pkt)


def nflog_body(prefix=PREFIX + "etl", pay=None, uid=1000):
    attrs = b""
    if prefix is not None:
        attrs += _attr(10, prefix.encode() + b"\0")
    if pay is not None:
        attrs += _attr(9, pay)
    if uid is not None:
        attrs += _attr(11, struct.pack("!I", uid))
    return b"\0\0\x00\x47" + attrs                                 # nfgenmsg then attributes


def test_parse_packet_msg_names_the_task_from_the_prefix():
    s = parse_packet_msg(nflog_body(pay=ipv4()), 123)
    assert (s.task, s.dst, s.dport, s.uid, s.recv_ns) == ("etl", "203.0.113.9", 443, 1000, 123)


@pytest.mark.parametrize("body", [nflog_body(prefix="other:etl", pay=ipv4()), nflog_body(prefix=None, pay=ipv4()),
                                  nflog_body(pay=None), b"\0\0"])
def test_foreign_or_malformed_messages_are_ignored_not_crashed_on(body):
    with pytest.raises(ValueError):
        parse_packet_msg(body, 1)


class FakeTapNft:
    """Just enough nft to exercise TapRules: stores rules, answers -j list chain, applies -f - scripts."""
    def __init__(self):
        self.rules, self.next, self.chain, self.scripts, self.sets = [], 1, False, [], set()

    def __call__(self, args, stdin):
        if args[:2] == ["-j", "list"]:
            if not self.chain:
                return 1, "", "No such file"
            return 0, json.dumps({"nftables": [{"chain": {}}] + [{"rule": r} for r in self.rules]}), ""
        if args[:2] == ["list", "chain"]:
            return (0, "", "") if self.chain else (1, "", "No such file")
        if args[:2] == ["list", "set"]:
            return (0, "", "") if args[-1] in self.sets else (1, "", "No such file")
        if args == ["-f", "-"]:
            self.scripts.append(stdin)
            for line in stdin.splitlines():
                if line.startswith("add set"):
                    self.sets.add(line.split()[4])      # add set inet <table> <name> {...}
                elif line.startswith("delete set"):
                    self.sets.discard(line.split()[-1])
                elif line.startswith("add chain"):
                    self.chain = True
                elif line.startswith("add rule"):
                    c = re.search(r'comment "([^"]+)"', line).group(1)
                    self.rules.append({"handle": self.next, "comment": c, "text": line,
                                       "expr": [{"counter": {"packets": 0, "bytes": 0}}]})
                    self.next += 1
                elif line.startswith("delete rule"):
                    h = int(line.split()[-1]); self.rules = [r for r in self.rules if r["handle"] != h]
                elif line.startswith("flush chain"):
                    self.rules = []
                elif line.startswith("delete chain"):
                    self.chain = False
            return 0, "", ""
        return 1, "", "unexpected"


def _drop_lock(table):
    for d in ("/run/lock", tempfile.gettempdir()):
        try: os.unlink(os.path.join(d, f"cora-tap-{table}.lock"))
        except OSError: pass


def _fake_tap(tmp_path, udp):
    """Unit tests must NEVER use a table name production uses: TapRules takes a per-table lock, and a
    test holding `cora-tap-cora.lock` could stall a real sentinel on the same machine."""
    base = tmp_path / "cgroup"; root = base / "cora"; root.mkdir(parents=True)
    n = FakeTapNft()
    table = f"unit{os.getpid()}x{abs(hash(str(tmp_path))) % 10**6}"
    cg = CgroupRoot(str(root), str(base))
    return TapRules(Firewall(cg, table=table, nft_base=str(base), run=n), group=88, udp=udp), cg, n, table


@pytest.fixture
def tapfake(tmp_path):
    t, cg, n, table = _fake_tap(tmp_path, udp=False)
    yield t, cg, n
    _drop_lock(table)


@pytest.fixture
def tapfake_udp(tmp_path):
    t, cg, n, table = _fake_tap(tmp_path, udp=True)
    yield t, cg, n
    _drop_lock(table)


def test_tap_rule_text_carries_everything_the_listener_needs(tapfake):
    t, cg, _ = tapfake
    cg.create("etl")
    r = t.rule_text("etl")
    assert 'level 2 "cora/etl"' in r and "tcp flags & (syn | ack) == syn" in r
    assert f'log prefix "{PREFIX}etl" group 88 queue-threshold 1 snaplen 128' in r
    assert re.search(r'comment "cora-tap:etl:\d+"', r)


def test_sync_is_one_atomic_transaction_and_idempotent(tapfake):
    t, cg, n = tapfake
    t.ensure_chain()
    for x in ("a", "b", "c"):
        cg.create(x)
    live = {x: os.stat(cg.root / x).st_ino for x in "abc"}
    added, removed = t.sync(live)
    assert sorted(added) == ["a", "b", "c"] and removed == [] and len(n.scripts) == 2     # chain + ONE sync script
    assert t.sync(live) == ([], []) and len(n.scripts) == 2                               # no change => no nft call


def test_sync_replaces_a_stale_rule_and_removes_dead_tasks(tapfake):
    t, cg, n = tapfake
    t.ensure_chain(); cg.create("a"); cg.create("b")
    t.sync({"a": os.stat(cg.root / "a").st_ino, "b": os.stat(cg.root / "b").st_ino})
    n.rules[0]["comment"] = "cora-tap:a:999999"        # the rule belongs to an OLDER cgroup of the name "a"
    cur_a = os.stat(cg.root / "a").st_ino
    added, removed = t.sync({"a": cur_a})
    assert added == ["a"] and removed == ["b"] and list(t.rules()) == ["a"] and t.rules()["a"]["cgid"] == cur_a
    assert len(n.rules) == 1


def test_hostile_task_names_never_reach_nft(tapfake):
    t, cg, n = tapfake
    t.ensure_chain()
    for bad in ('a"b', "../x", "A b", "x; drop"):
        with pytest.raises(Exception):
            t.sync({bad: 1})
    assert n.rules == []


def test_teardown_removes_the_chain(tapfake):
    t, cg, n = tapfake
    t.ensure_chain(); cg.create("a"); t.sync({"a": 1})
    t.teardown()
    assert not n.chain and n.rules == [] and not t.active()


# ============================ part 2: the real kernel ============================
def _mount():
    for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified"):
        p = Path(m) / f"coraprobe-{os.getpid()}"
        try:
            p.mkdir(); p.rmdir()
            if (Path(m) / "cgroup.controllers").exists():
                return m
        except OSError:
            continue


def _route():
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                gw = socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
                s = socket.socket(2, 2); s.connect((gw, 9)); ip = s.getsockname()[0]; s.close()
                return ip, gw
    except OSError:
        pass
    return None, None


def _nft_ok():
    if not shutil.which("nft"):
        return False
    t = f"coraprobe{os.getpid()}"
    if subprocess.run(["nft", "add", "table", "inet", t], capture_output=True).returncode:
        return False
    subprocess.run(["nft", "delete", "table", "inet", t], capture_output=True)
    return True


MOUNT, (LOCAL, GW) = _mount(), _route()
GROUP = 100 + os.getpid() % 900                       # never collides with a production group 71
real = pytest.mark.skipif(not (MOUNT and LOCAL and _nft_ok() and available(GROUP)[0]),
                          reason="needs root, nft, nfnetlink_log, cgroup v2, a real address")


@pytest.fixture
def env():
    cg = CgroupRoot(f"{MOUNT}/coratap-{os.getpid()}", MOUNT)
    cg.ensure()
    fw = Firewall(cg, table=f"coratest{os.getpid()}")
    made = []
    noise = _ambient.maybe_noise(LOCAL)             # CORA_TEST_AMBIENT=1: deliberate host noise, see _ambient.py
    yield cg, fw, made
    if noise:
        noise.stop()
    for m in made:
        try: m.stop()
        except Exception: pass
    fw.purge()
    for lock in ("/run/lock", tempfile.gettempdir()):          # the per-table tap lock file
        try: os.unlink(os.path.join(lock, f"cora-tap-{fw.table}.lock"))
        except OSError: pass
    for n in cg.names():
        try: cg.kill(n)
        except Exception: pass
    for _ in range(40):
        try:
            for n in cg.names(): (cg.root / n).rmdir()
            cg.root.rmdir(); break
        except OSError:
            time.sleep(0.1)


def task(cg, fw, name, code, preinstall=True, python=None, cwd=None):
    """Start `code` as a task. `python` is the interpreter the TASK runs (default: this one): cora-run itself always starts with this one,
    as root, but the task may be dropped to another user, who has to be able to execute its interpreter."""
    e = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT,
         "CORA_NFT_TABLE": fw.table, "CORA_NFLOG_GROUP": str(GROUP)}
    py = python or sys.executable
    cmd = ([sys.executable, "-m", "cora_sentinel.run", name, py, "-c", code] if preinstall
           else [py, "-c", code])
    return subprocess.Popen(cmd, env=e, stdout=subprocess.PIPE, text=True, cwd=cwd)


def beacons(port, n, hold=1.5, host=None):
    return (f"import socket,time\nfor _ in range({n}):\n"
            f"    socket.create_connection(('{host or LOCAL}',{port})).close()\ntime.sleep({hold})")


def listener(backlog=4096):
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(backlog)
    return lis, lis.getsockname()[1]


def drain(lis):
    """Accept and close, like a real server, so the listen queue never overflows."""
    stop = threading.Event()

    def run():
        lis.settimeout(0.1)
        while not stop.is_set():
            try:
                lis.accept()[0].close()
            except (socket.timeout, OSError):
                pass
    th = threading.Thread(target=run, daemon=True)
    th.start()
    return stop


def monitor(cg, fw, made, events, interval=0.05, lines=None, udp=True, udp_timeout=30):
    from cora_sentinel.netmon import NetMonitor
    bl = Blocklist()
    for ln in (lines if lines is not None else [f"{LOCAL}/32"]):
        bl.add_line(ln, "rogue")
    s = Sentinel("UNUSED", ["/tmp"], spike_mb=10**6, window_s=5, emit=events.append,
                 net_allow=["0.0.0.0/0"], cgroups=cg, blocklist=bl, cooldown_s=0)
    tap = TapService(fw, GROUP, udp=udp, udp_timeout=udp_timeout)
    nm = NetMonitor(s, interval=interval, tap=tap)
    nm.slips_by_port = _ambient.watch_slips(nm)    # slips are host-wide; assert on the test's own port (see _ambient.py)
    s.netmon_active = True
    nm.raw = []                                   # diagnostics: every raw SYN message, before coalescing
    orig = nm._on_syn
    nm._on_syn = lambda syn: (nm.raw.append((time.monotonic(), syn.task, syn.sport, syn.dport)), orig(syn))
    nm.start(); made.append(nm)
    return s, nm


def explain(nm, task):
    """Why does a task's SYN count differ from the truth? Print what the raw messages say."""
    rows = [r for r in nm.raw if r[1] == task]
    sp = [r[2] for r in rows]
    dups = sorted(p for p, c in __import__("collections").Counter(sp).items() if c > 1)
    t0 = rows[0][0] if rows else 0
    return (f"{task}: raw={len(rows)} unique_sports={len(set(sp))} dup_sports={dups} "
            f"retrans_coalesced={nm.stats['syn_retrans']} "
            f"dup_dt={[round(r[0]-t0, 3) for r in rows if r[2] in dups][:6]}")


@real
def test_every_zero_lifetime_beacon_is_attributed_to_the_right_task(env):
    """The direct counterpart of the sock_diag result, where the same 0 ms connections were 0/60 attributed."""
    cg, fw, made = env
    events = []
    lis, port = listener()
    stop_drain = drain(lis)
    s, nm = monitor(cg, fw, made, events)
    plan = {"alpha": 40, "bravo": 25, "charlie": 60}
    procs = [task(cg, fw, k, beacons(port, n)) for k, n in plan.items()]
    for p in procs:
        p.wait(timeout=60)
    time.sleep(0.8)
    ev = [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]
    per_task = {}
    for e in ev:
        per_task[e["subject"]["cgroup"]] = per_task.get(e["subject"]["cgroup"], 0) + 1
    print(f"\n{sum(plan.values())} zero-lifetime beacons across 3 tasks -> attributed per task: {per_task}; "
          f"slips={nm.slips_by_port[port]} lost={nm.lost()}")
    assert dict(nm.syn_by_task) == plan, "\n".join(explain(nm, k) for k in plan)   # every SYN, to the right task, exactly
    assert per_task == plan and len(ev) == sum(plan.values())  # one event each: no loss, no duplicates
    assert all(e["anomaly"]["evidence"]["via"] == "syn_tap" for e in ev)
    assert nm.slips_by_port[port] == 0 and nm.stats["owner_gone"] == 0 and nm.lost() == 0
    stop_drain.set(); lis.close()


@real
def test_flood_of_1500_beacons_loses_nothing(env):
    cg, fw, made = env
    events = []
    lis, port = listener()
    stop_drain = drain(lis)
    s, nm = monitor(cg, fw, made, events)
    p = task(cg, fw, "flood", beacons(port, 1500))
    p.wait(timeout=90)
    time.sleep(1.0)
    print(f"\n1500 beacons: syn events={nm.stats['syn']} lost={nm.lost()} slips={nm.slips_by_port[port]}")
    assert nm.syn_by_task["flood"] == 1500 and nm.lost() == 0 and nm.slips_by_port[port] == 0
    stop_drain.set(); lis.close()


@real
def test_retransmitted_syns_coalesce_into_one_connection(env):
    """A listener that never accepts overflows its queue, so TCP retransmits SYNs. Those are the SAME
    connection: counting packets instead of connections would inflate events and quarantine on noise."""
    cg, fw, made = env
    events = []
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(1)       # tiny queue, nobody accepts
    port = lis.getsockname()[1]
    s, nm = monitor(cg, fw, made, events)
    code = (f"import socket,time\nss=[]\nfor _ in range(8):\n    x=socket.socket(); x.setblocking(False)\n"
            f"    x.connect_ex(('{LOCAL}',{port})); ss.append(x)\ntime.sleep(3.2)")   # outlives the 1 s SYN RTO
    task(cg, fw, "retx", code).wait(timeout=30)
    time.sleep(0.5)
    print(f"\n8 connection attempts: {nm.stats['syn']} connections counted, {nm.stats['syn_retrans']} SYN retransmits coalesced")
    assert nm.syn_by_task["retx"] == 8 and nm.stats["syn_retrans"] >= 1
    assert len([e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]) == 8
    lis.close()


@real
def test_syn_to_receipt_latency_is_measured_with_a_concurrent_reader(env):
    """Honest latency: a reader thread timestamps each event on arrival while the task runs.
    Upper bound, since the child's clock read precedes its connect() syscall."""
    cg, fw, made = env
    lis, port = listener()
    cg.create("lat")
    tr = TapRules(fw, GROUP)
    tr.ensure_chain(); tr.sync({"lat": os.stat(cg.root / "lat").st_ino})
    nl = NflogListener(GROUP)
    got, stop = [], threading.Event()

    def reader():
        while not stop.is_set():
            got.extend(nl.poll(0.05))
    th = threading.Thread(target=reader); th.start()
    N = 200
    code = (f"import socket,time\nt=[]\nfor _ in range({N}):\n    a=time.time_ns()\n"
            f"    socket.create_connection(('{LOCAL}',{port})).close(); t.append(a); time.sleep(0.002)\n"
            f"print(*t)")
    p = task(cg, fw, "lat", code)
    out = p.communicate(timeout=60)[0].split()
    time.sleep(0.5); stop.set(); th.join(); nl.close()
    t_before = [int(x) for x in out]
    assert len(got) == N == len(t_before)
    d = sorted((g.recv_ns - tb) / 1000 for g, tb in zip(got, t_before))
    print(f"\nconnect() call -> userspace receipt over {N} beacons: median {statistics.median(d):.0f} us, "
          f"p99 {d[int(N*.99)-1]:.0f} us, max {d[-1]:.0f} us (kernel timestamp is absent; this is receipt time)")
    assert statistics.median(d) < 20_000 and d[-1] < 500_000
    lis.close()


@real
def test_an_isolated_tasks_attempts_are_still_logged(env):
    """The tap runs at priority -10, before the egress drop at 0: containment must not blind the tap."""
    cg, fw, made = env
    cg.create("jailed")
    tr = TapRules(fw, GROUP)
    tr.ensure_chain(); tr.sync({"jailed": os.stat(cg.root / "jailed").st_ino})
    assert fw.block("jailed")
    nl = NflogListener(GROUP)
    code = (f"import socket\nfor _ in range(5):\n    s=socket.socket(); s.settimeout(0.3)\n"
            f"    print(s.connect_ex(('{GW}',80)))")
    p = task(cg, fw, "jailed", code)
    errs = p.communicate(timeout=30)[0].split()
    seen = []
    end = time.monotonic() + 2
    while time.monotonic() < end and len(seen) < 5:
        seen += nl.poll(0.2)
    nl.close()
    assert all(e != "0" for e in errs) and len(errs) == 5       # none connected: a dropped SYN is a timeout
    assert [x.task for x in seen] == ["jailed"] * 5 and {x.dst for x in seen} == {GW}


@real
def test_other_processes_are_not_tapped(env):
    cg, fw, made = env
    cg.create("only")
    tr = TapRules(fw, GROUP)
    tr.ensure_chain(); tr.sync({"only": os.stat(cg.root / "only").st_ino})
    nl = NflogListener(GROUP)
    lis, port = listener()
    for _ in range(10):
        socket.create_connection((LOCAL, port)).close()        # this test process is in no task cgroup
    assert nl.poll(0.5) == []
    nl.close(); lis.close()


@real
def test_rule_follows_a_recreated_cgroup(env):
    cg, fw, made = env
    lis, port = listener()
    tr = TapRules(fw, GROUP)
    tr.ensure_chain(); cg.create("again"); tr.sync({"again": os.stat(cg.root / "again").st_ino})
    (cg.root / "again").rmdir(); cg.create("again")           # new task, same name, new cgroup id
    nl = NflogListener(GROUP)
    task(cg, fw, "again", beacons(port, 3, hold=0.2), preinstall=False)
    time.sleep(0.01)
    # the OLD rule matches the OLD id: a process in the recreated cgroup is not seen until sync repairs it
    tr.sync({"again": os.stat(cg.root / "again").st_ino})
    assert tr.rules()["again"]["cgid"] == os.stat(cg.root / "again").st_ino and len(tr.rules()) == 1
    nl.close(); lis.close()


@real
def test_cora_run_installs_the_rule_before_exec_so_the_first_syn_is_attributed(env):
    """No monitor is running and nobody synced: only cora_run's pre-install can make this work."""
    cg, fw, made = env
    lis, port = listener()
    tr = TapRules(fw, GROUP)
    tr.ensure_chain()                                         # the sentinel's chain exists ...
    nl = NflogListener(GROUP)
    task(cg, fw, "firstsyn", f"import socket;socket.create_connection(('{LOCAL}',{port})).close()").wait(timeout=30)
    got = nl.poll(1.0)
    nl.close(); lis.close()
    assert [g.task for g in got] == ["firstsyn"]               # ... so the task's very first connect() was seen


@real
def test_documented_gap_a_task_started_without_cora_run_is_unobserved_until_synced(env):
    cg, fw, made = env
    lis, port = listener()
    tr = TapRules(fw, GROUP)
    tr.ensure_chain()
    nl = NflogListener(GROUP)
    cg.create("rawtask")
    code = (f"import socket\nopen('{cg.root}/rawtask/cgroup.procs','w').write('0')\n"
            f"socket.create_connection(('{LOCAL}',{port})).close()")
    subprocess.run([sys.executable, "-c", code], timeout=30)
    assert nl.poll(0.5) == []                                  # no rule yet: the limit, pinned by a test
    tr.sync({"rawtask": os.stat(cg.root / "rawtask").st_ino})
    subprocess.run([sys.executable, "-c", code], timeout=30)
    assert [g.task for g in nl.poll(1.0)] == ["rawtask"]       # one sync later it is covered
    nl.close(); lis.close()


@real
def test_a_group_can_only_be_bound_once_and_teardown_releases_it(env):
    cg, fw, made = env
    first = NflogListener(GROUP)
    with pytest.raises(OSError) as e:
        NflogListener(GROUP)
    assert "already bound" in str(e.value) or "CAP_NET_ADMIN" in str(e.value)
    first.close()
    svc = TapService(fw, GROUP)                                # the group is free again
    assert svc.rules.active()
    svc.close()
    assert not svc.rules.active()                              # chain removed on close
    NflogListener(GROUP).close()                               # and the group is released


def test_nflog_flag_is_refused_without_its_prerequisites():
    r = subprocess.run([sys.executable, "-m", "cora_sentinel.daemon", "--nflog"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and "--nflog needs" in r.stderr


# ---- ordering regression: a dump can see a SYN_SENT socket before its SYN message is read ----
def test_a_dump_never_judges_a_socket_before_its_syn_message_has_been_drained(tmp_path):
    from cora_sentinel.netmon import NetMonitor
    from cora_sentinel.nflog import Syn
    from cora_sentinel.sockdiag import Sock

    root = tmp_path / "cgroup" / "cora"
    (root / "t1").mkdir(parents=True)
    (root / "t1" / "cgroup.procs").write_text(f"{os.getpid()}\n")
    cg = CgroupRoot(str(root), str(tmp_path / "cgroup"))
    task_id = os.stat(root / "t1").st_ino
    sock = Sock(socket.AF_INET, 2, "10.1.1.5", 40000, "203.0.113.9", 443, 0, 0, 7, task_id)   # SYN_SENT
    syn = Syn("t1", socket.AF_INET, "10.1.1.5", 40000, "203.0.113.9", 443, 0, 1)

    class FakeDiag:
        def dump(self, **kw): return [sock]
        def close(self): pass

    class Queue:                                   # stands in for both netlink sockets
        lost, s = 0, None
        def __init__(self, items): self.items = list(items)
        def poll(self, t):
            out, self.items = self.items, []
            return out
        def close(self): pass

    class FakeTapService:
        def __init__(self): self.listener = Queue([syn])
        def sync(self, cur): return list(cur), []
        def close(self): pass

    class NoProbe(NetMonitor):
        def _probe_cgroup_ids(self): pass

    bl = Blocklist(); bl.add_line("203.0.113.0/24", "rogue")
    events = []
    s = Sentinel("X", ["/tmp"], 10**6, 5, emit=events.append, net_allow=["0.0.0.0/0"],
                 cgroups=cg, blocklist=bl, cooldown_s=0)
    nm = NoProbe(s, diag=FakeDiag(), listener=Queue([]), tap=FakeTapService())
    nm.poll_once()                                 # the dump sees the socket; its SYN is still unread
    ev = [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]
    assert len(ev) == 1 and ev[0]["anomaly"]["evidence"]["via"] == "syn_tap"
    assert nm.stats["dump_dup"] == 1 and nm.stats["live_hits"] == 0


# ============================ UDP / QUIC / DNS: parsing (no kernel) ============================
def dns_query(name="tracker.example.com", qr=0, opcode=0, qd=1, raw_name=None):
    flags = (qr << 15) | (opcode << 11) | 0x0100
    if raw_name is None:
        raw_name = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, flags, qd, 0, 0, 0) + raw_name + struct.pack("!HH", 1, 1)


def udp4(payload, dport=53, sport=40000, src="10.1.1.5", dst="203.0.113.9", frag=0):
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 6, frag)
    ip[9] = 17
    ip[12:16], ip[16:20] = socket.inet_aton(src), socket.inet_aton(dst)
    return bytes(ip) + struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def udp6(payload, dport=443, sport=40001, src="2001:db8::1", dst="2001:db8::beef"):
    ip = bytearray(40)
    ip[0], ip[6] = 0x60, 17
    ip[8:24], ip[24:40] = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
    return bytes(ip) + struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def quic_initial(version=1, first=0xC3):
    return bytes([first]) + struct.pack("!I", version) + b"\x08" + os.urandom(8) + b"\0" + b"\x00" * 1100


def test_dns_names_are_parsed_and_lowercased():
    assert parse_dns_query(dns_query("Ads.Tracker.EXAMPLE.com")) == "ads.tracker.example.com"
    assert parse_dns_query(dns_query("a.b") + b"trailing garbage is fine") == "a.b"


@pytest.mark.parametrize("pkt", [
    dns_query(qr=1), dns_query(opcode=4), dns_query(qd=0), b"\0" * 10, dns_query(raw_name=b"\xc0\x0c"),
    dns_query(raw_name=b"\x05ab"), dns_query(raw_name=bytes([64]) + b"a" * 64 + b"\0"),
    dns_query(raw_name=b"\0"), dns_query(raw_name=b"\x03\xff\xfe\xfd\0"),
    dns_query(raw_name=b"".join(bytes([63]) + b"a" * 63 for _ in range(5)) + b"\0")])
def test_anything_that_is_not_a_plain_dns_question_is_rejected(pkt):
    with pytest.raises(ValueError):
        parse_dns_query(pkt)


@pytest.mark.parametrize("dport,payload,expect", [
    (53, dns_query("x.example.org"), ("dns", "x.example.org")),
    (53, b"not dns", (None, None)),
    (443, quic_initial(1), ("quic", None)),
    (443, quic_initial(0x6B3343CF), ("quic", None)),              # QUIC v2
    (443, quic_initial(0xFF00001D), ("quic", None)),              # IETF draft-29
    (443, quic_initial(0xDEADBEEF), (None, None)),                # unknown version
    (443, bytes([0x43]) + b"\0" * 40, (None, None)),              # short header: not a flow start
    (443, b"\xc3\0", (None, None)),                               # too short to carry a version
    (8443, quic_initial(1), (None, None)),                        # only 443 is labelled
    (5000, dns_query(), (None, None))])
def test_udp_classification(dport, payload, expect):
    assert classify_udp(dport, payload) == expect


def test_parse_udp_flow_v4_v6_and_the_payload_survives():
    p = parse_ip_flow(udp4(b"hello", dport=5300))
    assert p[:6] == ("udp", socket.AF_INET, "10.1.1.5", 40000, "203.0.113.9", 5300) and p[6] == b"hello"
    q = parse_ip_flow(udp6(b"quic!"))
    assert q[:6] == ("udp", socket.AF_INET6, "2001:db8::1", 40001, "2001:db8::beef", 443) and q[6] == b"quic!"
    assert parse_ip_flow(ipv4())[0] == "tcp"                       # TCP still works through the same entry point


@pytest.mark.parametrize("pkt", [udp4(b"x", frag=0x0010), udp4(b"x")[:24], b"\x45" + b"\0" * 30])
def test_fragments_and_truncated_udp_are_rejected(pkt):
    with pytest.raises(ValueError):
        parse_ip_flow(pkt)


def test_a_udp_message_becomes_a_flow_with_its_l7_label_and_name():
    s = parse_packet_msg(nflog_body(pay=udp4(dns_query("Doubleclick.net"), dport=53)), 5)
    assert (s.proto, s.l7, s.qname, s.task, s.dport) == ("udp", "dns", "doubleclick.net", "etl", 53)
    q = parse_packet_msg(nflog_body(pay=udp6(quic_initial(1))), 6)
    assert (q.proto, q.l7, q.qname) == ("udp", "quic", None)


# ============================ UDP rule management (fake nft) ============================
def test_udp_mode_creates_both_flow_sets_and_five_rules_per_task(tapfake_udp):
    t, cg, n = tapfake_udp
    t.ensure_chain(); cg.create("a")
    assert n.sets == {"cora_flow4", "cora_flow6"} and n.chain
    t.sync({"a": os.stat(cg.root / "a").st_ino})
    comments = [r["comment"].split(":")[0] for r in n.rules]
    assert comments == ["cora-tap", "cora-tap-u4s", "cora-tap-u4l", "cora-tap-u6s", "cora-tap-u6l"]
    assert t.rules()["a"]["kinds"] == {"t", "u4s", "u4l", "u6s", "u6l"}


def test_the_once_gate_always_precedes_the_log_rule_and_snaplens_differ(tapfake_udp):
    t, cg, n = tapfake_udp
    cg.create("a")
    tx = t.rule_texts("a")
    assert list(tx) == ["t", "u4s", "u4l", "u6s", "u6l"]
    assert "@cora_flow4 update @cora_flow4" in tx["u4s"] and " return " in tx["u4s"] and "log" not in tx["u4s"]
    assert "add @cora_flow4" in tx["u4l"] and "snaplen 320" in tx["u4l"]
    # the TASK is part of the flow identity: socket cgroup . daddr . dport . sport
    assert "socket cgroupv2 level 2 . ip daddr . udp dport . udp sport" in tx["u4l"]
    assert "socket cgroupv2 level 2 . ip6 daddr . udp dport . udp sport" in tx["u6l"] and "@cora_flow6" in tx["u6l"]
    assert "snaplen 128" in tx["t"]                                 # TCP needs only the headers


def test_a_partial_rule_set_is_repaired_as_a_whole(tapfake_udp):
    t, cg, n = tapfake_udp
    t.ensure_chain(); cg.create("a")
    live = {"a": os.stat(cg.root / "a").st_ino}
    t.sync(live)
    n.rules = [r for r in n.rules if "u6l" not in r["comment"]]     # a crash left 4 of 5
    added, _ = t.sync(live)
    assert added == ["a"] and len(n.rules) == 5 and t.rules()["a"]["kinds"] == {"t", "u4s", "u4l", "u6s", "u6l"}
    assert t.sync(live) == ([], [])                                 # and now it is stable


def test_a_stale_udp_rule_set_is_replaced_not_accumulated(tapfake_udp):
    t, cg, n = tapfake_udp
    t.ensure_chain(); cg.create("a")
    t.sync({"a": os.stat(cg.root / "a").st_ino})
    for r in n.rules:
        r["comment"] = r["comment"].rsplit(":", 1)[0] + ":999999"   # all five belong to an older cgroup
    t.sync({"a": os.stat(cg.root / "a").st_ino})
    assert len(n.rules) == 5 and t.rules()["a"]["cgid"] == os.stat(cg.root / "a").st_ino


def test_cora_run_style_autodetect_follows_the_live_table(tapfake_udp):
    t, cg, n = tapfake_udp
    t.ensure_chain(); cg.create("a")
    auto = TapRules(t.fw, 88, udp=None)
    assert auto.udp_enabled() and auto._needed() == {"t", "u4s", "u4l", "u6s", "u6l"}
    n.sets.clear()                                                  # a sentinel running --no-tap-udp
    assert not auto.udp_enabled() and auto._needed() == {"t"}


def test_teardown_removes_the_chain_and_both_sets(tapfake_udp):
    t, cg, n = tapfake_udp
    t.ensure_chain(); cg.create("a"); t.sync({"a": 1})
    t.teardown()
    assert not n.chain and n.rules == [] and n.sets == set()


# ============================ judging UDP/DNS/QUIC (no kernel) ============================
def detector(lines=(), allow=(), nets=("127.0.0.0/8", "::1/128", "10.0.0.0/8")):
    bl = Blocklist()
    for ln in lines:
        bl.add_line(ln, "ads")
    if allow:
        bl.allow = Blocklist()
        for ln in allow:
            bl.allow.add_line(ln, "ok")
    return ConnDetector(NetPolicy(list(nets)), bl)


def test_a_listed_dns_name_is_a_hit_even_through_an_allowed_resolver():
    j = detector(["doubleclick.net"]).judge("127.0.0.53", 53, 40000, proto="udp", l7="dns", qname="stats.g.doubleclick.net")
    assert j["severity"] == "high" and j["evidence"]["l7"] == "dns" and j["evidence"]["qname"] == "stats.g.doubleclick.net"
    assert j["evidence"]["blocklist"] == {"list": "ads", "kind": "tracker_domain", "entry": "doubleclick.net"}


def test_an_unlisted_dns_name_via_an_allowed_resolver_is_nothing():
    assert detector(["doubleclick.net"]).judge("127.0.0.53", 53, 40000, proto="udp", l7="dns", qname="example.org") is None


def test_a_lookup_to_an_unauthorized_resolver_is_only_medium_and_has_no_blocklist_key():
    j = detector(["doubleclick.net"]).judge("8.8.8.8", 53, 40000, proto="udp", l7="dns", qname="example.org")
    assert j["severity"] == "medium" and "blocklist" not in j["evidence"] and j["evidence"]["dest_class"] == "public"


def test_the_allow_list_overrides_a_listed_dns_name():
    d = detector(["doubleclick.net"], allow=["doubleclick.net"])
    assert d.judge("127.0.0.53", 53, 40000, proto="udp", l7="dns", qname="doubleclick.net") is None


def test_quic_to_a_listed_address_is_high_and_labelled():
    j = detector(["203.0.113.0/24"]).judge("203.0.113.7", 443, 40443, proto="udp", l7="quic")
    assert j["severity"] == "high" and j["evidence"]["proto"] == "udp" and j["evidence"]["l7"] == "quic"
    assert "qname" not in j["evidence"]


def test_tcp_evidence_is_unchanged_by_the_udp_work():
    j = detector(["203.0.113.0/24"]).judge("203.0.113.7", 443, 40443)
    assert set(j["evidence"]) == {"remote_ip", "remote_port", "local_port", "dest_class", "blocklist"}


# ============================ UDP / QUIC / DNS on the real kernel ============================
def udp_beacons(port, n, hold=1.5, payload="b'x'", sport_base=None, report_ports=False):
    """n zero-lifetime UDP flows. sport_base pins a distinct source port per beacon (below the ephemeral
    range) so flows are distinct by construction; otherwise the kernel picks them at RANDOM, and 125
    closed-at-once sockets collide at the birthday rate (~1 run in 4 on a real kernel)."""
    bind = f"s.bind(('',{sport_base}+i)); " if sport_base else ""
    note = "ports.append(s.getsockname()[1]); " if report_ports else ""
    out = "print(len(set(ports)))\n" if report_ports else ""
    return (f"import socket,struct,time\nports=[]\nfor i in range({n}):\n"
            f"    s=socket.socket(2,2); {bind}s.sendto({payload},('{LOCAL}',{port})); {note}s.close()\n{out}time.sleep({hold})")


def dns_code(names, host):
    return ("import socket,struct,time\n"
            "def q(n):\n    raw=b''.join(bytes([len(p)])+p.encode() for p in n.split('.'))+b'\\0'\n"
            "    return struct.pack('!HHHHHH',0x1234,0x0100,1,0,0,0)+raw+struct.pack('!HH',1,1)\n"
            f"for i, n in enumerate({list(names)!r}):\n    s=socket.socket(2,2); s.bind(('',22500+i)); s.sendto(q(n),('{host}',53)); s.close()\n"
            "time.sleep(1.5)")


def udp_events(events):
    return [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"
            and e["anomaly"]["evidence"].get("proto") == "udp"]


@real
def test_every_zero_lifetime_udp_beacon_is_attributed_to_the_right_task(env):
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    plan = {"uone": 40, "utwo": 25, "uthree": 60}
    procs = [task(cg, fw, k, udp_beacons(5300, n, sport_base=21000 + 1000 * i))
             for i, (k, n) in enumerate(plan.items())]
    for p in procs:
        p.wait(timeout=60)
    time.sleep(0.8)
    ev = udp_events(events)
    per_task = {}
    for e in ev:
        per_task[e["subject"]["cgroup"]] = per_task.get(e["subject"]["cgroup"], 0) + 1
    print(f"\n{sum(plan.values())} UDP beacons (each a new flow, socket closed at once) -> per task: {per_task}; lost={nm.lost()}")
    why = f"stats={dict(nm.stats)} owner_diag={nm.owner_diag}"     # if this ever fails, say WHY
    assert dict(nm.udp_by_task) == plan, why
    assert per_task == plan and len(ev) == sum(plan.values()), why
    assert all(e["anomaly"]["evidence"]["via"] == "udp_tap" for e in ev) and nm.lost() == 0


@real
def test_a_20000_packet_one_way_udp_flood_is_one_event_not_20000(env):
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    code = (f"import socket,time\nu=socket.socket(2,2)\nfor _ in range(20000):\n"
            f"    u.sendto(b'x',('{LOCAL}',5302))\ntime.sleep(1)")
    task(cg, fw, "flood", code).wait(timeout=60)
    time.sleep(0.8)
    print(f"\n20000 packets on one flow -> {nm.udp_by_task['flood']} event(s), lost={nm.lost()}")
    assert nm.udp_by_task["flood"] == 1 and nm.lost() == 0 and len(udp_events(events)) == 1


@real
def test_a_listed_dns_name_is_caught_at_query_time_by_name_and_unlisted_names_are_not(env):
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events, lines=["ads.tracker-test.example"])   # a NAME, not an address
    task(cg, fw, "dns", dns_code(["ads.tracker-test.example", "fine.example.org"], LOCAL)).wait(timeout=30)
    time.sleep(0.6)
    ev = udp_events(events)
    assert nm.stats["udp_dns"] == 2 and len(ev) == 1
    e = ev[0]["anomaly"]["evidence"]
    assert e["l7"] == "dns" and e["qname"] == "ads.tracker-test.example"
    assert e["blocklist"] == {"list": "rogue", "kind": "tracker_domain", "entry": "ads.tracker-test.example"}


@real
def test_quic_initial_is_labelled_and_a_listed_destination_is_caught(env):
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    quic = "bytes([0xC3])+struct.pack('!I',1)+b'\\x00'*1100"
    task(cg, fw, "quic", udp_beacons(443, 3, payload=quic, sport_base=22000)).wait(timeout=30)
    time.sleep(0.6)
    ev = udp_events(events)
    assert nm.stats["udp_quic"] == 3 and len(ev) == 3
    assert all(e["anomaly"]["evidence"]["l7"] == "quic" and e["anomaly"]["evidence"]["remote_port"] == 443 for e in ev)


@real
def test_an_isolated_tasks_udp_is_still_logged(env):
    cg, fw, made = env
    cg.create("jailu")
    tr = TapRules(fw, GROUP, udp=True)
    tr.ensure_chain(); tr.sync({"jailu": os.stat(cg.root / "jailu").st_ino})
    assert fw.block("jailu")
    nl = NflogListener(GROUP)
    code = (f"import socket\nfor _ in range(3):\n    s=socket.socket(2,2)\n"
            f"    try:\n        s.sendto(b'x',('{GW}',9)); print(0)\n    except OSError as e:\n        print(e.errno)")
    errs = task(cg, fw, "jailu", code).communicate(timeout=30)[0].split()
    seen = []
    end = time.monotonic() + 2
    while time.monotonic() < end and len(seen) < 3:
        seen += nl.poll(0.2)
    nl.close()
    assert errs == ["1"] * 3                                       # EPERM: the egress drop really happened
    assert [(x.task, x.proto) for x in seen] == [("jailu", "udp")] * 3


@real
def test_an_idle_udp_flow_is_a_new_flow_after_the_timeout_but_a_busy_one_is_not(env):
    cg, fw, made = env
    cg.create("idle")
    tr = TapRules(fw, GROUP, udp=True, udp_timeout=2)
    tr.ensure_chain(); tr.sync({"idle": os.stat(cg.root / "idle").st_ino})
    nl = NflogListener(GROUP)
    code = (f"import socket,time\nu=socket.socket(2,2)\nfor _ in range(3):\n    u.sendto(b'a',('{LOCAL}',5303))\n"
            f"time.sleep(2.8)\nu.sendto(b'again',('{LOCAL}',5303))")
    task(cg, fw, "idle", code).wait(timeout=30)
    got = []
    end = time.monotonic() + 1.5
    while time.monotonic() < end:
        got += nl.poll(0.2)
    nl.close()
    assert len(got) == 2                                           # 3 quick packets -> 1; after 2.8 s idle -> 1 more


@real
def test_cora_run_preinstalls_the_udp_rules_too(env):
    cg, fw, made = env
    tr = TapRules(fw, GROUP, udp=True)
    tr.ensure_chain()                                              # a sentinel is "running": chain + sets exist
    nl = NflogListener(GROUP)
    task(cg, fw, "firstudp", f"import socket;socket.socket(2,2).sendto(b'x',('{LOCAL}',5304))").wait(timeout=30)
    got = nl.poll(1.0)
    nl.close()
    assert [(g.task, g.proto, g.dport) for g in got] == [("firstudp", "udp", 5304)]


@real
def test_tcp_only_mode_creates_no_udp_sets_and_ignores_udp(env):
    cg, fw, made = env
    events = []
    lis, port = listener()
    stop_drain = drain(lis)
    s, nm = monitor(cg, fw, made, events, udp=False)
    rc, _, _ = fw._run(["list", "set", "inet", fw.table, "cora_flow4"], None)
    assert rc != 0                                                 # the sets were never created
    code = (f"import socket,time\nsocket.socket(2,2).sendto(b'x',('{LOCAL}',5305))\n"
            f"socket.create_connection(('{LOCAL}',{port})).close()\ntime.sleep(1.2)")
    task(cg, fw, "tcponly", code).wait(timeout=30)
    time.sleep(0.6)
    assert nm.udp_by_task == {} and nm.syn_by_task["tcponly"] == 1
    stop_drain.set(); lis.close()


# ============================ regressions: duplicate rules and duplicate SYN messages ============================
def _netmon_with_fake_tap(tmp_path):
    from cora_sentinel.netmon import NetMonitor
    root = tmp_path / "cgroup" / "cora"
    (root / "t1").mkdir(parents=True)
    (root / "t1" / "cgroup.procs").write_text(f"{os.getpid()}\n")
    cg = CgroupRoot(str(root), str(tmp_path / "cgroup"))

    class Q:
        lost, s = 0, None
        def poll(self, t): return []
        def close(self): pass

    class FakeTap:
        listener = Q()
        def sync(self, cur): return list(cur), []
        def close(self): pass

    class NoProbe(NetMonitor):
        def _probe_cgroup_ids(self): pass

    s = Sentinel("X", ["/tmp"], 10**6, 5, emit=lambda p: None, net_allow=["0.0.0.0/0"], cgroups=cg, cooldown_s=0)
    class FakeDiag:
        def dump(self, **kw): return []
        def close(self): pass
    return NoProbe(s, diag=FakeDiag(), listener=Q(), tap=FakeTap())


def test_a_duplicate_syn_message_is_one_connection_even_after_the_socket_was_destroyed(tmp_path):
    """The straddle: a duplicate message (from a duplicated rule, or a retransmit) that arrives AFTER the
    destroy event cleared the 3-tuple used to be counted as a second connection."""
    from cora_sentinel.nflog import Syn
    from cora_sentinel.sockdiag import Sock
    nm = _netmon_with_fake_tap(tmp_path)
    syn = Syn("t1", socket.AF_INET, "10.1.1.5", 40000, "203.0.113.9", 443, 0, 1, seq=1111)
    nm._on_syn(syn)
    nm._on_destroy(Sock(socket.AF_INET, 7, "10.1.1.5", 40000, "203.0.113.9", 443, 0, 0, 9, None))   # socket gone
    nm._on_syn(syn)                                                                                  # the straggler
    assert nm.stats["syn"] == 1 and nm.stats["syn_retrans"] == 1 and nm.syn_by_task["t1"] == 1


def test_a_new_connection_reusing_the_same_port_is_not_mistaken_for_a_retransmit(tmp_path):
    from cora_sentinel.nflog import Syn
    from cora_sentinel.sockdiag import Sock
    nm = _netmon_with_fake_tap(tmp_path)
    nm._on_syn(Syn("t1", socket.AF_INET, "10.1.1.5", 40000, "203.0.113.9", 443, 0, 1, seq=1111))
    nm._on_destroy(Sock(socket.AF_INET, 7, "10.1.1.5", 40000, "203.0.113.9", 443, 0, 0, 9, None))
    nm._on_syn(Syn("t1", socket.AF_INET, "10.1.1.5", 40000, "203.0.113.9", 443, 0, 2, seq=2222))    # new ISN
    assert nm.stats["syn"] == 2 and nm.stats["syn_retrans"] == 0


def test_the_tcp_initial_sequence_number_is_parsed_from_the_packet():
    pkt = bytearray(ipv4())
    struct.pack_into("!I", pkt, 20 + 4, 0xDEADBEEF)
    assert parse_packet_msg(nflog_body(pay=bytes(pkt)), 1).seq == 0xDEADBEEF
    assert parse_packet_msg(nflog_body(pay=udp4(b"x", dport=5000)), 1).seq is None


def test_a_rule_set_with_a_duplicated_rule_is_repaired_by_sync(tapfake):
    t, cg, n = tapfake
    t.ensure_chain(); cg.create("a")
    live = {"a": os.stat(cg.root / "a").st_ino}
    t.sync(live)
    n.rules.append(dict(n.rules[0], handle=n.next)); n.next += 1        # the race left a second identical rule
    assert len(n.rules) == 2 and t.rules()["a"]["kinds"] == {"t"}         # kinds alone cannot see the duplicate
    added, _ = t.sync(live)
    assert added == ["a"] and len(n.rules) == 1 and t.sync(live) == ([], [])


def test_concurrent_installers_never_duplicate_a_tasks_rules(tmp_path):
    """cora_run and the monitor both read-then-add. Without a lock, interleaved readers each add a copy."""
    base = tmp_path / "cgroup"; root = base / "cora"; (root / "a").mkdir(parents=True)
    fake = FakeTapNft()
    real_call = fake.__call__

    def slow(args, stdin):                          # open the window AFTER the read: "I looked, nothing there"
        out = real_call(args, stdin)                # ... and only then let the other threads in, so they
        if args[:2] == ["-j", "list"]:              # all read the same empty state before anyone adds
            time.sleep(0.02)
        return out
    cg = CgroupRoot(str(root), str(base))
    barrier = threading.Barrier(8)

    def installer():
        t = TapRules(Firewall(cg, table=f"racetest{os.getpid()}", nft_base=str(base), run=slow), 88, udp=False)
        t.ensure_chain()
        barrier.wait()
        t.install("a")
    threads = [threading.Thread(target=installer) for _ in range(8)]
    [th.start() for th in threads]; [th.join() for th in threads]
    for lock in ("/run/lock", tempfile.gettempdir()):
        try: os.unlink(os.path.join(lock, f"cora-tap-racetest{os.getpid()}.lock"))
        except OSError: pass
    assert len(fake.rules) == 1


@real
def test_pre_install_racing_the_monitors_sync_never_leaves_duplicate_rules(env):
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events, interval=0.02, udp=False)     # the monitor syncs every 20 ms
    tr = TapRules(fw, GROUP, udp=False)
    dups = []
    for i in range(20):
        p = task(cg, fw, f"race{i}", "import time;time.sleep(0.5)")      # cora_run pre-installs at the same moment
        time.sleep(0.35)
        e = tr.rules().get(f"race{i}")
        if e and len(e["handles"]) != 1:
            dups.append((f"race{i}", len(e["handles"])))
        p.wait(timeout=10)
    assert dups == []


# ---- argument validation must come before any file is touched ----
def _daemon(*args):
    return subprocess.run([sys.executable, "-m", "cora_sentinel.daemon", *args], capture_output=True, text=True, timeout=30)


def test_a_bad_flag_combination_is_reported_before_any_file_is_opened():
    """Regression: the daemon used to open --out first, so in an unwritable directory a plain usage
    error surfaced as a PermissionError traceback instead of the real message."""
    r = _daemon("--nflog", "--out", "/nonexistent-dir/events.jsonl")
    assert r.returncode == 1 and "--nflog needs" in r.stderr and "Traceback" not in r.stderr


def test_an_unwritable_output_path_is_a_clean_error_not_a_traceback():
    r = _daemon("--out", "/nonexistent-dir/events.jsonl")
    assert r.returncode == 1 and "Traceback" not in r.stderr and "cannot open" in r.stderr


# ============ UDP flow identity: one task must never suppress another task's flow ============
FIXED = ("import socket,time\nu=socket.socket(2,2); u.bind(('',23456)); "
         "u.sendto(b'x',('%s',5310)); u.close()\ntime.sleep(1)")


@real
def test_two_tasks_with_the_same_source_port_to_the_same_destination_are_both_attributed(env):
    """Regression, found on bare metal. The once-per-flow set was keyed (daddr, dport, sport) and shared by
    every task, so a second task's identical-looking flow was swallowed and never attributed: a task
    contacting a blocklisted address could escape isolation because of someone else's earlier packet."""
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    task(cg, fw, "xone", FIXED % LOCAL).wait(timeout=30)      # sequential, so the source port is free again
    task(cg, fw, "xtwo", FIXED % LOCAL).wait(timeout=30)
    time.sleep(0.6)
    assert dict(nm.udp_by_task) == {"xone": 1, "xtwo": 1}
    assert sorted(e["subject"]["cgroup"] for e in udp_events(events)) == ["xone", "xtwo"]


@real
def test_one_task_repeating_the_same_flow_is_a_single_flow_by_design(env):
    """Same task, same destination, same source port, inside the idle timeout: it IS the same flow, and
    the per-task cooldown would collapse its events anyway. Documented behaviour, not a loss."""
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    code = ("import socket,time\nfor _ in range(2):\n    u=socket.socket(2,2); u.bind(('',23457)); "
            f"u.sendto(b'x',('{LOCAL}',5311)); u.close()\ntime.sleep(1)")
    task(cg, fw, "same", code).wait(timeout=30)
    time.sleep(0.6)
    assert dict(nm.udp_by_task) == {"same": 1}


@real
def test_random_source_ports_never_cost_any_task_a_flow(env):
    """The oracle holds under ANY port allocator: each child reports how many DISTINCT source ports it used,
    and its events must equal exactly that. Same-task collisions coalesce (see above); a collision with
    another task must cost nothing. 1,800 flows across 3 tasks to one destination."""
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    names = ["rone", "rtwo", "rthree"]
    procs = [task(cg, fw, n, udp_beacons(5312, 600, hold=1.0, report_ports=True)) for n in names]
    distinct = {n: int(p.communicate(timeout=90)[0].split()[-1]) for n, p in zip(names, procs)}
    time.sleep(0.8)
    print(f"\ndistinct source ports used per task: {distinct}; events per task: {dict(nm.udp_by_task)}")
    assert dict(nm.udp_by_task) == distinct and nm.lost() == 0


def test_an_nft_that_cannot_key_a_set_on_the_cgroup_fails_loudly_with_the_way_out(tmp_path):
    """The cgroup-keyed flow set needs a recent nft. If it is refused, say so and say what to do."""
    base = tmp_path / "cgroup"; root = base / "cora"; root.mkdir(parents=True)

    def refuses(args, stdin):
        if args == ["-f", "-"] and "typeof socket" in stdin:
            return 1, "", "Error: syntax error, unexpected socket"
        return 0, "", ""
    fw = Firewall(CgroupRoot(str(root), str(base)), table=f"hint{os.getpid()}", nft_base=str(base), run=refuses)
    with pytest.raises(Exception) as e:
        TapRules(fw, 88, udp=True).ensure_chain()
    assert "--no-tap-udp" in str(e.value) and "socket cgroupv2" in str(e.value)
    TapRules(fw, 88, udp=False).ensure_chain()                    # TCP-only never needs that feature


# ============ owner resolution: a violation by a known task must not vanish ============
def _owner_monitor(tmp_path, procs):
    """A monitor over a fake cgroup directory whose cgroup.procs we control, with a blocklisted 203.0.113.0/24."""
    from cora_sentinel.netmon import NetMonitor
    root = tmp_path / "cgroup" / "cora"
    (root / "t1").mkdir(parents=True)
    procfile = root / "t1" / "cgroup.procs"
    procfile.write_text("".join(f"{p}\n" for p in procs))

    class Q:
        lost, s = 0, None
        def poll(self, t): return []
        def close(self): pass

    class FakeTap:
        listener = Q()
        def sync(self, cur): return list(cur), []
        def close(self): pass

    class FakeDiag:
        def dump(self, **kw): return []
        def close(self): pass

    class NoProbe(NetMonitor):
        def _probe_cgroup_ids(self): pass

    bl = Blocklist(); bl.add_line("203.0.113.0/24", "rogue")
    events = []
    s = Sentinel("X", ["/tmp"], 10**6, 5, emit=events.append, net_allow=["0.0.0.0/0"],
                 cgroups=CgroupRoot(str(root), str(tmp_path / "cgroup")), blocklist=bl, cooldown_s=0)
    return NoProbe(s, diag=FakeDiag(), listener=Q(), tap=FakeTap()), events, procfile


def _udp_syn(dport=5300, sport=40000):
    from cora_sentinel.nflog import Syn
    return Syn("t1", socket.AF_INET, "10.1.1.5", sport, "203.0.113.9", dport, 0, 1, proto="udp")


DEAD_PID = 4194300      # above any real pid_max default: guaranteed not to exist


def test_the_owner_is_any_live_member_of_the_task_not_just_the_first_pid(tmp_path):
    nm, events, _ = _owner_monitor(tmp_path, [DEAD_PID, os.getpid()])     # the FIRST pid is unreadable
    nm._on_udp(_udp_syn(), time.monotonic())
    ev = [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]
    assert len(ev) == 1 and ev[0]["subject"]["pid"] == os.getpid() and nm.stats["owner_gone"] == 0


def test_a_violation_by_a_task_that_exited_is_still_reported_from_its_last_known_identity(tmp_path):
    """Regression-shaped: the tap attributes a flow to a KNOWN task; the task is gone by the time we process
    it. That used to vanish from the verdict and report pipeline. The gate still refuses to act on the dead pid."""
    nm, events, procfile = _owner_monitor(tmp_path, [os.getpid()])
    nm.poll_once()                                    # the task is seen alive: its identity is remembered
    procfile.write_text("")                           # ... then it exits (cgroup now empty)
    nm._on_udp(_udp_syn(), time.monotonic())
    ev = [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]
    assert len(ev) == 1 and ev[0]["subject"]["pid"] == os.getpid()
    assert ev[0]["anomaly"]["evidence"]["owner_exited"] is True
    assert nm.stats["owner_cached"] == 1 and nm.stats["owner_gone"] == 0


def test_a_task_never_seen_alive_and_already_gone_cannot_be_dispatched_but_says_why(tmp_path):
    nm, events, procfile = _owner_monitor(tmp_path, [])                   # empty from the start, no cache
    nm._on_udp(_udp_syn(), time.monotonic())
    assert [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"] == []
    assert nm.stats["owner_gone"] == 1
    assert any("cgroup.procs empty" in d for d in nm.owner_diag)          # the next failure explains itself


def test_diagnostics_name_the_state_of_each_unreadable_pid(tmp_path):
    nm, events, _ = _owner_monitor(tmp_path, [DEAD_PID])
    nm._on_udp(_udp_syn(), time.monotonic())
    assert nm.stats["owner_gone"] == 1 and any(str(DEAD_PID) in d for d in nm.owner_diag)


def test_a_slow_poll_is_measured_so_a_stalled_monitor_is_visible(tmp_path):
    nm, _, _ = _owner_monitor(tmp_path, [os.getpid()])
    real_dump = nm.diag.dump
    nm.diag.dump = lambda **kw: (time.sleep(0.25), real_dump(**kw))[1]
    nm.poll_once()
    assert nm.stats["poll_ms_max"] >= 200


# ============ the event loop must never block on nft, a file lock, or the registry lock ============
class FeedQ:
    """A selectable fake netlink socket: push() makes it readable, poll() hands over what was pushed."""
    lost = 0

    def __init__(self):
        self.s, self._w = socket.socketpair()
        self.items = []

    def push(self, item):
        self.items.append(item)
        self._w.send(b"x")

    def poll(self, timeout):
        self.s.setblocking(False)
        try:
            self.s.recv(4096)
        except OSError:
            pass
        out, self.items = self.items, []
        return out

    def close(self):
        self.s.close(); self._w.close()


def _threaded_monitor(tmp_path, sync=lambda cur: (list(cur), []), timing=None):
    """A monitor whose threads run for real, over a fake cgroup dir and fake netlink sockets."""
    from cora_sentinel.netmon import NetMonitor
    root = tmp_path / "cgroup" / "cora"
    (root / "t1").mkdir(parents=True)
    (root / "t1" / "cgroup.procs").write_text(f"{os.getpid()}\n")
    tapq, destq = FeedQ(), FeedQ()

    class Tap:
        listener = tapq
        last_timing = timing or {}
        def sync(self, cur): return sync(cur)
        def close(self): pass

    class FakeDiag:
        def dump(self, **kw): return []
        def close(self): pass

    class NoProbe(NetMonitor):
        def _probe_cgroup_ids(self): pass

    bl = Blocklist(); bl.add_line("203.0.113.0/24", "rogue")
    events = []
    s = Sentinel("X", ["/tmp"], 10**6, 5, emit=events.append, net_allow=["0.0.0.0/0"],
                 cgroups=CgroupRoot(str(root), str(tmp_path / "cgroup")), blocklist=bl, cooldown_s=0)
    return NoProbe(s, interval=0.05, diag=FakeDiag(), listener=destq, tap=Tap()), events, tapq


def _until(cond, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def _hits(events):
    return [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]


def test_a_blocked_tap_sync_does_not_stop_events_being_processed(tmp_path):
    """Regression for the bare-metal stall (poll_ms_max=13160): nft runs under a cross-process lock, and a slow
    nft used to freeze the whole event loop behind it, so a short-lived task could exit before its events ran."""
    release = threading.Event()
    nm, events, tapq = _threaded_monitor(tmp_path, sync=lambda cur: (release.wait(3), (list(cur), []))[1])
    nm.start()
    try:
        time.sleep(0.3)                                    # the first sync is now stuck inside nft
        assert not release.is_set()
        tapq.push(_udp_syn())
        assert _until(lambda: _hits(events), 1.0), "the event waited behind a blocked nft call"
    finally:
        release.set(); nm.stop()


def test_a_held_registry_lock_does_not_stop_the_loop_draining_events(tmp_path):
    """The adjudicator holds the registry lock while it runs nft for an ISOLATE. The event loop must keep
    draining (and deduping) meanwhile; only DELIVERY may wait."""
    nm, events, tapq = _threaded_monitor(tmp_path)
    nm.start()
    nm.s.net.lock.acquire()                                # an ISOLATE is mid-nft
    try:
        for i in range(5):
            tapq.push(_udp_syn(sport=41000 + i))
        assert _until(lambda: nm.stats["udp"] == 5, 1.0), f"loop stalled after {nm.stats['udp']} of 5 events"
        assert _hits(events) == []                         # delivery is waiting for the lock, as it must
    finally:
        nm.s.net.lock.release()
    assert _until(lambda: len(_hits(events)) == 5, 2.0)    # and nothing is lost once the lock frees
    nm.stop()


def test_a_full_dispatch_queue_drops_loudly_never_silently(tmp_path):
    import queue
    nm, events, tapq = _threaded_monitor(tmp_path)
    nm._dq = queue.Queue(maxsize=2)
    nm.start()
    nm.s.net.lock.acquire()
    try:
        for i in range(8):
            tapq.push(_udp_syn(sport=42000 + i))
        assert _until(lambda: nm.stats["udp"] == 8, 1.0)
        assert nm.stats["dispatch_dropped"] >= 4           # counted (and noted on stderr), not swallowed
    finally:
        nm.s.net.lock.release(); nm.stop()


@real
def test_a_slow_nft_no_longer_stalls_the_event_loop(env, monkeypatch, tmp_path):
    """The bare-metal stall, reproduced and fixed: every nft call takes 0.8 s (a host with a large ruleset).
    0.1.2 measured poll_ms_max=2418 under exactly this. The loop must stay responsive; only the sync worker
    may be slow, and every flow must still be attributed."""
    real_nft = shutil.which("nft")
    shim = tmp_path / "nft"
    shim.write_text(f'#!/bin/sh\nsleep 0.8\nexec {real_nft} "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    plan = {"slowa": 30, "slowb": 20}
    procs = [task(cg, fw, k, udp_beacons(5320, n, hold=4.0, sport_base=24000 + 1000 * i))
             for i, (k, n) in enumerate(plan.items())]
    for p in procs:
        p.wait(timeout=120)
    assert nm.flush(5)
    print(f"\nslow nft: loop poll_ms_max={nm.stats['poll_ms_max']}  tap_sync_ms_max={nm.stats['tap_sync_ms_max']}  "
          f"events per task={dict(nm.udp_by_task)}")
    assert dict(nm.udp_by_task) == plan
    assert len(_hits(events)) == sum(plan.values())
    assert nm.stats["tap_sync_ms_max"] >= 700            # nft really was slow ...
    assert nm.stats["poll_ms_max"] < 400                 # ... and the loop did not care


@real
def test_a_reload_changes_what_is_enforced_while_the_task_and_its_taps_keep_running(env):
    """The point of SIGHUP: swap the lists under a LIVE task on the real kernel. The tap rules (same nft handles),
    the sockets, the cgroup tracking and the task itself are untouched; the new list is enforced on the very next
    flow, attributed to the same task; and the old one stops being enforced the moment it is swapped out."""
    from cora_sentinel.reload import Reloader
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events, lines=["203.0.113.0/24"])               # LOCAL is not listed yet
    code = ("import socket,time\nend=time.time()+14\nwhile time.time()<end:\n"
            f"    s=socket.socket(2,2); s.sendto(b'x',('{LOCAL}',5353)); s.close(); time.sleep(0.05)\n")
    p = task(cg, fw, "reltask", code)
    assert _until(lambda: nm.udp_by_task["reltask"] > 20, 8)                      # the tap sees the task's flows
    assert _hits(events) == [] and p.poll() is None                               # none of them listed
    rules_before, installed, errors = nm.tap.rules.rules(), nm.stats["tap_installed"], nm.stats["errors"]
    pid_before = p.pid

    def listed(*lines):
        b = Blocklist()
        for ln in lines:
            b.add_line(ln, "rogue")
        return b, []
    log = []
    r = Reloader(s, lambda: listed(f"{LOCAL}/32"), log=log.append)
    assert r.reload_now() == "ok"
    assert _until(lambda: len(_hits(events)) >= 30, 10), "the new list was not enforced on the next flows"
    assert {e["subject"]["cgroup"] for e in _hits(events)} == {"reltask"}         # same task, same cgroup tracking
    assert p.poll() is None and p.pid == pid_before                                # the task was never disturbed
    assert nm.tap.rules.rules() == rules_before                                    # same nft rule handles: untouched
    assert nm.stats["tap_installed"] == installed and nm.stats["errors"] == errors and nm.lost() == 0

    flagged_by_b = len(_hits(events))
    r2 = Reloader(s, lambda: listed("203.0.113.0/24"), log=log.append)             # and back: the old entry is gone
    assert r2.reload_now() == "ok"
    time.sleep(0.4)
    settled = len(_hits(events))
    time.sleep(1.5)
    assert len(_hits(events)) == settled, "flows kept being flagged after the entry was removed"
    assert p.poll() is None and nm.tap.rules.rules() == rules_before
    print(f"\nreload under a live task: {flagged_by_b} flows flagged while list B was live, then {settled - flagged_by_b} "
          f"after swapping back to list A; "
          f"rule handles identical; poll_ms_max={nm.stats['poll_ms_max']}")


# ============ where does a slow tap sync spend its time: the lock, or nft? ============
def _slow_tap(tmp_path, delay):
    base = tmp_path / "cgroup"; root = base / "cora"; root.mkdir(parents=True)
    n = FakeTapNft()

    def slow(args, stdin):
        time.sleep(delay)
        return n(args, stdin)
    cg = CgroupRoot(str(root), str(base))
    table = f"unit{os.getpid()}t{abs(hash(str(tmp_path))) % 10**6}"
    return TapRules(Firewall(cg, table=table, nft_base=str(base), run=slow), group=88, udp=False), cg


def test_nft_time_is_attributed_to_nft_and_not_to_the_lock(tmp_path):
    t, cg = _slow_tap(tmp_path, 0.05)
    try:
        t.ensure_chain(); cg.create("a")
        t.sync({"a": 1})
        lt = t.last_timing
        assert lt["nft_calls"] == 2 and lt["nft_ms"] >= 90 and lt["nft_slowest_ms"] >= 45
        assert lt["lock_ms"] < 30
    finally:
        _drop_lock(t.fw.table)


def test_time_spent_waiting_for_the_cross_process_lock_is_attributed_to_the_lock(tmp_path):
    t, cg = _slow_tap(tmp_path, 0.0)
    try:
        t.ensure_chain(); cg.create("a")
        held = threading.Event()

        def hog():
            with t._locked():
                held.set()
                time.sleep(0.5)
        th = threading.Thread(target=hog, daemon=True)
        th.start()
        assert held.wait(5)
        t.sync({"a": 1})                                         # has to wait for the hog
        th.join()
        lt = t.last_timing
        assert lt["lock_ms"] >= 350 and lt["nft_ms"] < 100
    finally:
        _drop_lock(t.fw.table)


@pytest.mark.parametrize("total,lock,nft,slowest,ctl,cb,sb,says", [
    # the lock wait is measured directly
    (1000, 900, 50, 40, 1, None, None, "waiting for the cross-process tap lock"),
    # no idle baseline yet: absolute rules only
    (1600, 10, 1580, 1500, 2, None, None, "inside nft or the kernel"),
    (1600, 10, 1580, 1500, 400, None, None, "host is too busy"),
    (1600, 10, 1580, 1500, 60, None, None, "host is too busy"),
    (1600, 10, 1580, 1500, -1, None, None, "could not be measured"),
    (900, 10, 20, 15, 1, None, None, "neither the tap lock nor nft"),
    (22, 0, 22, 12, 3, None, None, "not slow"),                        # an idle, healthy sync is not "a busy host"
    # with a baseline (each against its own fastest), judged by EXTRA ms: the child barely delayed -> nft alone
    (1600, 10, 1580, 1500, 6, 2, 10, "points at nft or the kernel"),
    (1600, 10, 1580, 1500, 8, 2, 10, "points at nft or the kernel"),
    (600, 0, 600, 300, 2, 2, 10, "points at nft or the kernel"),
    (253, 0, 253, 223, 4, 0.9, 3.2, "points at nft or the kernel"),   # measured: 16 low-CPU loaders hammering nft
    (336, 0, 336, 273, 6, 2, 11, "points at nft or the kernel"),       # measured: 30k-rule loads, run 1
    # ... the child delayed by a comparable share -> the whole host
    (112, 0, 112, 77, 13, 2, 11, "whole host is slow"),                # measured: 6 spinning processes, 1 core
    (592, 0, 591, 364, 91, 0.9, 3.2, "whole host is slow"),            # measured: 40 spinning processes, 1 core
    (336, 0, 336, 273, 63, 2, 11, "whole host is slow"),               # measured: 30k-rule loads, run 2 (1 core)
    (1600, 10, 1580, 1500, 400, 2, 10, "whole host is slow"),
    # ... host slow in its own right (>= 30 ms for a no-op!) AND nft far slower still: do not blame either alone
    (1600, 10, 1580, 1500, 60, 2, 10, "mixed")])
def test_the_diagnosis_says_what_the_numbers_suggest(total, lock, nft, slowest, ctl, cb, sb, says):
    from cora_sentinel.netmon import diagnose
    assert says in diagnose(total, lock, nft, slowest, ctl, cb, sb)


def test_a_slow_sync_is_split_recorded_and_explained_in_the_log(tmp_path, monkeypatch, capsys):
    from cora_sentinel import netmon
    monkeypatch.setattr(netmon, "_fork_exec_ms", lambda: 3.0)
    monkeypatch.setattr(netmon, "STALL_WARN_MS", 100)
    timing = {"lock_ms": 200.0, "nft_ms": 40.0, "nft_calls": 4, "nft_slowest_ms": 25.0}
    nm, events, _ = _threaded_monitor(tmp_path, sync=lambda cur: (time.sleep(0.25), (list(cur), []))[1], timing=timing)
    nm.start()
    live = []
    try:
        assert _until(lambda: nm.stats["tap_sync_ms_max"] >= 200, 5)
        # the note must appear WHILE it runs, not only in the end-of-run summary (which repeats the same text)
        assert _until(lambda: (live.append(capsys.readouterr().err), "tap sync took" in "".join(live))[1], 5)
    finally:
        nm.stop()
    during = "".join(live)
    st, w = nm.stats, nm.worst_sync
    assert (st["tap_lock_wait_ms_max"], st["tap_nft_ms_max"], st["tap_nft_call_ms_max"], st["tap_ctl_ms_max"]) == (200, 40, 25, 3)
    assert w["lock_ms"] == 200 and w["nft_ms"] == 40 and w["calls"] == 4 and w["ctl_ms"] == 3
    assert "lock wait 200 + nft 40 (4 calls, slowest 25)" in during and "a no-op child took 3 ms" in during
    assert "waiting for the cross-process tap lock" in during and "worst_tap_sync" not in during
    end = capsys.readouterr().err                            # and the summary at stop() carries the same facts
    assert "lock_wait_max=200 nft_max=40 slowest_nft_call=25 noop_child_max=3" in end and "worst_tap_sync:" in end


def test_a_fast_sync_is_recorded_but_not_shouted_about(tmp_path, monkeypatch, capsys):
    from cora_sentinel import netmon
    monkeypatch.setattr(netmon, "_fork_exec_ms", lambda: 1.0)
    nm, _, _ = _threaded_monitor(tmp_path, timing={"lock_ms": 1.0, "nft_ms": 2.0, "nft_calls": 2, "nft_slowest_ms": 1.0})
    nm.start()
    try:
        assert _until(lambda: nm.stats["tap_ctl_ms_max"] == 1, 5)
    finally:
        nm.stop()
    err = capsys.readouterr().err
    assert "tap sync took" not in err and "worst_tap_sync" not in err


@real
def test_a_held_tap_lock_shows_up_as_lock_wait_on_the_real_kernel(env):
    """A real nft, a real flock, a real task: another holder keeps the tap lock for 1.6 s. The sentinel's sync must
    be reported as WAITING FOR THE LOCK, with nft itself fast, and the log must say so."""
    from cora_sentinel.netmon import NetMonitor
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    time.sleep(0.5)                                        # the initial (empty) sync is done
    held = threading.Event()

    def hog():
        with nm.tap.rules._locked():
            held.set()
            time.sleep(1.6)
    th = threading.Thread(target=hog, daemon=True)
    th.start()
    assert held.wait(5)
    p = task(cg, fw, "hogged", "import time; time.sleep(2)")        # cora-run also waits; so must the sentinel
    p.wait(timeout=60)
    th.join()
    assert _until(lambda: nm.stats["tap_lock_wait_ms_max"] >= 1000, 5)
    w = nm.worst_sync
    print(f"\nheld lock: {NetMonitor._describe(w)}")
    assert w["lock_ms"] > w["nft_ms"] and nm.stats["tap_nft_ms_max"] < 500
    assert "waiting for the cross-process tap lock" in NetMonitor._describe(w)


_TOOL = Path(__file__).resolve().parents[1] / "tools" / "nft_latency_experiments.py"


@real
def test_the_experiment_tool_names_idle_and_a_lock_hog_correctly_and_cleans_up():
    """The shipped tool, run for real: idle is 'not slow', a lock hog is named as lock wait, exit code 0, and no
    scratch table, cgroup or lock file is left behind."""
    r = subprocess.run([sys.executable, str(_TOOL), "idle", "lock", "--check", "--syncs", "8"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "not slow" in r.stdout and "waiting for the cross-process tap lock" in r.stdout
    tables = subprocess.run(["nft", "list", "tables"], capture_output=True, text=True).stdout
    assert "coraexp" not in tables
    assert not [n for n in os.listdir(MOUNT) if n.startswith("coraexp-")]
    assert not [n for n in os.listdir("/run/lock") if n.startswith("cora-tap-coraexp")]


@pytest.mark.skipif(os.geteuid() == 0, reason="as root the tool would actually run")
def test_the_experiment_tool_refuses_to_run_without_root():
    r = subprocess.run([sys.executable, str(_TOOL), "idle"], capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "run as root" in r.stderr


# ============ a hung lock holder must not wedge the caller ============
def _stuck_holder(table):
    """A real process that takes the real tap lock, prints 'held', and then sleeps. It dies with its parent
    (PR_SET_PDEATHSIG), so a failing test cannot leave a frozen process holding a lock on this machine."""
    code = (f"import ctypes, time\nctypes.CDLL(None).prctl(1, 9)\n"
            f"from cora_sentinel.cgroup import CgroupRoot\nfrom cora_sentinel.firewall import Firewall\n"
            f"from cora_sentinel.nflog import TapRules\n"
            f"t = TapRules(Firewall(CgroupRoot('/nonexistent/x', '/nonexistent'), table='{table}'), 88, lock_timeout=5)\n"
            f"with t._locked():\n    print('held', flush=True)\n    time.sleep(120)\n")
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "held"
    return p


def test_a_stuck_lock_holder_times_out_instead_of_hanging_the_caller(tmp_path):
    from cora_sentinel.nflog import TapLockTimeout
    t, cg = _slow_tap(tmp_path, 0.0)
    holder = None
    try:
        t.ensure_chain(); cg.create("a")
        holder = _stuck_holder(t.fw.table)
        os.kill(holder.pid, signal.SIGSTOP)                      # hung: it keeps the lock and will never release it
        t.lock_timeout = 0.4
        start = time.monotonic()
        with pytest.raises(TapLockTimeout, match=r"within 0\.4 s: held by pid %d \(-c, stopped\)" % holder.pid):
            t.sync({"a": 1})
        assert time.monotonic() - start < 2.0                    # bounded, where a plain flock would wait forever
        assert t.last_timing["lock_ms"] >= 350                   # and the failed wait is still accounted for
        os.kill(holder.pid, signal.SIGKILL); holder.wait(10)     # the holder dies: the lock is released with it ...
        t.lock_timeout = 5.0
        t.sync({"a": 1})                                         # ... and the very next sync just works
        assert t.last_timing["lock_ms"] < 100
    finally:
        if holder:
            holder.kill(); holder.wait(10)
        _drop_lock(t.fw.table)


def test_the_holder_is_named_with_its_state(tmp_path):
    t, cg = _slow_tap(tmp_path, 0.0)
    p = subprocess.Popen(["sleep", "60"])
    try:
        fd = os.open(os.path.join(tempfile.gettempdir(), "who-holds-test"), os.O_CREAT | os.O_RDWR, 0o600)
        os.pwrite(fd, f"{p.pid} cora-run\n".encode(), 0)
        time.sleep(0.1)
        assert t._who_holds(fd) == f"held by pid {p.pid} (cora-run, sleeping)"
        os.kill(p.pid, signal.SIGSTOP); time.sleep(0.1)
        assert t._who_holds(fd) == f"held by pid {p.pid} (cora-run, stopped)"
        os.pwrite(fd, b"not a pid\n", 0); os.ftruncate(fd, 10)
        assert "could not be identified" in t._who_holds(fd)
        os.pwrite(fd, b"999999999 ghost\n", 0); os.ftruncate(fd, 16)
        assert "could not be identified" in t._who_holds(fd)          # a pid that does not exist
        os.close(fd)
    finally:
        p.kill(); p.wait()
        try: os.unlink(os.path.join(tempfile.gettempdir(), "who-holds-test"))
        except OSError: pass
        _drop_lock(t.fw.table)


def test_a_released_lock_is_taken_promptly_and_an_uncontended_one_at_once(tmp_path):
    t, cg = _slow_tap(tmp_path, 0.0)
    try:
        t.ensure_chain(); cg.create("a")
        t.sync({"a": 1})
        assert t.last_timing["lock_ms"] < 20                      # uncontended: no waiting at all
        held = threading.Event()

        def hog():
            with t._locked():
                held.set(); time.sleep(0.3)
        th = threading.Thread(target=hog, daemon=True)
        th.start(); assert held.wait(5)
        t.sync({"a": 1}); th.join()
        assert 270 <= t.last_timing["lock_ms"] <= 400             # polling adds at most a few ms after the release
    finally:
        _drop_lock(t.fw.table)


@pytest.mark.parametrize("raw,expect_default", [("2.5", False), ("0.1", False), ("abc", True), ("-1", True),
                                                ("0", True), ("nan", True), ("inf", True), ("", True)])
def test_the_lock_timeout_can_be_set_from_the_environment_and_nonsense_is_ignored_loudly(monkeypatch, capsys, raw, expect_default):
    from cora_sentinel.nflog import lock_timeout_from_env
    monkeypatch.setenv("CORA_TAP_LOCK_TIMEOUT", raw)
    v = lock_timeout_from_env(30.0)
    assert (v == 30.0) is expect_default and (expect_default or v == float(raw))
    assert ("ignoring invalid" in capsys.readouterr().err) is expect_default
    monkeypatch.delenv("CORA_TAP_LOCK_TIMEOUT")
    assert lock_timeout_from_env(7.0) == 7.0 and capsys.readouterr().err == ""


def test_the_sync_worker_logs_a_lock_timeout_and_retries_instead_of_giving_up(tmp_path, capsys):
    from cora_sentinel.nflog import TapLockTimeout
    calls = []

    def sync(cur):
        calls.append(1)
        if len(calls) == 1:
            raise TapLockTimeout("could not get the tap lock /run/lock/x within 30 s: held by pid 7 (cora-run, stopped)")
        return list(cur), []
    nm, events, tapq = _threaded_monitor(tmp_path, sync=sync)
    nm.start()
    try:
        assert _until(lambda: len(calls) >= 2, 5), "the worker did not retry"
        assert nm.stats["errors"] >= 1
    finally:
        nm.stop()
    assert "tap rule sync failed: could not get the tap lock" in capsys.readouterr().err


@real
def test_cora_run_does_not_wait_for_a_stuck_lock_and_the_sentinel_recovers_when_it_frees(env, capsys):
    """On the real kernel: the tap lock is held by a hung process. cora-run gives up after a short wait and STARTS the
    task anyway (saying what that costs); the sentinel's sync worker times out, logs it, keeps the loop responsive,
    and installs the task's rules as soon as the lock frees."""
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events)
    nm.tap.rules.lock_timeout = 0.6
    time.sleep(0.5)                                                  # initial (empty) sync done
    holder = _stuck_holder(fw.table)
    os.kill(holder.pid, signal.SIGSTOP)
    try:
        e = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT, "CORA_NFT_TABLE": fw.table,
             "CORA_NFLOG_GROUP": str(GROUP), "CORA_TAP_LOCK_TIMEOUT": "0.5"}
        start = time.monotonic()
        p = subprocess.Popen([sys.executable, "-m", "cora_sentinel.run", "stuckstart", sys.executable, "-c",
                              "import time; print('started', flush=True); time.sleep(4)"],
                             env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert p.stdout.readline().strip() == "started"
        assert time.monotonic() - start < 5.0                        # it did not wait for the hung holder
        assert _until(lambda: nm.stats["errors"] >= 1, 5)            # the sentinel's worker timed out too ...
        assert nm.stats["poll_ms_max"] < 500                         # ... while the event loop stayed responsive
        assert "stuckstart" not in nm.tap.rules.rules()              # nobody could install the rule yet
        os.kill(holder.pid, signal.SIGKILL); holder.wait(10)         # the hung holder dies; the lock frees with it
        assert _until(lambda: "stuckstart" in nm.tap.rules.rules(), 8), "the sentinel never installed the rule"
        err = p.communicate(timeout=30)[1]
        assert "tap pre-install SKIPPED" in err and "held by pid %d" % holder.pid in err
        assert "task starts anyway" in err
    finally:
        holder.kill(); holder.wait(10)
    assert "tap rule sync failed: could not get the tap lock" in capsys.readouterr().err


def test_cora_run_waits_less_for_the_lock_than_the_sentinel_does_by_default(monkeypatch, tmp_path):
    """Starting a task must never be held up for long, so cora-run's default is shorter than the sync worker's."""
    from cora_sentinel import nflog, run
    monkeypatch.delenv("CORA_TAP_LOCK_TIMEOUT", raising=False)
    assert nflog.PREINSTALL_LOCK_TIMEOUT_S <= 10 < nflog.DEFAULT_LOCK_TIMEOUT_S
    seen = []
    monkeypatch.setattr(nflog.TapRules, "active", lambda self: seen.append(self.lock_timeout) or False)
    root = tmp_path / "cora"; root.mkdir()
    run._preinstall_tap(CgroupRoot(str(root), str(tmp_path)), "x")
    assert seen == [nflog.PREINSTALL_LOCK_TIMEOUT_S]                    # what cora-run really builds
    t, _ = _slow_tap(tmp_path / "s", 0.0)
    try:
        assert t.lock_timeout == nflog.DEFAULT_LOCK_TIMEOUT_S           # what the sentinel builds
    finally:
        _drop_lock(t.fw.table)


# ============ CPU pressure: telling "the CPUs are oversubscribed" from "commit contention" ============
@pytest.mark.parametrize("pressure,says", [
    (0.97, "CPUs were oversubscribed"),            # measured on 28 cores: 80 spinners, nft x5 slower, fork still 2 ms
    (0.60, "CPUs were oversubscribed"),
    (0.03, "NOT oversubscribed"),                  # measured on 28 cores: 16 low-CPU loaders hammering nft
    (0.30, "inconclusive"),
    (None, "CPU pressure unavailable")])
def test_a_slow_nft_with_a_prompt_noop_child_is_read_with_the_cpu_pressure(pressure, says):
    from cora_sentinel.netmon import diagnose
    v = diagnose(452, 0, 451, 425, 2, 1, 79, pressure)       # their idle baseline: nft 79 ms, no-op child 1 ms
    assert says in v
    assert "not general host load" not in v                  # the old wording was wrong: load CAN reach nft without slowing fork


def test_oversubscription_is_not_called_evidence_of_commit_contention():
    from cora_sentinel.netmon import diagnose
    assert "not evidence of commit contention" in diagnose(452, 0, 451, 425, 2, 1, 79, 0.95)
    assert "consistent with commit contention" in diagnose(280, 0, 280, 185, 1, 0.9, 79, 0.03)


def test_the_log_line_names_the_slowest_nft_call_and_the_cpu_pressure(tmp_path, monkeypatch, capsys):
    import itertools
    from cora_sentinel import netmon
    monkeypatch.setattr(netmon, "_fork_exec_ms", lambda: 1.0)
    monkeypatch.setattr(netmon, "STALL_WARN_MS", 100)
    monkeypatch.setattr(netmon, "_cpu_stall_ms", lambda it=itertools.cycle([0.0, 1000.0]): next(it))
    timing = {"lock_ms": 0.0, "nft_ms": 240.0, "nft_calls": 2, "nft_slowest_ms": 220.0, "nft_slowest_cmd": "-f -"}
    nm, _, _ = _threaded_monitor(tmp_path, sync=lambda cur: (time.sleep(0.25), (list(cur), []))[1], timing=timing)
    nm.start()
    live = []
    try:
        assert _until(lambda: (live.append(capsys.readouterr().err), "tap sync took" in "".join(live))[1], 5)
    finally:
        nm.stop()
    during = "".join(live)
    assert "slowest 220 [-f -]" in during                    # a dump or a commit? now it says
    assert "CPU pressure during it: 100%" in during          # 1000 ms of stall over a ~250 ms sync, capped at 100%
    assert nm.stats["tap_cpu_pressure_pct_max"] == 100
    assert "cpu_pressure_max=100%" in capsys.readouterr().err


@pytest.mark.skipif(_cpu_stall_ms_missing := not os.path.exists("/proc/pressure/cpu"), reason="no PSI on this kernel")
def test_the_cpu_pressure_reading_rises_when_the_cpus_are_oversubscribed():
    """The sensor itself, on the real kernel: idle gives almost no stall, 2 x cores spinning processes give a lot."""
    from cora_sentinel.netmon import _cpu_stall_ms
    a = _cpu_stall_ms(); time.sleep(0.4); b = _cpu_stall_ms()
    assert a is not None and b >= a
    quiet = b - a
    spinners = [subprocess.Popen([sys.executable, "-c", "while 1: pass"]) for _ in range(2 * (os.cpu_count() or 1))]
    try:
        time.sleep(0.4)                                      # let them all get running
        a = _cpu_stall_ms(); time.sleep(0.5); b = _cpu_stall_ms()
    finally:
        for p in spinners:
            p.kill()
        for p in spinners:
            p.wait()
    assert (b - a) >= 150 and (b - a) > 5 * max(quiet, 10)   # >= 30% of the window, and far above idle


# ============ reading the kernel's rules over netlink instead of `nft list` ============
def _both(tr):
    """TapRules.rules() read both ways, on the same kernel state."""
    tr.fw.native = True
    a = tr.rules()
    tr.fw.native = False
    b = tr.rules()
    tr.fw.native = True
    return a, b


@real
def test_netlink_and_nft_read_the_same_rules_in_every_state_including_damage_and_live_counters(env):
    from cora_sentinel import nftdump
    cg, fw, made = env
    tr = TapRules(fw, GROUP)
    tr.ensure_chain()
    assert fw.native is True                                        # the real nft, and its binary is there
    a, b = _both(tr)
    assert a == b == {}                                             # an empty chain
    lis, port = listener()
    stop = drain(lis)
    p = task(cg, fw, "cnt", beacons(port, 4, hold=8))               # cora-run pre-installs; the task makes 4 real SYNs
    try:
        assert _until(lambda: tr.rules().get("cnt", {}).get("packets", 0) >= 4, 10)
        cg.create("other")
        tr.sync({n: os.stat(cg.root / n).st_ino for n in cg.names()})
        a, b = _both(tr)
        assert a == b and set(a) == {"cnt", "other"} and a["cnt"]["packets"] >= 4      # same handles, kinds, counters
        fw._script(f"add rule inet {fw.table} tap {tr.rule_texts('cnt')['t']}\n")      # DAMAGE: a duplicate rule
        a, b = _both(tr)
        assert a == b and len(a["cnt"]["handles"]) == len(tr._needed()) + 1
        assert (fw.chain_exists("tap"), fw.chain_exists("nosuch")) == (True, False)
        fw.native = False
        assert (fw.chain_exists("tap"), fw.chain_exists("nosuch")) == (True, False)    # the command agrees
        assert (fw.set_exists("cora_flow4"), fw.set_exists("nosuch")) == (True, False)
        fw.native = True
        assert (fw.set_exists("cora_flow4"), fw.set_exists("nosuch")) == (True, False)
        assert nftdump.dump_rules("no-such-table", "tap") == [] and nftdump.dump_rules(fw.table, "nosuch") == []
    finally:
        stop.set(); p.kill(); p.wait(); lis.close()


@real
def test_netlink_and_nft_read_the_same_egress_rules_with_live_drop_counters(env):
    cg, fw, made = env
    cg.create("jailed")
    fw.ensure()
    assert fw.block("jailed")
    a, b = None, None
    for native in (True, False):
        fw.native = native
        r = fw.rules()
        a, b = (r, b) if native else (a, r)
    assert a == b and a["jailed"]["packets"] == 0 and a["jailed"]["cgid"] == os.stat(cg.root / "jailed").st_ino
    fw.native = True
    assert fw.is_blocked("jailed") and not fw.is_blocked("nobody")


# How many live tasks the listing benchmark creates (each adds 5 tap rules). nft's own listing is quadratic in this, and firewall.py gives
# any nft call 10 s: at 140 tasks (700 rules) the legacy listing took ~11 s on a throttled 2-vCPU GitHub runner and sometimes tripped it,
# at 60 (300 rules) it is ~(60/140)^2 of that, about 2 s there and 0.4 s on a 1-core sandbox, while the contrast with netlink is still
# an order of magnitude. CORA_TEST_TAP_TASKS=140 runs the original scale (on bare metal, to measure).
TAP_TASKS = int(os.environ.get("CORA_TEST_TAP_TASKS", "60"))


@real
def test_listing_cost_no_longer_grows_with_the_number_of_live_tasks(env):
    """nft resolves each rule's cgroup id to a path by walking the cgroup tree, so `nft list` of the tap chain costs
    (rules x cgroups visited) and grows QUADRATICALLY with live tasks (each adds 5 rules and a sibling cgroup). The
    netlink read is O(rules). Measured on bare metal: 160 tasks -> 1.8 s by nft, 22 ms by netlink."""
    cg, fw, made = env
    tr = TapRules(fw, GROUP)
    tr.ensure_chain()
    for i in range(TAP_TASKS):
        cg.create(f"t{i}")
    tr.sync({n: os.stat(cg.root / n).st_ino for n in cg.names()})            # TAP_TASKS tasks = 5 x TAP_TASKS tap rules

    def ms(native):
        fw.native = native
        t = time.monotonic()
        rules = tr.rules()
        return (time.monotonic() - t) * 1000.0, rules
    fast, via_netlink = ms(True)
    slow, via_nft = ms(False)
    fw.native = True
    print(f"\n{TAP_TASKS} live tasks ({5 * TAP_TASKS} rules): nft command {slow:.0f} ms, netlink {fast:.0f} ms")
    assert via_netlink == via_nft and len(via_netlink) == TAP_TASKS          # the SAME answer ...
    if slow < 100:
        pytest.skip("this machine lists too quickly for nft's cost to show")
    assert fast < 80 and fast * 10 <= slow                                   # ... without nft's cost


@pytest.mark.parametrize("total,base,says", [
    (111, 94, "not slow"),        # measured on 28 cores: an idle sync of 111 ms, best seen 94 ms (not a stall)
    (188, 94, "not slow"),        # exactly 2x the machine's own best is still not an anomaly
    (189, 94, "nft"),             # just beyond it, the explanation is given
    (900, 94, "nft"),             # a real stall is explained however slow the machine's baseline is
    (150, None, "nft")])          # no baseline yet: only the absolute floor applies
def test_not_slow_means_within_twice_this_machines_own_best_sync(total, base, says):
    from cora_sentinel.netmon import diagnose
    v = diagnose(total, 0, total - 3, total - 8, 1, 1, 10, 0.05, base)
    assert says in v and ("not slow" in v) is (says == "not slow")


@real
def test_the_experiment_tool_shows_netlink_and_the_nft_command_agreeing_and_cleans_up():
    r = subprocess.run([sys.executable, str(_TOOL), "dump", "--tasks", "60", "--check"],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout + r.stderr
    rows = [ln for ln in r.stdout.splitlines() if ln.rstrip().endswith(("yes", "NO"))]
    assert rows and all(ln.rstrip().endswith("yes") for ln in rows)         # the same rules at every size
    assert "coraexp" not in subprocess.run(["nft", "list", "tables"], capture_output=True, text=True).stdout
    assert not [n for n in os.listdir(MOUNT) if n.startswith("coraexp-")]


def test_a_machine_that_has_only_ever_been_slow_still_gets_its_stall_explained():
    """The first sync defines nothing: a 13 s stall must never be called 'not slow' because it is the best seen."""
    from cora_sentinel.netmon import diagnose
    assert "waiting for the cross-process tap lock" in diagnose(13000, 12000, 800, 700, 1, None, None, None, None)
    assert "waiting for the cross-process tap lock" in diagnose(13000, 12000, 800, 700, 1, 1, 10, 0.0, 13000)
    assert "nft" in diagnose(600, 0, 590, 580, 1, 1, 10, 0.0, 400)          # 600 ms is within 2x of 400, but it is a stall
    assert "not slow" in diagnose(450, 0, 440, 430, 1, 1, 10, 0.0, 400)     # under the loud-note threshold and within 2x


def test_the_baseline_comes_from_earlier_syncs_not_from_the_one_being_judged(tmp_path, monkeypatch):
    from cora_sentinel import netmon
    monkeypatch.setattr(netmon, "_cpu_stall_ms", lambda: None)
    nm, _, _ = _threaded_monitor(tmp_path)
    nm._record_sync(900.0, 1.0, {"lock_ms": 850.0, "nft_ms": 40.0})
    assert nm.worst_sync["total_base"] is None                              # the first sync has no history
    nm._record_sync(950.0, 1.0, {"lock_ms": 900.0, "nft_ms": 40.0})
    assert nm.worst_sync["total_base"] == 900.0                             # and the second is judged against the first
    nm._record_sync(80.0, 1.0, {"lock_ms": 0.0, "nft_ms": 70.0})
    nm._record_sync(1200.0, 1.0, {"lock_ms": 1100.0, "nft_ms": 40.0})
    assert nm.worst_sync["total_base"] == 80.0                              # the fastest of the earlier ones


# ============ the tap's writes: one transaction per operation ============
def _order_in(script, *prefixes):
    lines = script.splitlines()
    return [next(i for i, ln in enumerate(lines) if ln.startswith(p)) for p in prefixes]


def test_install_is_ONE_transaction_when_the_chain_and_sets_already_exist(tmp_path):
    t, cg, n, table = _fake_tap(tmp_path, udp=True)
    try:
        t.ensure_chain(); cg.create("a"); n.scripts.clear()
        assert t.install("a") is True
        assert len(n.scripts) == 1 and n.scripts[0].count("add rule") == 5          # 1 TCP + 4 UDP rules
        assert not any(w in n.scripts[0] for w in ("add table", "add chain", "add set"))     # nothing missing: no commit
        assert t.install("a") is False and len(n.scripts) == 1                       # complete: no transaction at all
    finally:
        _drop_lock(table)


def test_the_first_install_creates_table_sets_and_chain_in_the_same_transaction_before_the_rules(tmp_path):
    t, cg, n, table = _fake_tap(tmp_path, udp=True)
    try:
        cg.create("a")
        assert t.install("a") is True and len(n.scripts) == 1
        tb, st, ch, rl = _order_in(n.scripts[0], "add table", "add set", "add chain", "add rule")
        assert tb < st < ch < rl
    finally:
        _drop_lock(table)


def test_a_stale_install_replaces_the_rules_in_one_transaction_deleting_before_adding(tmp_path):
    t, cg, n, table = _fake_tap(tmp_path, udp=True)
    try:
        t.ensure_chain(); cg.create("a"); t.install("a")
        for r in n.rules:
            r["comment"] = re.sub(r":\d+$", ":1", r["comment"])                      # the cgroup was recreated
        n.scripts.clear()
        assert t.install("a") is True and len(n.scripts) == 1
        d, a = _order_in(n.scripts[0], "delete rule", "add rule")
        assert d < a and n.scripts[0].count("delete rule") == 5 and n.scripts[0].count("add rule") == 5
    finally:
        _drop_lock(table)


def test_sync_of_several_changes_is_one_transaction(tmp_path):
    t, cg, n, table = _fake_tap(tmp_path, udp=True)
    try:
        t.ensure_chain()
        for x in ("a", "b", "c"):
            cg.create(x)
        t.sync({x: os.stat(cg.root / x).st_ino for x in ("a", "b", "c")})
        n.scripts.clear()
        cg.create("d"); cg.create("e")
        t.sync({x: os.stat(cg.root / x).st_ino for x in ("a", "b", "d", "e")})        # +d +e, -c
        assert len(n.scripts) == 1 and n.scripts[0].count("delete rule") == 5 and n.scripts[0].count("add rule") == 10
    finally:
        _drop_lock(table)


def test_the_udp_hint_survives_the_merge_and_only_appears_when_the_set_was_being_created(tmp_path):
    from cora_sentinel.firewall import FirewallError
    t, cg, n, table = _fake_tap(tmp_path, udp=True)
    try:
        orig = n.__call__
        t.fw._run = lambda args, stdin: ((1, "", "Error: syntax error near typeof")
                                         if args == ["-f", "-"] and "add set" in (stdin or "") else orig(args, stdin))
        cg.create("a")
        with pytest.raises(FirewallError, match="--no-tap-udp"):                      # creating the set failed: the hint
            t.install("a")
        t.fw._run = orig
        t.ensure_chain(); n.scripts.clear()
        t.fw._run = lambda args, stdin: (1, "", "Error: boom") if args == ["-f", "-"] else orig(args, stdin)
        with pytest.raises(FirewallError) as e:
            t.install("a")                                                           # nothing was being created: no hint
        assert "--no-tap-udp" not in str(e.value)
    finally:
        _drop_lock(table)


@real
def test_the_tap_installs_and_syncs_are_one_commit_each_on_the_real_kernel(env):
    cg, fw, made = env
    tr = TapRules(fw, GROUP)
    tr.ensure_chain()
    assert fw.native is True
    cg.create("a"); cg.create("b"); cg.create("c")
    fw.timing.reset(); assert tr.install("a") is True
    assert fw.timing.calls == 1 and tr.rules()["a"]["kinds"] == tr._needed()          # complete, with ONE commit
    fw.timing.reset(); assert tr.install("a") is False
    assert fw.timing.calls == 0                                                        # already complete: no commit
    fw.timing.reset()
    tr.sync({n: os.stat(cg.root / n).st_ino for n in ("a", "b", "c")})                # +b +c in one transaction
    assert fw.timing.calls == 1 and set(tr.rules()) == {"a", "b", "c"}
    (cg.root / "c").rmdir()
    fw.timing.reset()
    tr.sync({n: os.stat(cg.root / n).st_ino for n in ("a", "b")})                     # -c
    assert fw.timing.calls == 1 and set(tr.rules()) == {"a", "b"}


@real
def test_the_experiment_tool_shows_one_commit_per_write_operation_and_cleans_up():
    r = subprocess.run([sys.executable, str(_TOOL), "writes", "--tasks", "40", "--check"],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout + r.stderr
    rows = [ln for ln in r.stdout.splitlines() if ln.strip()[:1].isdigit() and "commit" in ln]
    assert len(rows) >= 2 and all(" 1 commit " in ln and "commits" not in ln for ln in rows)
    assert "coraexp" not in subprocess.run(["nft", "list", "tables"], capture_output=True, text=True).stdout
    assert not [n for n in os.listdir(MOUNT) if n.startswith("coraexp-")]


# ============ time-to-containment, from the TASK's point of view, on the real kernel ============
class _SlowModel:
    """Stands in for the real model: `delay` seconds per event, then ESCALATE (it adds nothing at the floor)."""
    def __init__(self, delay):
        self.delay = delay

    def judge(self, ev):
        time.sleep(self.delay)
        return json.dumps({"verdict": "ESCALATE", "confidence": 0.9, "reason": "slow"})


_PROBE = ("import socket, time\n"
          "s = socket.socket(2, 2); t0 = time.monotonic()\n"
          "while time.monotonic() - t0 < 8:\n"
          "    try:\n"
          "        s.sendto(b'x', ('203.0.113.1', 9))\n"
          "    except PermissionError:\n"                       # netfilter OUTPUT drop: egress is really cut
          "        print(int((time.monotonic() - t0) * 1000), flush=True); time.sleep(8); break\n"   # stay alive: the late
          "    time.sleep(0.001)\n"                                                               # decision needs a pid
          "else:\n"
          "    print(-1, flush=True)\n")


@real
@pytest.mark.parametrize("contain_first", [True, False])
def test_a_task_hitting_a_listed_address_is_cut_off_in_milliseconds_not_after_the_model(env, contain_first):
    """A real task sends UDP to a listed address in a loop and measures how long until its first EPERM (egress
    really dropped). The model takes 1.5 s. With early containment the task is cut off long before the model answers;
    the control (switch off) is cut off only after it, which is how the system behaved before."""
    from cora_sentinel.verdict import Adjudicator, Executor
    if GW is None:
        pytest.skip("no default route: a UDP send would fail before netfilter")
    cg, fw, made = env
    events, decisions = [], []
    s, nm = monitor(cg, fw, made, events, lines=["203.0.113.1/32"])
    adj = Adjudicator(s.net, _SlowModel(1.5), Executor(True, cg, fw), None, 0.6, sink=decisions.append,
                      contain_first=contain_first)
    s.emit = lambda p: (events.append(p), adj.submit(p))
    adj.start()
    p = task(cg, fw, "probe", _PROBE)
    try:
        latency = int(p.stdout.readline().strip())
        assert _until(lambda: decisions, 10)                              # the model's decision arrives later
    finally:
        p.kill(); adj.stop()
    d = decisions[0]
    print(f"\ncontain_first={contain_first}: task cut off after {latency} ms; decision after model {d['model_ms']} ms; "
          f"in-process first-seen -> contained {d.get('contained_ms')} ms")
    assert latency >= 0 and d["final"] == "ISOLATE" and d["model_ms"] >= 1500
    if contain_first:
        assert latency < 500, "the task was not cut off before the model answered"
        assert d["contained_first"]["action"].startswith("done:ISOLATE") and d["contained_ms"] < 500
        assert d["action"].endswith(",already]")
    else:
        assert latency >= 1400, "without early containment the task is only cut off after the model"


_LATENCY_TOOL = Path(__file__).resolve().parents[1] / "tools" / "containment_latency.py"


@real
def test_the_containment_latency_tool_shows_floor_first_beating_the_model_and_cleans_up():
    if GW is None:
        pytest.skip("no default route")
    r = subprocess.run([sys.executable, str(_LATENCY_TOOL), "--trials", "2", "--model-delay", "1.0", "--check"],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout[-1500:] + r.stderr[-1500:]
    assert "floor-first ON" in r.stdout and "floor-first OFF" in r.stdout and "slower: that is the model" in r.stdout
    assert "coralat" not in subprocess.run(["nft", "list", "tables"], capture_output=True, text=True).stdout
    assert not [n for n in os.listdir(MOUNT) if n.startswith("coralat-")]
    assert not [n for n in os.listdir("/run/lock") if n.startswith("cora-tap-coralat")]


@pytest.mark.skipif(os.geteuid() == 0, reason="as root the tool would actually run")
def test_the_containment_latency_tool_refuses_to_run_without_root():
    r = subprocess.run([sys.executable, str(_LATENCY_TOOL)], capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "run as root" in r.stderr


# ============ IPv6 through the tap. NOT RUN BY THE AUTHOR: the development kernel has no IPv6 at all ============
def _v6_loopback():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


v6 = pytest.mark.skipif(not _v6_loopback(), reason="no IPv6 loopback (sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0)")


@real
@v6
def test_ipv6_tcp_syns_are_seen_by_the_tap_and_attributed_to_the_task(env):
    """Written so the first run on a machine WITH IPv6 either confirms the v6 TCP tap or finds the hole. The tap's TCP
    rule is in an `inet` table, so it should cover v6; that has never been exercised on a kernel."""
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events, lines=[])
    lis = socket.socket(socket.AF_INET6)
    lis.bind(("::1", 0))
    lis.listen(64)
    port = lis.getsockname()[1]
    stop = drain(lis)
    code = ("import socket, time\n"
            "for _ in range(6):\n"
            f"    socket.create_connection(('::1', {port}), timeout=2).close()\n"
            "    time.sleep(0.05)\n"
            "time.sleep(2)\n")
    p = task(cg, fw, "v6tcp", code)
    try:
        assert _until(lambda: nm.syn_by_task["v6tcp"] >= 6, 10), f"the tap saw {dict(nm.syn_by_task)}"
    finally:
        stop.set(); p.kill(); p.wait(); lis.close()


@real
@v6
def test_ipv6_udp_first_packets_are_seen_once_per_flow_not_once_per_packet(env):
    """The v6 UDP rules (u6s/u6l) and the cora_flow6 set have never run on a kernel. 8 flows x 6 datagrams each must
    be 8 events."""
    cg, fw, made = env
    events = []
    s, nm = monitor(cg, fw, made, events, lines=[])
    srv = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    srv.bind(("::1", 0))
    port = srv.getsockname()[1]
    code = ("import socket, time\n"
            "socks = [socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) for _ in range(8)]\n"
            "for _ in range(6):\n"
            "    for s in socks:\n"
            f"        s.sendto(b'x', ('::1', {port}))\n"
            "    time.sleep(0.02)\n"
            "time.sleep(2)\n")
    p = task(cg, fw, "v6udp", code)
    try:
        assert _until(lambda: nm.udp_by_task["v6udp"] >= 8, 10), f"the tap saw {dict(nm.udp_by_task)}"
        time.sleep(0.5)
        assert nm.udp_by_task["v6udp"] == 8, f"expected one event per flow (8), got {nm.udp_by_task['v6udp']}"
    finally:
        p.kill(); p.wait(); srv.close()


def test_the_listing_benchmark_takes_its_scale_from_one_constant_and_keeps_nft_well_under_its_ceiling():
    """The 0.8.9 change lowered the loop but left `== 140` in the assertion and `140 live tasks` in the label, so the test could not pass.
    Guard both halves: nothing in the test hard-codes the old scale, and the default scale is small enough for nft's quadratic listing."""
    import inspect
    src = inspect.getsource(test_listing_cost_no_longer_grows_with_the_number_of_live_tasks)
    for stale in ("== 140", "140 live", "700 rules", "range(60)", "range(140)"):
        assert stale not in src, f"the benchmark hard-codes its scale again ({stale})"
    assert "TAP_TASKS" in src
    if "CORA_TEST_TAP_TASKS" not in os.environ:
        assert 30 <= TAP_TASKS <= 100, "enough tasks to show nft's cost, few enough to stay far below firewall.py's 10 s ceiling on a slow runner"
