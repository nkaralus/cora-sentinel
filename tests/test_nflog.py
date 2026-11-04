"""Part 1 runs anywhere (synthetic packets, fake nft). Part 2 needs root, nft, nfnetlink_log, cgroup v2.
Run: sudo -E $(which python) -m pytest -q -s tests/test_nflog.py"""
import json
import os
import re
import shutil
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
    yield cg, fw, made
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


def task(cg, fw, name, code, preinstall=True):
    e = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT,
         "CORA_NFT_TABLE": fw.table, "CORA_NFLOG_GROUP": str(GROUP)}
    cmd = ([sys.executable, "-m", "cora_sentinel.run", name, sys.executable, "-c", code] if preinstall
           else [sys.executable, "-c", code])
    return subprocess.Popen(cmd, env=e, stdout=subprocess.PIPE, text=True)


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
          f"slips={nm.stats['slips']} lost={nm.lost()}")
    assert dict(nm.syn_by_task) == plan, "\n".join(explain(nm, k) for k in plan)   # every SYN, to the right task, exactly
    assert per_task == plan and len(ev) == sum(plan.values())  # one event each: no loss, no duplicates
    assert all(e["anomaly"]["evidence"]["via"] == "syn_tap" for e in ev)
    assert nm.stats["slips"] == 0 and nm.stats["owner_gone"] == 0 and nm.lost() == 0
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
    print(f"\n1500 beacons: syn events={nm.stats['syn']} lost={nm.lost()} slips={nm.stats['slips']}")
    assert nm.syn_by_task["flood"] == 1500 and nm.lost() == 0 and nm.stats["slips"] == 0
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
