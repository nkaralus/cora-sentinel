"""Part 1 runs anywhere (synthetic packets, fake nft). Part 2 needs root, nft, nfnetlink_log, cgroup v2.
Run: sudo -E $(which python) -m pytest -q -s test_cora_nflog.py"""
import json
import os
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from cora_blocklist import Blocklist
from cora_cgroup import CgroupRoot
from cora_firewall import Firewall
from cora_nflog import (PREFIX, NflogListener, TapRules, TapService, available, parse_ip_tcp_syn, parse_packet_msg,
                        _attr)
from cora_sentinel import Sentinel

HERE = Path(__file__).parent


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
        self.rules, self.next, self.chain, self.scripts = [], 1, False, []

    def __call__(self, args, stdin):
        if args[:2] == ["-j", "list"]:
            if not self.chain:
                return 1, "", "No such file"
            return 0, json.dumps({"nftables": [{"chain": {}}] + [{"rule": r} for r in self.rules]}), ""
        if args[:2] == ["list", "chain"]:
            return (0, "", "") if self.chain else (1, "", "No such file")
        if args == ["-f", "-"]:
            self.scripts.append(stdin)
            for line in stdin.splitlines():
                if line.startswith("add chain"):
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


@pytest.fixture
def tapfake(tmp_path):
    base = tmp_path / "cgroup"; root = base / "cora"; root.mkdir(parents=True)
    n = FakeTapNft()
    cg = CgroupRoot(str(root), str(base))
    return TapRules(Firewall(cg, nft_base=str(base), run=n), group=88), cg, n


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
    return subprocess.Popen([sys.executable, str(HERE / ("cora_run.py" if preinstall else "-")), name,
                             sys.executable, "-c", code] if preinstall else [sys.executable, "-c", code],
                            env=e, stdout=subprocess.PIPE, text=True)


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


def monitor(cg, fw, made, events, interval=0.05):
    from cora_netmon import NetMonitor
    bl = Blocklist(); bl.add_line(f"{LOCAL}/32", "rogue")
    s = Sentinel("UNUSED", ["/tmp"], spike_mb=10**6, window_s=5, emit=events.append,
                 net_allow=["0.0.0.0/0"], cgroups=cg, blocklist=bl, cooldown_s=0)
    tap = TapService(fw, GROUP)
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
    r = subprocess.run([sys.executable, str(HERE / "cora_sentinel.py"), "--nflog"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and "--nflog needs" in r.stderr


# ---- ordering regression: a dump can see a SYN_SENT socket before its SYN message is read ----
def test_a_dump_never_judges_a_socket_before_its_syn_message_has_been_drained(tmp_path):
    from cora_netmon import NetMonitor
    from cora_nflog import Syn
    from cora_sockdiag import Sock

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
