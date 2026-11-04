"""Run: pytest -q test_cora_net.py"""
import ipaddress
import socket
import subprocess
import sys
import time

import pytest

from cora_sentinel import (ConnDetector, NetPolicy, Sentinel, _hex_ip,
                           parse_proc_net_tcp)

MARK = "CORA_TASK_NETTEST"
LINE = "   0: {l} {r} {st} 00000000:00000000 00:00000000 00000000  1000        0 {ino} 1 0000000000000000 100 0 0 10 0"
HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


# ---- parsing --------------------------------------------------------------
def test_hex_ip_v4_and_v6():
    assert _hex_ip("0100007F") == "127.0.0.1"
    assert _hex_ip("0F02000A") == "10.0.2.15"
    assert _hex_ip("00000000000000000000000001000000") == "::1"
    assert ipaddress.ip_address(_hex_ip("0000000000000000FFFF00000100007F")) == \
        ipaddress.ip_address("::ffff:127.0.0.1")


def test_parse_row():
    rows = parse_proc_net_tcp(HEAD + LINE.format(l="0100007F:1F90", r="0F02000A:C350", st="01", ino=12345))
    assert rows == [{"local_ip": "127.0.0.1", "local_port": 8080, "remote_ip": "10.0.2.15",
                     "remote_port": 50000, "state": "01", "inode": 12345}]


# ---- policy ---------------------------------------------------------------
@pytest.mark.parametrize("ip,expect", [
    ("127.0.0.1", None), ("10.5.5.5", None), ("::1", None),
    ("::ffff:127.0.0.1", None), ("::ffff:10.1.1.1", None),
    ("8.8.8.8", ("high", "public")), ("::ffff:8.8.8.8", ("high", "public")),
    ("2606:4700::1111", ("high", "public")),
    ("192.168.1.5", ("medium", "private")), ("169.254.1.1", ("medium", "link_local"))])
def test_policy(ip, expect):
    assert NetPolicy(["127.0.0.0/8", "::1/128", "10.0.0.0/8"]).check(ip) == expect


# ---- diff -----------------------------------------------------------------
def row(ino, rip="8.8.8.8", rport=443, lport=50000, st="01"):
    return {"local_ip": "10.0.2.15", "local_port": lport, "remote_ip": rip,
            "remote_port": rport, "state": st, "inode": ino}


def test_diff_flags_once():
    d = ConnDetector(NetPolicy(["10.0.0.0/8"]))
    by = {1: row(1)}
    assert len(d.scan(7, {1}, by, set())) == 1
    assert d.scan(7, {1}, by, set()) == []          # same connection, next tick
    by[2] = row(2, rip="1.1.1.1", lport=50001)
    out = d.scan(7, {1, 2}, by, set())
    assert [o["evidence"]["remote_ip"] for o in out] == ["1.1.1.1"]


def test_diff_skips_inbound_dead_and_allowed():
    d = ConnDetector(NetPolicy(["10.0.0.0/8"]))
    by = {1: row(1, lport=8080), 2: row(2, st="06"), 3: row(3, rip="10.1.1.1"), 4: row(4, rport=0)}
    assert d.scan(7, {1, 2, 3, 4}, by, listen_ports={8080}) == []


def test_dest_class_in_evidence():
    d = ConnDetector(NetPolicy(["10.0.0.0/8"]))
    out = d.scan(7, {1}, {1: row(1)}, set())
    assert out[0]["severity"] == "high" and out[0]["evidence"]["dest_class"] == "public"


# ---- live sockets ---------------------------------------------------------
@pytest.fixture
def procs():
    ps = []
    yield ps
    for p in ps:
        p.kill(); p.wait()


def sentinel(events):
    return Sentinel(MARK, ["/tmp"], spike_mb=10**6, window_s=5, emit=events.append,
                    net_allow=["10.0.0.0/8"])   # loopback deliberately NOT allowed


def test_live_outbound_flagged(procs):
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(1)
    port = lis.getsockname()[1]
    procs.append(subprocess.Popen([sys.executable, "-c",
        f"import socket,time;c=socket.create_connection(('127.0.0.1',{port}));time.sleep(30)", MARK]))
    ev = []; s = sentinel(ev)
    end = time.monotonic() + 5
    while time.monotonic() < end and not ev:
        s.tick(); time.sleep(0.2)
    lis.close()
    e = [x for x in ev if x["anomaly"]["kind"] == "unauthorized_connection"]
    assert e and e[0]["anomaly"]["evidence"]["remote_port"] == port
    assert e[0]["anomaly"]["evidence"]["remote_ip"] == "127.0.0.1"


def test_live_inbound_not_flagged(procs):
    p = subprocess.Popen([sys.executable, "-c",
        "import socket,time;l=socket.socket();l.bind(('127.0.0.1',0));l.listen();"
        "print(l.getsockname()[1],flush=True);c,_=l.accept();time.sleep(30)", MARK],
        stdout=subprocess.PIPE, text=True)
    procs.append(p)
    port = int(p.stdout.readline())
    cli = socket.create_connection(("127.0.0.1", port))
    ev = []; s = sentinel(ev)
    for _ in range(10):
        s.tick(); time.sleep(0.2)
    cli.close()
    assert [x for x in ev if x["anomaly"]["kind"] == "unauthorized_connection"] == []


# ---- tagging regression ---------------------------------------------------
def test_marker_is_exact_token_not_substring(procs):
    code = "import time;time.sleep(30)"
    exact = subprocess.Popen([sys.executable, "-c", code, MARK])
    loose = subprocess.Popen([sys.executable, "-c", code, f"x{MARK}x"])
    shell = subprocess.Popen(["bash", "-c", f"sleep 30 # {MARK}"])
    procs += [exact, loose, shell]
    time.sleep(0.3)
    t = sentinel([])._targets()
    assert exact.pid in t and loose.pid not in t and shell.pid not in t
