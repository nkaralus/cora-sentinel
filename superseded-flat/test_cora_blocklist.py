"""Run: pytest -q test_cora_blocklist.py"""
import ipaddress
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from cora_blocklist import Blocklist, DomainResolver
from cora_sentinel import ConnDetector, NetPolicy, Sentinel


def bl_from(text, name="t", **kw):
    b = Blocklist(**kw)
    for line in text.splitlines():
        b.add_line(line, name)
    return b


# ---- parsing --------------------------------------------------------------
def test_all_formats_parse():
    b = bl_from("""
# comment
! adblock comment
||ads.example.com^
0.0.0.0 tracker.example.net cdn-ads.example.org
127.0.0.1 localhost
*.metrics.test.io
Beacon.Example.COM.
198.51.100.0/24 ; SBL12345
203.0.113.7
2001:db8::/32  # v6
""")
    assert set(b.domains) == {"ads.example.com", "tracker.example.net", "cdn-ads.example.org",
                              "metrics.test.io", "beacon.example.com"}
    assert b.n_nets == 3 and not b.rejects


@pytest.mark.parametrize("line,why", [
    ("0.0.0.0/0", "too_broad"), ("::/0", "too_broad"), ("10.0.0.0/7", "too_broad"),
    ("127.0.0.1", "protected"), ("127.0.0.0/8", "protected"), ("::1", "protected"),
    ("intranet", "bad_entry"), ("not a thing here", "bad_entry"),
    ("a" * 300 + ".com", "bad_entry"), ("bad_domain!.com", "bad_entry")])
def test_dangerous_or_garbage_rejected(line, why):
    b = bl_from(line)
    assert b.rejects[why] == 1 and not b.domains and b.n_nets == 0


def test_hosts_noise_is_ignored_not_rejected():
    b = bl_from("127.0.0.1 localhost\n0.0.0.0 broadcasthost")
    assert not b.domains and not b.rejects


# ---- matching -------------------------------------------------------------
def test_net_match_is_exact_at_boundaries_and_most_specific():
    b = bl_from("198.51.100.0/24\n198.51.100.128/25")
    assert b.match_net("198.51.100.0").entry == "198.51.100.0/24"
    assert b.match_net("198.51.100.255").entry == "198.51.100.128/25"   # most specific wins
    assert b.match_net("198.51.101.0") is None and b.match_net("198.51.99.255") is None


def test_v6_and_mapped_addresses():
    b = bl_from("2001:db8::/32\n198.51.100.0/24")
    assert b.match_net("2001:db8:1::5").kind == "rogue_subnet"
    assert b.match_net("::ffff:198.51.100.9").entry == "198.51.100.0/24"   # no v6-wrapping bypass
    assert b.match_net("2001:db9::1") is None


def test_domain_matches_subdomains_not_lookalikes():
    b = bl_from("doubleclick.net")
    assert b.match_domain("doubleclick.net") and b.match_domain("a.b.doubleclick.net")
    assert b.match_domain("notdoubleclick.net") is None and b.match_domain("net") is None


def test_directory_load_uses_stems_and_skips_junk(tmp_path):
    (tmp_path / "ads.txt").write_text("ads.example.com\n")
    (tmp_path / "rogue.cidr").write_text("198.51.100.0/24\n")
    (tmp_path / ".hidden").write_text("hidden.example.com\n")
    (tmp_path / "notes.json").write_text('{"x": 1}')
    b = Blocklist()
    assert b.load(tmp_path) == 2
    assert b.match_domain("ads.example.com").list == "ads"
    assert b.match_net("198.51.100.1").list == "rogue" and not b.match_domain("hidden.example.com")


# ---- resolver -------------------------------------------------------------
PUB1, PUB2 = "93.184.216.34", "151.101.1.69"


def test_resolution_maps_public_addresses_only():
    b = bl_from("track.example.com")
    DomainResolver(b, resolve=lambda n: [PUB1, "10.0.0.5", "0.0.0.0", "127.0.0.1", "garbage"]).cycle()
    h = b.match_ip(PUB1)
    assert h and h.kind == "tracker_domain" and h.entry == "track.example.com"
    assert b.match_ip("10.0.0.5") is None and b.match_ip("0.0.0.0") is None   # sinkholes ignored


def test_round_robin_covers_everything_and_survives_failures():
    b = bl_from("a.example.com\nb.example.com\nc.example.com")
    ips = {"a.example.com": [PUB1], "b.example.com": None, "c.example.com": [PUB2]}

    def res(n):
        if ips[n] is None:
            raise RuntimeError("SERVFAIL")
        return ips[n]
    r = DomainResolver(b, resolve=res, max_per_cycle=1)
    for _ in range(3):
        r.cycle()
    assert b.match_ip(PUB1) and b.match_ip(PUB2)


def test_slow_resolver_cannot_stall_a_cycle():
    b = bl_from("slow.example.com")
    r = DomainResolver(b, resolve=lambda n: time.sleep(3) or [PUB1], deadline_s=0.3)
    t0 = time.monotonic()
    r.cycle()
    assert time.monotonic() - t0 < 1.5 and b.match_ip(PUB1) is None


def test_allow_list_wins_over_both_paths():
    b = bl_from("198.51.100.0/24\ncdn.example.com")
    DomainResolver(b, resolve=lambda n: [PUB1]).cycle()
    assert b.match_ip(PUB1) and b.match_ip("198.51.100.9")
    b.allow = bl_from("198.51.100.0/24\nexample.com")      # exception for the net AND the parent domain
    assert b.match_ip("198.51.100.9") is None and b.match_ip(PUB1) is None


# ---- detector integration (no kernel needed) ---------------------------------
def row(ino, rip, rport=443, lport=50000):
    return {"local_ip": "10.0.2.15", "local_port": lport, "remote_ip": rip,
            "remote_port": rport, "state": "01", "inode": ino}


def test_blocklist_hit_beats_the_allowlist():
    b = bl_from("10.9.9.0/24")                      # rogue device INSIDE the allowed 10/8
    d = ConnDetector(NetPolicy(["10.0.0.0/8"]), b)
    out = d.scan(1, {1, 2}, {1: row(1, "10.9.9.9"), 2: row(2, "10.1.1.1", lport=50001)}, set())
    assert len(out) == 1                             # only the listed one trips
    e = out[0]["evidence"]
    assert out[0]["severity"] == "high" and e["blocklist"]["entry"] == "10.9.9.0/24"
    assert e["blocklist"]["kind"] == "rogue_subnet" and e["dest_class"] == "private"


def test_unlisted_outside_allowlist_still_flagged_without_blocklist_key():
    d = ConnDetector(NetPolicy(["10.0.0.0/8"]), bl_from("198.51.100.0/24"))
    out = d.scan(1, {1}, {1: row(1, "8.8.8.8")}, set())
    assert len(out) == 1 and "blocklist" not in out[0]["evidence"]


def test_resolved_domain_hit_reports_the_listed_domain():
    b = bl_from("track.example.com")
    DomainResolver(b, resolve=lambda n: [PUB1]).cycle()
    out = ConnDetector(NetPolicy(["10.0.0.0/8"]), b).scan(1, {1}, {1: row(1, PUB1)}, set())
    assert out[0]["evidence"]["blocklist"] == {"list": "t", "kind": "tracker_domain", "entry": "track.example.com"}


# ---- live: a real process connecting to a listed address -------------------------------
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


LOCAL = _local_ip()


@pytest.mark.skipif(not LOCAL, reason="needs a non-loopback address")
def test_live_listed_address_trips_even_when_allowlisted():
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(1)
    port = lis.getsockname()[1]
    p = subprocess.Popen([sys.executable, "-c",
        f"import socket,time;c=socket.create_connection(('{LOCAL}',{port}));time.sleep(30)", "CORA_TASK_BL"])
    try:
        ev = []
        s = Sentinel("CORA_TASK_BL", ["/tmp"], spike_mb=10**6, window_s=5, emit=ev.append,
                     net_allow=["0.0.0.0/0"],                     # allow EVERYTHING ...
                     blocklist=bl_from(f"{LOCAL}/32", "rogue"))   # ... except what is listed
        end = time.monotonic() + 5
        while time.monotonic() < end and not ev:
            s.tick(); time.sleep(0.2)
        e = [x for x in ev if x["anomaly"]["kind"] == "unauthorized_connection"]
        assert e and e[0]["anomaly"]["evidence"]["blocklist"]["list"] == "rogue"
        assert e[0]["anomaly"]["evidence"]["remote_port"] == port
    finally:
        p.kill(); p.wait(); lis.close()
