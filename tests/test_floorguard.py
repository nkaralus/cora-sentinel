"""The lockout guard without a kernel: gateway / SSH-peer detection from a fake /proc, the pre-check, and the
dead-man's state machine (confirm, rollback, watchdog, supersede, retry). Real-packet versions are in
test_floor_confirm.py. Run: pytest -q tests/test_floorguard.py"""
import ipaddress
import json
import struct
import sys
import threading
import time

import pytest

from cora_sentinel import floorguard, nftsets
from cora_sentinel.blocklist import Blocklist
from cora_sentinel.firewall import FirewallError
from cora_sentinel.floorguard import FloorGuard, GuardError
from cora_sentinel.nftsets import FloorRefused, FloorSync, NftSets

from test_nftsets import FakeNft, bl_with, sets_of


# ---------------- a fake /proc ----------------
def hex4(ip):
    return "%08X" % struct.unpack("=L", ipaddress.IPv4Address(ip).packed)[0]


def hex6(ip):
    p = ipaddress.IPv6Address(ip).packed
    return "".join("%08X" % struct.unpack("=L", p[i:i + 4])[0] for i in range(0, 16, 4))


def tcp_line(i, lip, lport, rip, rport, st, v6=False):
    h = hex6 if v6 else hex4
    return f"  {i}: {h(lip)}:{lport:04X} {h(rip)}:{rport:04X} {st} 00000000:00000000 00:00000000 00000000     0        0 1 1 0"


TCP_HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


@pytest.fixture
def proc(tmp_path):
    (tmp_path / "net").mkdir()
    r = tmp_path / "net"
    (r / "route").write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        f"eth0\t00000000\t{hex4('192.168.1.1')}\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        f"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        f"eth1\t00000000\t{hex4('10.9.9.9')}\t0001\t0\t0\t200\t00000000\t0\t0\t0\n")     # no RTF_GATEWAY bit: not a gateway
    (r / "ipv6_route").write_text(
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
        "20010db8000000000000000000000000 20 00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n")
    (r / "tcp").write_text("\n".join([
        TCP_HEAD,
        tcp_line(0, "192.168.1.5", 22, "192.168.1.50", 50000, "01"),       # an SSH session
        tcp_line(1, "192.168.1.5", 22, "192.168.1.99", 51000, "0A"),       # LISTEN-ish state: not a session
        tcp_line(2, "192.168.1.5", 8080, "192.168.1.60", 51000, "01"),     # another port
        tcp_line(3, "192.168.1.5", 22, "127.0.0.1", 51000, "01"),          # loopback peer: already allowed
    ]) + "\n")
    (r / "tcp6").write_text("\n".join([
        TCP_HEAD,
        tcp_line(0, "2001:db8::5", 22, "2001:db8::77", 50000, "01", v6=True),
        tcp_line(1, "::ffff:192.168.1.5", 22, "::ffff:192.168.1.70", 50001, "01", v6=True),
    ]) + "\n")
    return str(tmp_path)


def test_gateways_v4_and_v6_only_default_routes_with_the_gateway_flag(proc):
    g = floorguard.default_gateways(proc)
    assert set(g) == {"192.168.1.1", "fe80::1"}


def test_ssh_peers_are_established_sessions_on_the_ssh_port(proc):
    p = floorguard.ssh_peers(proc, env={})
    assert set(p) == {"192.168.1.50", "2001:db8::77", "192.168.1.70"}      # mapped v6 -> v4; no loopback, no 8080, no 0A


def test_ssh_connection_adds_the_client_and_a_nonstandard_port(proc):
    (proc_t := __import__("pathlib").Path(proc, "net", "tcp")).write_text(
        TCP_HEAD + "\n" + tcp_line(0, "192.168.1.5", 2222, "192.168.1.88", 40000, "01") + "\n")
    p = floorguard.ssh_peers(proc, env={"SSH_CONNECTION": "203.0.113.5 41000 192.168.1.5 2222"})
    assert "203.0.113.5" in p and "192.168.1.88" in p                      # the 2222 session is seen via SSH_CONNECTION


def test_protected_merges_and_drops_unusable(proc):
    assert set(floorguard.protected_addresses(proc, env={"SSH_CONNECTION": "127.0.0.1 1 127.0.0.1 22"})) >= {
        "192.168.1.1", "192.168.1.50"}
    assert "127.0.0.1" not in floorguard.protected_addresses(proc, env={"SSH_CONNECTION": "127.0.0.1 1 127.0.0.1 22"})


def test_missing_proc_files_mean_nothing_protected(tmp_path):
    assert floorguard.protected_addresses(str(tmp_path), env={}) == {}


def test_covering_names_the_net():
    idx = floorguard.net_index(["192.168.0.0/16", "2001:db8::/32"])
    assert floorguard.covering("192.168.1.1", idx) == "192.168.0.0/16"
    assert floorguard.covering("2001:db8::7", idx) == "2001:db8::/32"
    assert floorguard.covering("10.0.0.1", idx) is None


def test_fingerprint_ignores_order_and_merging_but_not_content():
    f = lambda e, t="cora", o=-5: floorguard.fingerprint(t, "raw", o, e)      # noqa: E731
    assert f(["10.0.0.0/25", "10.0.0.128/25"]) == f(["10.0.0.0/24"]) == f(["10.0.0.0/24", "10.0.0.0/24"])
    assert f(["10.0.0.0/24"]) != f(["10.0.1.0/24"]) and f(["10.0.0.0/24"]) != f(["10.0.0.0/24"], t="x")
    assert f(["10.0.0.0/24"]) != f(["10.0.0.0/24"], o=-300)


# ---------------- the pre-check ----------------
PEER = {"192.168.1.50": "established session to port 22", "192.168.1.1": "default gateway"}


def fsync(bl_log=None, **kw):
    logs = [] if bl_log is None else bl_log
    f = FakeNft()
    kw.setdefault("protect", lambda: dict(PEER))
    return FloorSync(NftSets(run=f), log=logs.append, resolv=lambda: [], **kw), f, logs


def test_a_list_that_would_drop_an_ssh_peer_is_refused_before_anything_is_installed():
    fs, f, _ = fsync()
    with pytest.raises(FloorRefused) as e:
        fs.apply(bl_with(["192.168.1.0/24"]))
    assert "192.168.1.50" in str(e.value) and "192.168.1.0/24" in str(e.value) and "--floor-allow" in str(e.value)
    assert f.scripts == []


def test_an_allow_entry_covering_the_peer_lets_the_list_through():
    fs, f, _ = fsync(extra_allow=["192.168.1.0/24"])
    fs.apply(bl_with(["192.168.1.0/24"]))
    assert sets_of(f, "static4") == {ipaddress.ip_network("192.168.1.0/24")}


def test_the_blocklist_allow_file_counts_too():
    fs, f, _ = fsync()
    fs.apply(bl_with(["192.168.1.0/24"], allow=["192.168.1.0/24"]))


def test_allow_detected_adds_the_protected_addresses_instead_of_refusing():
    fs, f, _ = fsync(allow_detected=True)
    fs.apply(bl_with(["192.168.1.0/24"]))
    assert {ipaddress.ip_network("192.168.1.50/32"), ipaddress.ip_network("192.168.1.1/32")} <= sets_of(f, "allow4")


def test_no_precheck_skips_it_and_a_list_not_touching_them_never_needed_it():
    fs, f, _ = fsync(precheck=False)
    fs.apply(bl_with(["192.168.1.0/24"]))
    fs2, f2, _ = fsync()
    fs2.apply(bl_with(["203.0.113.0/24"]))                                  # the peers are not covered: no conflict
    assert sets_of(f2, "static4") == {ipaddress.ip_network("203.0.113.0/24")}


def test_a_reload_that_would_drop_a_peer_is_refused_and_the_old_sets_stay():
    fs, f, logs = fsync()
    fs.apply(bl_with(["203.0.113.0/24"]))
    fs.on_reload(bl_with(["192.168.0.0/16"]))
    assert "REFUSED" in logs[-1] and sets_of(f, "static4") == {ipaddress.ip_network("203.0.113.0/24")}


def test_resolved_domain_addresses_never_include_a_protected_address():
    bl = bl_with(["tracker.example.com"], resolved={"192.168.1.50": ("tracker.example.com", "t"),
                                                    "203.0.113.5": ("tracker.example.com", "t")})
    fs, _, _ = fsync(dns=True)
    assert fs.dns_entries(bl) == ["203.0.113.5"]


# ---------------- the dead-man state machine ----------------
@pytest.fixture
def guard(tmp_path):
    fake = FakeNft()
    g = FloorGuard(str(tmp_path / "state"), sets_factory=lambda t: NftSets(table=t, run=fake), spawn=False)
    g.fake = fake
    return g


def removed(fake):
    return any("delete chain" in s for s in fake.scripts)


def test_arm_then_confirm_keeps_the_floor_and_remembers_the_allow_set(guard):
    tok = guard.arm("cora", 60, "fp1")
    assert guard.state(tok) == "pending" and 0 < guard.remaining() <= 60
    assert guard.confirm()[0] is True
    assert guard.state(tok) == "confirmed" and guard.pending() is None and guard.is_confirmed("fp1")
    assert not guard.is_confirmed("fp2")
    assert guard.confirm()[0] is False and not removed(guard.fake)


def test_unconfirm_makes_the_next_start_ask_again(guard):
    guard.arm("cora", 60, "fp1")
    guard.confirm()
    assert guard.unconfirm() is True and not guard.is_confirmed("fp1") and guard.unconfirm() is False


def test_a_pending_record_from_before_a_reboot_is_ignored(guard, monkeypatch):
    guard.arm("cora", 60, "fp1")
    monkeypatch.setattr(floorguard, "boot_id", lambda: "another-boot")
    assert guard.pending() is None and guard.remaining() is None


def test_rollback_removes_the_floor_only_when_pending(guard):
    assert guard.rollback() is False and not removed(guard.fake)
    tok = guard.arm("cora", 60, "fp")
    assert guard.rollback(expected_token="someone-else") is False and not removed(guard.fake)
    assert guard.rollback(expected_token=tok) is True and removed(guard.fake)
    assert guard.state(tok) == "rolledback" and guard.pending() is None


def test_a_confirmed_floor_is_not_rolled_back_by_a_later_rollback(guard):
    guard.arm("cora", 60, "fp")
    guard.confirm()
    assert guard.rollback() is False and not removed(guard.fake)            # ExecStopPost on a normal stop


def test_a_failed_removal_keeps_the_pending_record_for_a_retry(tmp_path):
    def boom(args, stdin):
        return 1, "", "Error: Device or resource busy"
    g = FloorGuard(str(tmp_path), sets_factory=lambda t: NftSets(table=t, run=boom), spawn=False)
    tok = g.arm("cora", 60, "fp")
    with pytest.raises(FirewallError):
        g.rollback(expected_token=tok)
    assert g.state(tok) == "pending"


def test_removal_tolerates_parts_that_are_already_gone(tmp_path):
    def gone(args, stdin):
        return 1, "", "Error: No such file or directory"
    g = FloorGuard(str(tmp_path), sets_factory=lambda t: NftSets(table=t, run=gone), spawn=False)
    tok = g.arm("cora", 60, "fp")
    assert g.rollback(expected_token=tok) is True                            # e.g. after `cora-firewall purge`


def test_arm_refuses_when_the_watchdog_cannot_start(tmp_path):
    g = FloorGuard(str(tmp_path), spawn_prefix=["/nonexistent/binary"])
    with pytest.raises(GuardError):
        g.arm("cora", 60, "fp")
    assert g.pending() is None


def test_arm_refuses_when_the_watchdog_starts_but_never_reports_in(tmp_path):
    g = FloorGuard(str(tmp_path), spawn_prefix=["true"])                     # `true python -m ...` exits at once
    t0 = time.monotonic()
    with pytest.raises(GuardError):
        g.arm("cora", 60, "fp")
    assert g.pending() is None and time.monotonic() - t0 < 4


def pid_alive(pid):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return st != "Z"                                                        # a zombie has exited


def test_a_real_watchdog_process_reports_in_and_exits_when_confirmed(tmp_path):
    g = FloorGuard(str(tmp_path))                                           # really spawns `python -m cora_sentinel.nftsets`
    tok = g.arm("cora_unit_never_exists", 30, "fp")
    pid = g.pending()["watchdog_pid"]
    assert pid and pid_alive(pid)
    assert g.confirm()[0] is True
    for _ in range(50):
        if not pid_alive(pid):
            break
        time.sleep(0.1)
    assert not pid_alive(pid)


# ---------------- the watchdog loop ----------------
def run_watchdog(g, tok, seconds, **kw):
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("rc", floorguard.watchdog(str(g.dir), tok, seconds, **kw)))
    t.start()
    return t, out


def test_unconfirmed_means_rolled_back_at_the_deadline(guard):
    tok = guard.arm("cora", 1, "fp")
    t, out = run_watchdog(guard, tok, 0.4, sets_factory=guard._sets_factory)
    t.join(5)
    assert out["rc"] == 0 and removed(guard.fake) and guard.state(tok) == "rolledback"


def test_a_confirm_before_the_deadline_stops_the_watchdog_without_removing_anything(guard):
    tok = guard.arm("cora", 5, "fp")
    t, out = run_watchdog(guard, tok, 3, sets_factory=guard._sets_factory)
    time.sleep(0.4)
    guard.confirm()
    t0 = time.monotonic()
    t.join(5)
    assert out["rc"] == 0 and time.monotonic() - t0 < 1.5 and not removed(guard.fake)


def test_a_superseded_watchdog_does_nothing(guard):
    old = guard.arm("cora", 5, "fp")
    new = guard.arm("cora", 5, "fp")                                         # the daemon restarted and re-armed
    assert floorguard.watchdog(str(guard.dir), old, 0.2, sets_factory=guard._sets_factory) == 0
    assert not removed(guard.fake) and guard.state(new) == "pending"


def test_the_watchdog_retries_a_failed_removal_and_gives_up_loudly(tmp_path):
    calls = {"n": 0}

    def flaky(args, stdin):
        calls["n"] += 1
        return (1, "", "Error: busy") if calls["n"] <= 2 else (0, "", "")
    g = FloorGuard(str(tmp_path), sets_factory=lambda t: NftSets(table=t, run=flaky), spawn=False)
    tok = g.arm("cora", 1, "fp")
    assert floorguard.watchdog(str(tmp_path), tok, 0, sets_factory=g._sets_factory, sleep=lambda s: None) == 0
    assert g.state(tok) == "rolledback"

    def always(args, stdin):
        return 1, "", "Error: busy"
    g2 = FloorGuard(str(tmp_path / "b"), sets_factory=lambda t: NftSets(table=t, run=always), spawn=False)
    tok2 = g2.arm("cora", 1, "fp")
    assert floorguard.watchdog(str(g2.dir), tok2, 0, sets_factory=g2._sets_factory, sleep=lambda s: None, retries=3) == 1
    assert g2.state(tok2) == "pending"                                       # still recorded, so ExecStopPost can retry


# ---------------- FloorSync.start orchestration ----------------
def test_the_dead_man_is_armed_before_the_floor_is_installed(guard):
    events = []
    orig = guard.arm
    guard.arm = lambda *a, **k: (events.append("arm"), orig(*a, **k))[1]
    f = guard.fake
    inner = f.__call__
    f2 = lambda args, stdin: (events.append("install") if args == ["-f", "-"] else None, inner(args, stdin))[1]   # noqa: E731
    fs = FloorSync(NftSets(run=f2), log=lambda m: None, resolv=lambda: [], protect=lambda: {}, guard=guard)
    fs.start(bl_with(["203.0.113.0/24"]), 60)
    assert events[0] == "arm" and "install" in events and fs.token and guard.state(fs.token) == "pending"


def test_a_failed_install_disarms_the_timer(guard):
    def bad(args, stdin):
        return 1, "", "Error: nope"
    fs = FloorSync(NftSets(run=bad), log=lambda m: None, resolv=lambda: [], protect=lambda: {}, guard=guard)
    with pytest.raises(FirewallError):
        fs.start(bl_with(["203.0.113.0/24"]), 60)
    assert guard.pending() is None


def test_a_pre_check_refusal_never_arms_anything(guard):
    fs = FloorSync(NftSets(run=FakeNft()), log=lambda m: None, resolv=lambda: [], guard=guard,
                   protect=lambda: dict(PEER))
    with pytest.raises(FloorRefused):
        fs.start(bl_with(["192.168.1.0/24"]), 60)
    assert guard.pending() is None


def test_an_allow_set_confirmed_before_needs_no_new_window_but_a_changed_one_does(guard):
    mk = lambda extra: FloorSync(NftSets(run=FakeNft()), log=lambda m: None, resolv=lambda: [],   # noqa: E731
                                 protect=lambda: {}, guard=guard, extra_allow=extra)
    bl = bl_with(["203.0.113.0/24"])
    a = mk(["192.168.0.0/16"])
    a.start(bl, 60)
    guard.confirm()
    b = mk(["192.168.0.0/16"])                                               # a restart, same allow set
    b.start(bl, 60)
    assert b.token is None and guard.pending() is None
    c = mk(["192.168.0.0/16", "10.0.0.0/8"])                                 # someone widened the allow set
    c.start(bl, 60)
    assert c.token and guard.state(c.token) == "pending"


def test_a_dhcp_resolver_change_does_not_reopen_the_window(guard):
    """Resolvers follow DHCP; an unattended reboot must not demand a confirmation nobody is there to give."""
    ns = ["9.9.9.9"]
    mk = lambda: FloorSync(NftSets(run=FakeNft()), log=lambda m: None, resolv=lambda: list(ns),   # noqa: E731
                           protect=lambda: {}, guard=guard, extra_allow=["192.168.0.0/16"])
    bl = bl_with(["203.0.113.0/24"])
    a = mk()
    a.start(bl, 60)
    guard.confirm()
    ns[:] = ["1.1.1.1"]
    b = mk()
    b.start(bl, 60)
    assert b.token is None and guard.pending() is None


def test_static_list_changes_alone_do_not_reopen_the_window(guard):
    mk = lambda: FloorSync(NftSets(run=FakeNft()), log=lambda m: None, resolv=lambda: [],   # noqa: E731
                           protect=lambda: {}, guard=guard)
    a = mk()
    a.start(bl_with(["203.0.113.0/24"]), 60)
    guard.confirm()
    b = mk()
    b.start(bl_with(["198.51.100.0/24", "203.0.113.0/24"]), 60)
    assert b.token is None


def test_poll_reports_each_outcome_once_and_a_rollback_stops_further_syncs(guard):
    logs = []
    f = FakeNft()
    fs = FloorSync(NftSets(run=f), log=logs.append, resolv=lambda: [], protect=lambda: {}, guard=guard)
    fs.start(bl_with(["203.0.113.0/24"]), 60)
    n = len(logs)
    fs.poll()
    assert len(logs) == n                                                    # still pending: silent
    guard.rollback(expected_token=fs.token)
    fs.poll()
    fs.poll()
    assert sum("ROLLED BACK" in m for m in logs) == 1 and fs.disabled
    scripts = len(f.scripts)
    fs.on_reload(bl_with(["198.51.100.0/24"]))
    assert len(f.scripts) == scripts                                         # the daemon does not rebuild what was rolled back


def test_a_reload_after_a_silent_rollback_is_also_skipped(guard):
    f = FakeNft()
    logs = []
    fs = FloorSync(NftSets(run=f), log=logs.append, resolv=lambda: [], protect=lambda: {}, guard=guard)
    fs.start(bl_with(["203.0.113.0/24"]), 60)
    guard.rollback(expected_token=fs.token)                                  # the daemon has not polled yet
    n = len(f.scripts)
    fs.on_reload(bl_with(["198.51.100.0/24"]))
    assert len(f.scripts) == n and any("rolled back" in m for m in logs)


# ---------------- CLI and daemon flags ----------------
def test_cli_confirm_pending_rollback_and_unconfirm(tmp_path, capsys):
    sd = str(tmp_path)
    assert nftsets.main(["--state-dir", sd, "confirm"]) == 1
    assert nftsets.main(["--state-dir", sd, "pending"]) == 0 and "none" in capsys.readouterr().out
    assert nftsets.main(["--state-dir", sd, "rollback"]) == 0 and "nothing pending" in capsys.readouterr().out
    assert nftsets.main(["--state-dir", sd, "unconfirm"]) == 0 and "nothing was confirmed" in capsys.readouterr().out
    g = FloorGuard(sd, spawn=False)
    g.arm("cora", 60, "fp")
    assert nftsets.main(["--state-dir", sd, "pending"]) == 0 and "left to confirm" in capsys.readouterr().out
    assert nftsets.main(["--state-dir", sd, "confirm"]) == 0 and "stays" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["--floor-confirm", "60"], ["--floor", "--nft", "--cgroup-root", "/x", "--floor-confirm", "5"],
                                  ["--floor", "--nft", "--cgroup-root", "/x", "--floor-confirm", "99999"]])
def test_floor_confirm_flag_is_validated(argv, monkeypatch, capsys):
    from cora_sentinel import daemon
    monkeypatch.setattr(sys, "argv", ["cora-sentinel", *argv])
    assert daemon.main() == 1
    assert "--floor" in capsys.readouterr().err
