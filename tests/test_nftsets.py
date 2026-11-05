"""The kernel-side floor, without a kernel: a fake nft that keeps set contents and applies `-f -` scripts
all-or-nothing. The real-packet tests are in test_floor_gate.py. Run: pytest -q tests/test_nftsets.py"""
import ipaddress
import json
import re
import sys

import pytest

from cora_sentinel import nftsets
from cora_sentinel.blocklist import Blocklist
from cora_sentinel.firewall import FirewallError
from cora_sentinel.nftsets import FloorSync, NftSets, parse_entries
from cora_sentinel.reload import Reloader

from test_reload import sentinel  # reuse the Sentinel builder


def mkfs(*a, **kw):
    """FloorSync with the host's real gateway / SSH peers taken out of the picture (they differ per machine)."""
    kw.setdefault("protect", lambda: {})
    return FloorSync(*a, **kw)


class FakeNft:
    """sets: name -> list of element tokens. A script is applied to a copy and kept only if every statement works."""
    ELEM = re.compile(r"^(add|delete) element inet (\S+) (\S+) \{ (.*) \}$")

    def __init__(self, **sets):
        self.sets = {k: list(v) for k, v in sets.items()}
        self.scripts, self.chain_json = [], {}

    def _norm(self, t):
        return str(ipaddress.ip_network(t, strict=False)) if re.match(r"^[0-9a-f:.]+(/\d+)?$", t) else t

    def __call__(self, args, stdin):
        if args[:3] == ["-j", "list", "set"]:
            toks = self.sets.get(args[5], [])
            els = []
            for t in toks:
                if "/" in t:
                    a, l = t.split("/")
                    els.append({"elem": {"val": {"prefix": {"addr": a, "len": int(l)}}, "counter": {"packets": 0}}})
                else:
                    els.append({"elem": {"val": t, "counter": {"packets": 0}}})
            return 0, json.dumps({"nftables": [{"set": {"name": args[5], "elem": els}}]}), ""
        if args[:3] == ["-j", "list", "chain"]:
            return (0, json.dumps(self.chain_json[args[5]]), "") if args[5] in self.chain_json else (1, "", "Error: No such file")
        if args == ["-f", "-"]:
            self.scripts.append(stdin)
            work = {k: list(v) for k, v in self.sets.items()}
            for line in stdin.strip().splitlines():
                m = self.ELEM.match(line)
                if not m:
                    continue
                kind, name = m.group(1), m.group(3)
                for el in m.group(4).split(", "):
                    el = el.split(" timeout ")[0].strip()
                    cur = work.setdefault(name, [])
                    if kind == "add":
                        if el not in cur:
                            cur.append(el)
                    elif el in cur:
                        cur.remove(el)
                    else:
                        return 1, "", "Error: Could not process rule: No such file or directory"
            self.sets = work
            return 0, "", ""
        return 0, "", ""


def sets_of(fake, name):
    return set(ipaddress.ip_network(t) for t in fake.sets.get(name, []))


# ---------------- the chain's shape ----------------
def test_no_rule_carries_both_limit_and_drop():
    """`limit ... log ... drop` in one rule lets every over-limit packet fall through to accept."""
    ns = NftSets(run=FakeNft())
    for d in ("in", "out"):
        for r in ns.rule_lines(d):
            assert not ("limit" in r and "drop" in r), r


def test_each_block_set_logs_then_drops_and_allow_comes_first():
    rules = NftSets(run=FakeNft()).rule_lines("out")
    assert rules[0].startswith('oifname "lo" accept')
    assert "@allow4 accept" in rules[1] and "@allow6 accept" in rules[2]
    for name in ("static4", "static6", "dns4", "dns6", "dyn4", "dyn6", "dynflow4", "dynflow6"):
        idx = [i for i, r in enumerate(rules) if f"@{name} " in r]
        assert len(idx) == 2 and "log group" in rules[idx[0]] and rules[idx[1]].endswith("counter drop")
        assert idx[0] > 2                          # every block comes after the allow rules


def test_outbound_floor_sits_after_the_tap_and_inbound_at_raw():
    script = NftSets(run=FakeNft()).ensure_script()
    assert "hook prerouting priority raw" in script
    assert "hook output priority -5" in script     # the tap is at -10: it still sees the first packet


def test_ensure_adds_sets_but_never_flushes_or_deletes_them():
    script = NftSets(run=FakeNft()).ensure_script()
    assert "flush set" not in script and "delete set" not in script and "delete element" not in script
    assert script.count("flush chain") == 2        # only the two floor chains are rebuilt


def test_table_name_is_validated():
    with pytest.raises(FirewallError):
        NftSets(table="bad name;")


# ---------------- delta sync ----------------
def test_sync_sends_only_the_difference_in_one_transaction():
    f = FakeNft(static4=["10.0.0.1", "10.0.0.3", "10.0.0.5"])
    ns = NftSets(run=f)
    assert ns.sync_static(["10.0.0.3", "10.0.0.5", "10.0.0.9"]) == (1, 1)
    assert len(f.scripts) == 1                     # one commit for v4 and v6 together
    s = f.scripts[0]
    assert "delete element inet cora static4 { 10.0.0.1 }" in s and "add element inet cora static4 { 10.0.0.9 }" in s
    assert "10.0.0.3" not in s and "10.0.0.5" not in s     # staying elements are never touched, so never absent
    assert sets_of(f, "static4") == {ipaddress.ip_network(x) for x in ("10.0.0.3", "10.0.0.5", "10.0.0.9")}


def test_a_sync_with_nothing_to_change_commits_nothing():
    f = FakeNft(static4=["10.0.0.1"])
    assert NftSets(run=f).sync_static(["10.0.0.1"]) == (0, 0)
    assert f.scripts == []


def test_entries_are_collapsed_so_the_kernel_never_sees_an_overlap():
    f = FakeNft()
    NftSets(run=f).sync_static(["10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/24", "# note", "", "2001:db8::/33"])
    assert sets_of(f, "static4") == {ipaddress.ip_network("10.0.0.0/24")}
    assert sets_of(f, "static6") == {ipaddress.ip_network("2001:db8::/33")}


def test_ipv4_mapped_entries_become_ipv4():
    v4, v6 = parse_entries(["::ffff:192.0.2.1"])
    assert [str(n) for n in v4] == ["192.0.2.1/32"] and v6 == []


def test_a_big_list_is_chunked_but_still_one_script():
    f = FakeNft()
    NftSets(run=f).sync_static([f"100.64.{(2 * i) // 256}.{(2 * i) % 256}" for i in range(2500)])   # non-adjacent
    assert len(f.scripts) == 1 and f.scripts[0].count("add element") == 3     # 1000 + 1000 + 500, one commit
    assert len(sets_of(f, "static4")) == 2500


def test_a_failed_transaction_changes_nothing():
    f = FakeNft(static4=["10.0.0.1"])
    ns = NftSets(run=f)
    with pytest.raises(FirewallError):
        ns._script("add element inet cora static4 { 10.0.0.9 }\ndelete element inet cora static4 { 10.9.9.9 }\n")
    assert f.sets["static4"] == ["10.0.0.1"]


# ---------------- dns mirror ----------------
def test_dns_sync_refuses_a_mass_removal_but_still_adds():
    live = [f"198.51.100.{i}" for i in range(40)]
    f = FakeNft(dns4=live)
    ns = NftSets(run=f)
    a, r = ns.sync_dns(["198.51.100.1", "203.0.113.9"])          # a resolver outage: 39 of 40 vanish
    assert (a, r) == (1, 0) and len(f.sets["dns4"]) == 41        # nothing unblocked, the new one added
    assert ns.sync_dns(["198.51.100.1"], guard=None)[1] == 40    # forced


def test_small_sets_are_not_guarded():
    f = FakeNft(dns4=["198.51.100.1", "198.51.100.2"])
    assert NftSets(run=f).sync_dns([])[1] == 2


def test_reconcile_allows_first_and_clears_dns_when_it_is_not_wanted():
    f = FakeNft(dns4=["198.51.100.1"] * 1 + [f"203.0.113.{i}" for i in range(30)])
    ns = NftSets(run=f)
    res = ns.reconcile(["192.0.2.0/24"], ["127.0.0.0/8"], dns=None)
    assert f.sets["dns4"] == [] and res["dns"][1] == 31
    commits = [s for s in f.scripts if "element" in s]
    assert "allow4" in commits[0] and "static4" in commits[1]    # allow commit precedes the static commit
    assert ns.reconcile(["192.0.2.0/24"], ["127.0.0.0/8"], dns=None)["static"] == (0, 0)   # idempotent


# ---------------- dynamic verdicts ----------------
def test_block_ip_validation_and_script():
    f = FakeNft()
    ns = NftSets(run=f)
    ns.block_ip("203.0.113.7", 90)
    assert "add element inet cora dyn4 { 203.0.113.7 timeout 90s }" in f.scripts[-1]
    ns.block_ip("::ffff:203.0.113.8")
    assert "dyn4 { 203.0.113.8 timeout 3600s }" in f.scripts[-1]
    ns.block_ip("2001:db8::1")
    assert "dyn6" in f.scripts[-1]
    for bad in ("127.0.0.1", "::1", "0.0.0.0", "224.0.0.1"):
        with pytest.raises(ValueError):
            ns.block_ip(bad)
    for ttl in (0, -5, 10**9):
        with pytest.raises(ValueError):
            ns.block_ip("203.0.113.7", ttl)


def test_block_flow_validation_and_script():
    f = FakeNft()
    ns = NftSets(run=f)
    ns.block_flow("203.0.113.7", "TCP", 443, 60)
    assert "dynflow4 { 203.0.113.7 . tcp . 443 timeout 60s }" in f.scripts[-1]
    for args in (("203.0.113.7", "icmp", 1), ("203.0.113.7", "tcp", 0), ("203.0.113.7", "tcp", 70000)):
        with pytest.raises(ValueError):
            ns.block_flow(*args)


def test_unblock_of_an_absent_element_is_false_not_an_error():
    f = FakeNft(dyn4=["203.0.113.7"])
    ns = NftSets(run=f)
    assert ns.unblock_ip("203.0.113.7") is True and ns.unblock_ip("203.0.113.7") is False


def test_drop_counts_sum_only_drop_rules():
    f = FakeNft()
    f.chain_json["floor_out"] = {"nftables": [
        {"rule": {"expr": [{"match": {}}, {"counter": {"packets": 7, "bytes": 1}}, {"drop": None}]}},
        {"rule": {"expr": [{"match": {}}, {"limit": {}}, {"log": {}}]}},
        {"rule": {"expr": [{"counter": {"packets": 5, "bytes": 1}}, {"accept": None}]}},
        {"rule": {"expr": [{"counter": {"packets": 3, "bytes": 1}}, {"drop": None}]}}]}
    assert NftSets(run=f).drop_counts() == {"in": 0, "out": 10}


def test_elements_with_counters_and_ranges_flatten():
    assert nftsets._flatten({"elem": {"val": {"prefix": {"addr": "10.0.0.0", "len": 8}}}}) == ["10.0.0.0/8"]
    assert nftsets._flatten({"range": ["10.0.0.1", "10.0.0.9"]}) == ["10.0.0.1-10.0.0.9"]
    assert nftsets._flatten({"elem": {"val": {"concat": ["1.2.3.4", "tcp", 443]}}}) == ["1.2.3.4 . tcp . 443"]


def test_a_live_range_is_replaced_not_overlapped():
    f = FakeNft(static4=["10.0.0.1-10.0.0.6"])           # a foreign range element (3 prefixes)
    ns = NftSets(run=f)
    ns.sync_static(["10.0.0.4/30"])
    s = f.scripts[0]
    assert "delete element inet cora static4 { 10.0.0.1-10.0.0.6 }" in s and "add element inet cora static4 { 10.0.0.4/30 }" in s


# ---------------- glue with the Blocklist ----------------
def bl_with(lines, allow=(), resolved=None):
    b = Blocklist()
    for ln in lines:
        b.add_line(ln, "t")
    if allow:
        b.allow = Blocklist()
        for ln in allow:
            b.allow.add_line(ln, "allow")
    if resolved:
        b.set_resolved(resolved)
    return b


def test_floor_sync_composes_allow_from_safe_resolvers_flags_and_the_allow_list():
    fs = mkfs(NftSets(run=FakeNft()), extra_allow=["192.168.0.0/16"], log=lambda m: None,
                   resolv=lambda: ["9.9.9.9"])
    got = fs.allow_entries(bl_with(["203.0.113.0/24"], allow=["198.51.100.0/24"]))
    assert {"127.0.0.0/8", "::1/128", "9.9.9.9", "192.168.0.0/16", "198.51.100.0/24"} <= set(got)


def test_floor_sync_applies_static_from_the_blocklist_and_keeps_dns_off_by_default():
    f = FakeNft()
    logs = []
    fs = mkfs(NftSets(run=f), log=logs.append, resolv=lambda: [])
    bl = bl_with(["203.0.113.0/24", "tracker.example.com"], resolved={"93.184.216.34": ("tracker.example.com", "t")})
    fs.apply(bl)
    assert sets_of(f, "static4") == {ipaddress.ip_network("203.0.113.0/24")}
    assert f.sets.get("dns4", []) == []                           # opt-in only
    assert "(off)" in logs[-1]


def test_dns_entries_skip_what_the_allow_list_wins_and_need_the_flag():
    bl = bl_with(["tracker.example.com"], allow=["93.184.216.0/24"],
                 resolved={"93.184.216.34": ("tracker.example.com", "t"), "203.0.113.5": ("tracker.example.com", "t")})
    assert mkfs(NftSets(run=FakeNft()), dns=True).dns_entries(bl) == ["203.0.113.5"]
    assert mkfs(NftSets(run=FakeNft()), dns=False).dns_entries(bl) == []


def test_on_reload_follows_the_new_list_and_failure_keeps_the_old_sets():
    f, logs = FakeNft(), []
    fs = mkfs(NftSets(run=f), log=logs.append, resolv=lambda: [])
    fs.apply(bl_with(["203.0.113.0/24"]))
    fs.on_reload(bl_with(["198.51.100.0/24"]))
    assert sets_of(f, "static4") == {ipaddress.ip_network("198.51.100.0/24")}

    def boom(args, stdin):
        return 1, "", "Error: nope"
    fs.sets._run = boom
    fs.on_reload(bl_with(["192.0.2.0/24"]))                       # logged, not raised
    assert "FAILED" in logs[-1]


def test_reloader_calls_on_reload_with_the_new_list_after_the_swap():
    old, new, seen = bl_with(["203.0.113.0/24"]), bl_with(["198.51.100.0/24"]), []
    s = sentinel(old)
    r = Reloader(s, lambda: (new, []), log=lambda m: None, on_reload=lambda b: seen.append((b, s.conn.blocklist)))
    assert r.reload_now() == "ok"
    assert seen == [(new, new)]                                   # already live when the hook runs


def test_a_failing_hook_does_not_undo_the_reload():
    old, new, logs = bl_with(["203.0.113.0/24"]), bl_with(["198.51.100.0/24"]), []
    s = sentinel(old)

    def bad(_):
        raise RuntimeError("x")
    r = Reloader(s, lambda: (new, []), log=logs.append, on_reload=bad)
    assert r.reload_now() == "ok" and s.conn.blocklist is new and any("hook failed" in m for m in logs)


# ---------------- the daemon's flag checks ----------------
@pytest.mark.parametrize("argv", [["--floor"], ["--floor", "--nft"], ["--floor-dns", "--nft", "--cgroup-root", "/x"]])
def test_floor_flags_are_refused_without_their_prerequisites(argv, monkeypatch, capsys):
    from cora_sentinel import daemon
    monkeypatch.setattr(sys, "argv", ["cora-sentinel", *argv])
    assert daemon.main() == 1
    assert "--floor needs" in capsys.readouterr().err


def test_cora_floor_cli_is_importable_and_validates_its_table():
    assert callable(nftsets.main)
    with pytest.raises(FirewallError):
        NftSets(table="Bad")
