#!/usr/bin/env python3
"""
cora_sentinel.nftsets - the kernel-side blocklist floor. Stdlib only.

Known-bad addresses live in nftables sets and are dropped in the kernel, so a packet to a listed address is
refused before userspace has to see it. The tap keeps logging (audit, attribution, escalation to the model);
this module only closes the "first packet escapes" gap that 0.4.0 documented.

Layout (all inside the same table the Firewall uses, `inet cora` by default):

  allow4 / allow6      interval   ALWAYS accepted first: loopback, resolvers, your LAN, the blocklist allow list.
                                  A bad list or a bad verdict cannot lock the host out.
  static4 / static6    interval   the blocklist's subnets and addresses. No timeout. Delta-synced.
  dns4 / dns6          hash       addresses the DomainResolver resolved for listed domains. OPT-IN (--floor-dns):
                                  host-wide, and many tracker names sit on shared CDN addresses.
  dyn4 / dyn6          timeout    adjudicator / operator verdicts about one address. The KERNEL expires them.
  dynflow4 / dynflow6  timeout    the same for one (address, protocol, port) so a shared address survives.

  floor_in   (prerouting, priority raw)  accept lo, allow*, then log+drop for every block set on saddr
  floor_out  (output,     priority -5 )  the same on daddr

floor_out sits AFTER the tap chain (-10) on purpose: the tap still logs the first packet and attributes it to a
task, then the floor drops it before it leaves. At `raw` the drop would come first and the daemon would never
hear about the attempt. `out_priority` is a parameter if you want the other trade.

Rules that exist because the naive version gets them wrong:

  * LOG AND DROP ARE TWO RULES. `limit rate N log ... drop` in one rule drops only the packets UNDER the limit;
    the rest fall through to accept, so a scan would walk straight past the floor.
  * ONE TRANSACTION PER SYNC. Deletes and adds for a set go in one `nft -f` script, so an element that stays in
    the list is never absent for a moment, and a daemon killed mid-sync leaves the old state or the new one.
  * DELTA, NOT FLUSH. Only the difference is sent. Live dyn* elements are never touched by a list sync.
  * THE DAEMON DYING DOES NOT LIFT THE FLOOR. Sets and chains stay in the kernel; `cora-floor remove` or
    `cora-firewall purge` takes them out.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import threading
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from cora_sentinel.firewall import TABLE_RE, FirewallError, Runner, _default_runner

FLOOR_IN, FLOOR_OUT = "floor_in", "floor_out"
LOG_GROUP = 72                 # audit group; the tap uses 71. Unbound = the kernel discards the log records
LOG_RATE = "10/second"
IN_PRIORITY = "raw"            # -300: before conntrack allocates state
OUT_PRIORITY = -5              # after the tap (-10), before the per-task egress drop (0)
CHUNK = 1000                   # elements per statement
SAFE_ALLOW = ("127.0.0.0/8", "::1/128")
MAX_TTL_S = 7 * 86400

# set name -> declaration body. Order does not matter; all are `add`ed, so live elements survive.
SETS: Dict[str, str] = {
    "allow4":   "type ipv4_addr; flags interval;",
    "allow6":   "type ipv6_addr; flags interval;",
    "static4":  "type ipv4_addr; flags interval; counter;",
    "static6":  "type ipv6_addr; flags interval; counter;",
    "dns4":     "type ipv4_addr; counter;",
    "dns6":     "type ipv6_addr; counter;",
    "dyn4":     "type ipv4_addr; flags timeout; timeout 1h; size 65536; counter;",
    "dyn6":     "type ipv6_addr; flags timeout; timeout 1h; size 65536; counter;",
    "dynflow4": "type ipv4_addr . inet_proto . inet_service; flags timeout; timeout 10m; size 65536;",
    "dynflow6": "type ipv6_addr . inet_proto . inet_service; flags timeout; timeout 10m; size 65536;",
}
ADDR_SETS = (("static4", "ip"), ("static6", "ip6"), ("dns4", "ip"), ("dns6", "ip6"),
             ("dyn4", "ip"), ("dyn6", "ip6"))
FLOW_SETS = (("dynflow4", "ip"), ("dynflow6", "ip6"))
PROTOS = {"tcp": "tcp", "udp": "udp", "6": "tcp", "17": "udp"}


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------
def _flatten(el) -> List[str]:
    """One element of `nft -j list set` -> text tokens (an address, a prefix, a range, or a concatenation)."""
    if isinstance(el, (str, int)):
        return [str(el)]
    if "elem" in el:
        return _flatten(el["elem"]["val"])
    if "prefix" in el:
        return [f'{el["prefix"]["addr"]}/{el["prefix"]["len"]}']
    if "range" in el:
        return [f'{el["range"][0]}-{el["range"][1]}']
    if "concat" in el:
        return [" . ".join(" ".join(_flatten(x)) for x in el["concat"])]
    return []


def _norm_net(tok: str):
    n = ipaddress.ip_network(tok.strip(), strict=False)
    if n.version == 6 and n.network_address.ipv4_mapped is not None and n.prefixlen >= 96:
        n = ipaddress.ip_network((n.network_address.ipv4_mapped, n.prefixlen - 96))
    return n


def parse_entries(tokens: Iterable[str]) -> Tuple[List, List]:
    """cidr / single address / a-b range tokens -> (v4 nets, v6 nets), NOT collapsed. Blank and '#' lines skipped."""
    v4, v6 = [], []
    for tok in tokens:
        tok = tok.strip()
        if not tok or tok.startswith("#"):
            continue
        if "-" in tok and "/" not in tok:
            a, b = (ipaddress.ip_address(x.strip()) for x in tok.split("-", 1))
            nets = list(ipaddress.summarize_address_range(a, b))
        else:
            nets = [_norm_net(tok)]
        for n in nets:
            (v4 if n.version == 4 else v6).append(n)
    return v4, v6


def _fmt(n) -> str:
    return str(n.network_address) if n.num_addresses == 1 else str(n)


def _unwrap(a):
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


# --------------------------------------------------------------------------
# NftSets
# --------------------------------------------------------------------------
class NftSets:
    def __init__(self, table: str = "cora", run: Optional[Runner] = None, nft: str = "nft",
                 log_group: int = LOG_GROUP, log_rate: str = LOG_RATE, out_priority: int = OUT_PRIORITY,
                 in_priority: str = IN_PRIORITY):
        if not TABLE_RE.fullmatch(table):
            raise FirewallError(f"bad table name {table!r}")
        if not re.fullmatch(r"\d{1,6}/(second|minute)", log_rate):
            raise FirewallError(f"bad log rate {log_rate!r}")
        self.table, self.group, self.rate = table, int(log_group), log_rate
        self.out_priority, self.in_priority = out_priority, in_priority
        self._run: Runner = run or _default_runner(nft)

    @classmethod
    def from_firewall(cls, fw, **kw) -> "NftSets":
        """Share the Firewall's table and its (timed) nft runner, so a test's fake or the real nft is used alike."""
        return cls(table=fw.table, run=fw._run, **kw)

    # ---- plumbing ----------------------------------------------------------
    def _script(self, text: str) -> None:
        rc, out, err = self._run(["-f", "-"], text)
        if rc != 0:
            msg = (err or out).strip().splitlines()
            raise FirewallError(msg[0][:300] if msg else f"nft exited {rc}")

    def list_set(self, name: str) -> List[str]:
        rc, out, err = self._run(["-j", "list", "set", "inet", self.table, name], None)
        if rc != 0:
            msg = (err or out).strip().splitlines()
            raise FirewallError(msg[0][:300] if msg else f"cannot list set {name}")
        toks: List[str] = []
        for item in json.loads(out).get("nftables", []):
            for el in (item.get("set") or {}).get("elem", []):
                toks.extend(_flatten(el))
        return toks

    def table_exists(self) -> bool:
        rc, _, _ = self._run(["list", "table", "inet", self.table], None)
        return rc == 0

    # ---- bootstrap ---------------------------------------------------------
    def rule_lines(self, direction: str) -> List[str]:
        """The chain body. Exposed so a test can assert the shape (no rule may carry both `limit` and `drop`)."""
        a, iface, port = (("saddr", "iifname", "sport") if direction == "in" else ("daddr", "oifname", "dport"))
        rules = [f'{iface} "lo" accept', f"ip {a} @allow4 accept", f"ip6 {a} @allow6 accept"]
        for s, fam in ADDR_SETS:
            rules.append(f'{fam} {a} @{s} limit rate {self.rate} log group {self.group} prefix "cora-floor:{s}:{direction} "')
            rules.append(f"{fam} {a} @{s} counter drop")
        for s, fam in FLOW_SETS:
            key = f"{fam} {a} . meta l4proto . th {port}"
            rules.append(f'{key} @{s} limit rate {self.rate} log group {self.group} prefix "cora-floor:{s}:{direction} "')
            rules.append(f"{key} @{s} counter drop")
        return rules

    def ensure_script(self) -> str:
        t = f"inet {self.table}"
        lines = [f"add table {t}"]
        lines += [f"add set {t} {name} {{ {body} }}" for name, body in SETS.items()]
        for chain, hook, prio, d in ((FLOOR_IN, "prerouting", self.in_priority, "in"),
                                     (FLOOR_OUT, "output", self.out_priority, "out")):
            lines.append(f"add chain {t} {chain} {{ type filter hook {hook} priority {prio} ; policy accept ; }}")
            lines.append(f"flush chain {t} {chain}")
            lines += [f"add rule {t} {chain} {r}" for r in self.rule_lines(d)]
        return "\n".join(lines) + "\n"

    def ensure(self) -> None:
        """Idempotent. Sets are only `add`ed, so live elements survive; the two chains are flushed and refilled in
        the same transaction. If an existing chain has a different priority nft refuses: `cora-floor remove` first."""
        self._script(self.ensure_script())

    def remove(self) -> None:
        """Take out only the floor (chains, then sets). The per-task egress chain and the tap are untouched."""
        t = f"inet {self.table}"
        lines: List[str] = []
        for chain in (FLOOR_IN, FLOOR_OUT):
            lines += [f"flush chain {t} {chain}", f"delete chain {t} {chain}"]
        lines += [f"delete set {t} {name}" for name in SETS]
        self._script("\n".join(lines) + "\n")

    # ---- delta sync of list sets -------------------------------------------
    def _plan(self, name: str, want: Set, live_tokens: Sequence[str]) -> Tuple[List[str], List[str], int, int]:
        """-> (delete texts, add texts, n_added, n_removed). Works on what the kernel actually stores."""
        live: Dict = {}                       # net -> the text that deletes it
        for tok in live_tokens:
            tok = tok.strip()
            if "-" in tok and "/" not in tok:
                a, b = (ipaddress.ip_address(x.strip()) for x in tok.split("-", 1))
                nets = list(ipaddress.summarize_address_range(a, b))
                text = tok if len(nets) != 1 else _fmt(nets[0])
            else:
                nets, text = [_norm_net(tok)], None
                text = _fmt(nets[0])
            for n in nets:
                live[n] = text
        gone = set(live) - want
        del_texts = sorted({live[n] for n in gone})
        deleted = set(del_texts)
        add = sorted((want - set(live)) | {n for n in want if live.get(n) in deleted}, key=lambda n: (n.version, int(n.network_address), n.prefixlen))
        return del_texts, [_fmt(n) for n in add], len(add), len(gone)

    def _stmts(self, name: str, dels: List[str], adds: List[str]) -> List[str]:
        out = []
        for kind, items in (("delete", dels), ("add", adds)):
            for i in range(0, len(items), CHUNK):
                out.append(f"{kind} element inet {self.table} {name} {{ {', '.join(items[i:i + CHUNK])} }}")
        return out

    def _sync(self, base: str, v4: List, v6: List, collapse: bool,
              guard: Optional[float] = None) -> Tuple[int, int]:
        """Delta-sync `base`4 and `base`6 in ONE transaction. Returns (added, removed)."""
        stmts: List[str] = []
        added = removed = 0
        for suffix, nets in (("4", v4), ("6", v6)):
            want = set(ipaddress.collapse_addresses(nets)) if collapse else set(nets)
            name = base + suffix
            live_tokens = self.list_set(name)
            dels, adds, na, nr = self._plan(name, want, live_tokens)
            if guard is not None and len(live_tokens) >= 20 and nr > guard * len(live_tokens):
                dels, nr = [], 0               # refuse a mass removal: keep what is blocked, add what is new
            stmts += self._stmts(name, dels, adds)
            added, removed = added + na, removed + nr
        if stmts:
            self._script("\n".join(stmts) + "\n")
        return added, removed

    def sync_static(self, entries: Iterable[str]) -> Tuple[int, int]:
        v4, v6 = parse_entries(entries)
        return self._sync("static", v4, v6, collapse=True)

    def sync_allow(self, entries: Iterable[str]) -> Tuple[int, int]:
        v4, v6 = parse_entries(entries)
        return self._sync("allow", v4, v6, collapse=True)

    def sync_dns(self, addrs: Iterable[str], guard: Optional[float] = 0.5) -> Tuple[int, int]:
        """Mirror resolved addresses. With `guard` (default 0.5) a sync that would remove more than that fraction of a
        set of 20+ addresses is applied add-only: a DNS outage must not unblock everything. guard=None forces it."""
        v4, v6 = parse_entries(addrs)
        return self._sync("dns", v4, v6, collapse=False, guard=guard)

    # ---- dynamic verdicts (kernel timeout, no GC thread) ---------------------
    @staticmethod
    def _addr(ip: str):
        a = _unwrap(ipaddress.ip_address(str(ip).strip()))
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            raise ValueError(f"refusing to block {a}")
        return a

    @staticmethod
    def _ttl(ttl_s) -> int:
        t = int(ttl_s)
        if not 0 < t <= MAX_TTL_S:
            raise ValueError(f"ttl must be 1..{MAX_TTL_S} seconds")
        return t

    def block_ip(self, ip: str, ttl_s: int = 3600) -> None:
        a, t = self._addr(ip), self._ttl(ttl_s)
        self._script(f"add element inet {self.table} dyn{a.version} {{ {a} timeout {t}s }}\n")

    def unblock_ip(self, ip: str) -> bool:
        a = self._addr(ip)
        try:
            self._script(f"delete element inet {self.table} dyn{a.version} {{ {a} }}\n")
        except FirewallError as e:
            if "No such file" in str(e) or "does not exist" in str(e):
                return False
            raise
        return True

    def block_flow(self, ip: str, proto: str, port: int, ttl_s: int = 600) -> None:
        a, t = self._addr(ip), self._ttl(ttl_s)
        p = PROTOS.get(str(proto).lower())
        if p is None:
            raise ValueError("proto must be tcp or udp")
        if not 0 < int(port) < 65536:
            raise ValueError("bad port")
        self._script(f"add element inet {self.table} dynflow{a.version} "
                     f"{{ {a} . {p} . {int(port)} timeout {t}s }}\n")

    # ---- reading back ------------------------------------------------------
    def drop_counts(self) -> Dict[str, int]:
        """Packets dropped by the floor, per direction, from the drop rules' counters."""
        res = {"in": 0, "out": 0}
        for chain, d in ((FLOOR_IN, "in"), (FLOOR_OUT, "out")):
            rc, out, _ = self._run(["-j", "list", "chain", "inet", self.table, chain], None)
            if rc != 0:
                continue
            for item in json.loads(out).get("nftables", []):
                r = item.get("rule")
                if not r:
                    continue
                exprs = r.get("expr", [])
                if any("drop" in e for e in exprs):
                    res[d] += sum(e["counter"]["packets"] for e in exprs if "counter" in e)
        return res

    def status(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for name in SETS:
            try:
                out[name] = len(self.list_set(name))
            except FirewallError:
                out[name] = -1                 # set missing
        return out

    def reconcile(self, static: Iterable[str], allow: Iterable[str],
                  dns: Optional[Iterable[str]] = None) -> Dict[str, Tuple[int, int]]:
        """Daemon start. Rebuild chains, then make the lists match, ALLOW FIRST so a bad static entry cannot lock the
        host out between the two commits. `dns=None` CLEARS the dns sets (an opt-out must not leave old drops behind)."""
        self.ensure()
        res = {"allow": self.sync_allow(allow), "static": self.sync_static(static)}
        res["dns"] = self.sync_dns(dns if dns is not None else [], guard=None if dns is None else 0.5)
        return res


# --------------------------------------------------------------------------
# glue between a Blocklist and the sets
# --------------------------------------------------------------------------
def resolv_conf_nameservers(path: str = "/etc/resolv.conf") -> List[str]:
    out: List[str] = []
    try:
        for line in Path(path).read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                try:
                    out.append(str(_unwrap(ipaddress.ip_address(parts[1].split("%")[0]))))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


class FloorSync:
    """Keeps the kernel sets equal to the daemon's Blocklist. Called at start, on a hot reload and after each
    resolver cycle (two different threads, so it serialises itself)."""

    def __init__(self, sets: NftSets, extra_allow: Sequence[str] = (), dns: bool = False,
                 log: Callable[[str], None] = lambda m: print(f"[cora-sentinel] {m}", file=sys.stderr, flush=True),
                 resolv: Optional[Callable[[], List[str]]] = None):
        self.sets, self.extra_allow, self.dns, self.log = sets, list(extra_allow), dns, log
        self._resolv = resolv or resolv_conf_nameservers
        self._lock = threading.Lock()

    def allow_entries(self, bl) -> List[str]:
        out = list(SAFE_ALLOW) + self._resolv() + self.extra_allow
        if bl is not None and bl.allow is not None:
            out += sorted(bl.allow.entries()[1])
        return out

    @staticmethod
    def static_entries(bl) -> List[str]:
        return sorted(bl.entries()[1]) if bl is not None else []

    def dns_entries(self, bl) -> List[str]:
        """Resolved addresses the userspace matcher would call a hit (so the allow list already won)."""
        if bl is None or not self.dns:
            return []
        return [ip for ip in sorted(bl._resolved) if bl.match_ip(ip)]

    def apply(self, bl) -> str:
        """Full reconcile. Raises FirewallError if nft refuses."""
        with self._lock:
            if bl is not None and bl.allow is not None and bl.allow.domains:
                self.log("floor: allow-list DOMAINS are not mirrored into the kernel (only subnets and addresses)")
            r = self.sets.reconcile(self.static_entries(bl), self.allow_entries(bl),
                                    self.dns_entries(bl) if self.dns else None)
            msg = (f"kernel floor on: allow +{r['allow'][0]}/-{r['allow'][1]}, static +{r['static'][0]}/-{r['static'][1]}, "
                   f"dns +{r['dns'][0]}/-{r['dns'][1]}{'' if self.dns else ' (off)'}")
            self.log(msg)
            return msg

    def on_reload(self, bl) -> None:
        """Hot reload: allow first, then static. Failure keeps the old sets (they only ever change atomically)."""
        with self._lock:
            try:
                a = self.sets.sync_allow(self.allow_entries(bl))
                s = self.sets.sync_static(self.static_entries(bl))
                self.log(f"floor reloaded: allow +{a[0]}/-{a[1]}, static +{s[0]}/-{s[1]}")
            except (FirewallError, OSError, ValueError) as e:
                self.log(f"floor reload FAILED, keeping the previous sets: {e}")

    def on_resolver_cycle(self, bl) -> None:
        if not self.dns:
            return
        with self._lock:
            try:
                a, r = self.sets.sync_dns(self.dns_entries(bl))
                if a or r:
                    self.log(f"floor dns sets: +{a}/-{r}")
            except (FirewallError, OSError, ValueError) as e:
                self.log(f"floor dns sync FAILED, keeping the previous sets: {e}")


# --------------------------------------------------------------------------
# cora-floor
# --------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="cora-floor", description="Inspect and drive the kernel-side blocklist floor.")
    ap.add_argument("--table", default=os.environ.get("CORA_NFT_TABLE", "cora"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="element count per set and packets dropped per direction")
    p = sub.add_parser("list", help="print one set's elements"); p.add_argument("set", choices=sorted(SETS))
    sub.add_parser("ensure", help="create the sets and chains (idempotent)")
    sub.add_parser("remove", help="remove the floor only (not the egress chain or the tap)")
    p = sub.add_parser("block", help="block an address host-wide until its timeout")
    p.add_argument("ip"); p.add_argument("ttl", nargs="?", type=int, default=3600)
    p = sub.add_parser("unblock"); p.add_argument("ip")
    p = sub.add_parser("block-flow", help="block one (address, proto, port)")
    p.add_argument("ip"); p.add_argument("proto", choices=("tcp", "udp")); p.add_argument("port", type=int)
    p.add_argument("ttl", nargs="?", type=int, default=600)
    p = sub.add_parser("sync-static", help="make static4/static6 match these blocklist files (address and subnet entries)")
    p.add_argument("files", nargs="+")
    a = ap.parse_args(argv)
    ns = NftSets(table=a.table)
    try:
        if a.cmd == "status":
            for k, v in ns.status().items():
                print(f"{k:<10} {'(missing)' if v < 0 else v}")
            d = ns.drop_counts()
            print(f"dropped    in={d['in']} out={d['out']} packets")
        elif a.cmd == "list":
            print("\n".join(ns.list_set(a.set)))
        elif a.cmd == "ensure":
            ns.ensure(); print("floor ensured")
        elif a.cmd == "remove":
            ns.remove(); print("floor removed")
        elif a.cmd == "block":
            ns.block_ip(a.ip, a.ttl); print(f"blocked {a.ip} for {a.ttl}s")
        elif a.cmd == "unblock":
            print("unblocked" if ns.unblock_ip(a.ip) else "was not blocked")
        elif a.cmd == "block-flow":
            ns.block_flow(a.ip, a.proto, a.port, a.ttl); print("flow blocked")
        elif a.cmd == "sync-static":
            from cora_sentinel.blocklist import Blocklist
            bl = Blocklist()
            for f in a.files:
                bl.load(f)
            added, removed = ns.sync_static(FloorSync.static_entries(bl))
            print(f"static sets: +{added} -{removed} ({bl.summary()})")
    except (FirewallError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
