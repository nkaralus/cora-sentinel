#!/usr/bin/env python3
"""
cora_sentinel.blocklist - tracker-domain and rogue-subnet blocklists. Stdlib only.

Accepted line formats (mix freely, one list per file, list name = file stem):
    203.0.113.0/24            CIDR            1.2.3.4            single IP
    tracker.example.com       domain (also matches every subdomain)
    *.example.com             same as above
    0.0.0.0 ads.example.com   hosts-file line (the sink address is ignored)
    ||ads.example.com^        adblock-style domain rule
    1.2.3.0/24 ; SBL12345     Spamhaus DROP style (comments: '#' or ';')

Safety rails, because a poisoned list can quarantine every task on the box:
    * entries broader than /8 (v4) or /16 (v6) are rejected
    * entries overlapping loopback or the unspecified address are rejected
    * anything in an --allow list wins over the blocklist

Connections expose IPs, not hostnames. Domain entries therefore match through
DomainResolver, which resolves listed names to addresses in the background.
Shared CDN addresses can false-positive; that is what the allow list is for.
"""
from __future__ import annotations

import collections
import ipaddress
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Tuple

LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
DOMAIN_RE = re.compile(rf"(?:{LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})", re.ASCII)
ADBLOCK_RE = re.compile(r"\|\|([^/^*|\s]+)\^?")
MIN_V4, MIN_V6 = 8, 16
PROTECTED = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "0.0.0.0/32", "::1/128", "::/128")]
HOSTS_NOISE = {"localhost", "localhost.localdomain", "broadcasthost", "local", "ip6-localhost"}
MAX_FILE = 50 * 1024 * 1024
SUFFIXES = {"", ".txt", ".list", ".hosts", ".domains", ".cidr", ".nets", ".netset", ".ipset"}


class Hit(NamedTuple):
    list: str      # which blocklist file
    kind: str      # "tracker_domain" | "rogue_subnet"
    entry: str     # the exact entry that matched


def _ip_or_net(tok: str):
    try:
        return ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return None


def _norm(a):
    a = ipaddress.ip_address(a) if not hasattr(a, "version") else a
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


class Blocklist:
    def __init__(self, min_v4: int = MIN_V4, min_v6: int = MIN_V6):
        self.min = {4: min_v4, 6: min_v6}
        self.domains: Dict[str, str] = {}
        self._nets: Dict[int, Dict[int, Dict[int, Tuple[str, str]]]] = {4: {}, 6: {}}
        self.rejects: collections.Counter = collections.Counter()
        self.n_nets = 0
        self._resolved: Dict[str, Tuple[str, str]] = {}
        self.allow: Optional["Blocklist"] = None

    # ---- parsing ----------------------------------------------------------
    def add_line(self, raw: str, list_name: str) -> int:
        line = raw.strip()
        if not line or line[0] in "#!;[":
            return 0
        m = ADBLOCK_RE.fullmatch(line)
        if m:
            cands = [m.group(1)]
        else:
            line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
            toks = line.split()
            if not toks:
                return 0
            if len(toks) >= 2 and "/" not in toks[0] and _ip_or_net(toks[0]) is not None:
                cands = [t for t in toks[1:] if t.lower() not in HOSTS_NOISE]  # hosts line
            elif len(toks) == 1:
                cands = toks
            else:
                self.rejects["bad_entry"] += 1
                return 0
        added = 0
        for c in cands:
            added += self._add_one(c, list_name)
        return added

    def _add_one(self, tok: str, list_name: str) -> int:
        net = _ip_or_net(tok)
        if net is not None:
            if net.prefixlen < self.min[net.version]:
                self.rejects["too_broad"] += 1
                return 0
            if any(net.version == p.version and net.overlaps(p) for p in PROTECTED):
                self.rejects["protected"] += 1
                return 0
            self._nets[net.version].setdefault(net.prefixlen, {})[int(net.network_address)] = \
                (list_name, str(net))
            self.n_nets += 1
            return 1
        d = tok.lower().lstrip("*").lstrip(".").rstrip(".")
        if len(d) > 253 or not DOMAIN_RE.fullmatch(d):
            self.rejects["bad_entry"] += 1
            return 0
        self.domains.setdefault(d, list_name)
        return 1

    def load_file(self, path, list_name: Optional[str] = None) -> int:
        p = Path(path)
        if p.stat().st_size > MAX_FILE:
            raise ValueError(f"{p} is larger than {MAX_FILE} bytes")
        name = (list_name or p.stem).lower()
        n = 0
        with p.open(errors="replace") as f:
            for line in f:
                n += self.add_line(line, name)
        return n

    def load(self, path) -> int:
        p = Path(path)
        if p.is_dir():
            return sum(self.load_file(f) for f in sorted(p.iterdir())
                       if f.is_file() and not f.name.startswith(".") and f.suffix.lower() in SUFFIXES)
        return self.load_file(p)

    # ---- matching ---------------------------------------------------------
    def match_net(self, ip) -> Optional[Hit]:
        a = _norm(ip)
        bits = a.max_prefixlen
        for plen in sorted(self._nets[a.version], reverse=True):  # most specific first
            shift = bits - plen
            key = (int(a) >> shift) << shift
            hit = self._nets[a.version][plen].get(key)
            if hit:
                return Hit(hit[0], "rogue_subnet", hit[1])
        return None

    def match_domain(self, name: str) -> Optional[Hit]:
        parts = name.lower().rstrip(".").split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.domains:
                return Hit(self.domains[cand], "tracker_domain", cand)
        return None

    def match_name(self, name: str) -> Optional[Hit]:
        """A DNS query name (not an address). The allow list wins, exactly as it does for addresses."""
        hit = self.match_domain(name)
        if hit and self.allow and self.allow.match_domain(name):
            return None
        return hit

    def match_ip(self, ip) -> Optional[Hit]:
        a = _norm(ip)
        if self.allow and self.allow.match_net(a):
            return None
        hit = self.match_net(a)
        if hit:
            return hit
        r = self._resolved.get(str(a))
        if r:
            domain, lst = r
            if self.allow and self.allow.match_domain(domain):
                return None
            return Hit(lst, "tracker_domain", domain)
        return None

    def set_resolved(self, mapping: Dict[str, Tuple[str, str]]) -> None:
        self._resolved = mapping  # atomic swap; readers never see a half-built map

    def entries(self) -> Tuple[set, set]:
        """(domains, networks as normalized strings): what a diff compares."""
        nets = {e for v in self._nets.values() for per_len in v.values() for (_, e) in per_len.values()}
        return set(self.domains), nets

    def summary(self) -> str:
        rej = dict(self.rejects) or "none"
        return (f"{len(self.domains)} domains, {self.n_nets} subnets/IPs, "
                f"{len(self._resolved)} resolved addrs, rejected={rej}")


# --------------------------------------------------------------------------
# domain -> address resolution (background; never touches the poll loop)
# --------------------------------------------------------------------------
def system_resolve(name: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos})


class DomainResolver:
    """Resolves listed domains to addresses in the background, so a flow to a listed domain's CDN address matches
    even though the packet carries no name. `rebind()` points it at a new list (hot reload) and primes that list
    from the cache FIRST, so a reload never opens a window in which resolved addresses stop matching."""

    def __init__(self, bl: Blocklist, resolve: Callable[[str], Iterable[str]] = system_resolve,
                 max_per_cycle: int = 2000, workers: int = 8, deadline_s: float = 60.0,
                 interval_s: float = 3600.0,
                 on_cycle: Optional[Callable[[int], None]] = None):
        self.on_cycle = on_cycle
        self.bl, self.resolve = bl, resolve
        self.max, self.workers = max_per_cycle, workers
        self.deadline_s, self.interval_s = deadline_s, interval_s
        self._dom_ips: Dict[str, FrozenSet[str]] = {}
        self._cursor = 0
        self._state = threading.Lock()          # guards bl, _dom_ips, _cursor; NEVER held across a DNS lookup
        self._wake = threading.Event()          # kick(): run a cycle now instead of at the next interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _publish(self) -> None:
        """Build the address map for the CURRENT list from the cache. Caller holds _state. Entries for domains
        that are no longer listed are ignored, so a removed domain stops matching immediately."""
        bl = self.bl
        ipmap: Dict[str, Tuple[str, str]] = {}
        for dom, ips in sorted(self._dom_ips.items()):
            if dom not in bl.domains:
                continue
            for ip in ips:
                ipmap.setdefault(ip, (dom, bl.domains[dom]))
        bl.set_resolved(ipmap)

    def cycle(self) -> int:
        with self._state:
            names = sorted(self.bl.domains)
            if not names:
                return 0
            # Never-resolved names go first (after a reload, the new entries); the rest rotate with a cursor.
            fresh = [n for n in names if n not in self._dom_ips][:self.max]
            stale = [n for n in names if n in self._dom_ips]
            rot = [stale[(self._cursor + i) % len(stale)] for i in range(min(self.max - len(fresh), len(stale)))]
            if stale:
                self._cursor = (self._cursor + len(rot)) % len(stale)
            batch = fresh + rot
        got: Dict[str, FrozenSet[str]] = {}
        ex = ThreadPoolExecutor(max_workers=self.workers)
        futs = {ex.submit(lambda n=n: list(self.resolve(n))): n for n in batch}
        try:
            for f in as_completed(futs, timeout=self.deadline_s):
                try:
                    ips = f.result()
                except Exception:
                    continue
                keep = set()
                for ip in ips:
                    try:
                        a = _norm(ip)
                    except ValueError:
                        continue
                    if a.is_global:           # drop sinkholes (0.0.0.0, 127.x, private)
                        keep.add(str(a))
                got[futs[f]] = frozenset(keep)
        except Exception:
            pass                               # deadline hit: keep what we have
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        with self._state:
            self._dom_ips.update(got)
            for n in fresh:                    # attempted and got nothing (NXDOMAIN, timeout): count it as tried,
                self._dom_ips.setdefault(n, frozenset())      # or it would stay "fresh" and starve the rotation
            self._publish()                    # onto the CURRENT list, even if a reload happened mid-cycle
        return len(got)

    def rebind(self, new_bl: Blocklist) -> None:
        """Hot reload: aim at `new_bl` and fill its address map from the cache before it goes live."""
        with self._state:
            self.bl = new_bl
            self._dom_ips = {d: ips for d, ips in self._dom_ips.items() if d in new_bl.domains}
            self._cursor = 0
            self._publish()

    def kick(self) -> None:
        self._wake.set()

    def start(self) -> None:
        def loop():
            while not self._stop.is_set():
                self._wake.clear()
                n = self.cycle()
                if self.on_cycle:
                    self.on_cycle(n)
                self._wake.wait(self.interval_s)
        self._thread = threading.Thread(target=loop, name="blocklist-resolver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()


def main(argv=None) -> int:
    import sys
    a = sys.argv[1:] if argv is None else list(argv)
    if a[:1] and a[0] in ("pull", "diff", "accept", "status", "verify", "sync", "sync-rollback") or (a[:1] == ["--dir"]):
        from cora_sentinel.blocklist_store import main as store_main
        return store_main(a)
    if len(a) < 2 or a[0] != "check":
        print("usage: cora-blocklist check PATH [ip-or-domain ...]\n"
              "       cora-blocklist [--dir D] pull | status | diff [NAME] | accept NAME --sha256 HEX | verify | sync | sync-rollback")
        return 2
    bl = Blocklist()
    bl.load(a[1])
    print(bl.summary())
    for q in a[2:]:
        try:
            h = bl.match_net(q)
        except ValueError:
            h = None
        h = h or bl.match_domain(q)
        print(f"{q:<32} {h if h else 'no match'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
