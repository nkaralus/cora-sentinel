#!/usr/bin/env python3
"""
cora_sentinel.firewall - per-task egress quarantine with nftables. Stdlib only.

Isolation by construction:
  * Its own table (`inet cora`). It never touches any other table, so removing
    it (`purge`) removes every rule Cora ever added and nothing else.
  * One rule per task, matched on the socket's cgroup v2, tagged by a comment
    "cora:<task>". The rule drops everything leaving a non-loopback interface.
  * The kernel is the source of truth: no state file. A restarted daemon reads
    the ruleset back, and `gc` removes rules whose cgroup is gone.

  cora-firewall list | block NAME | unblock NAME | release NAME | gc | purge
  (root: $CORA_CGROUP_ROOT / $CORA_CGROUP_MOUNT, same as cora-cgroup; needs CAP_NET_ADMIN)
"""
from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from cora_sentinel import nftdump
from cora_sentinel.cgroup import DEFAULT_MOUNT, DEFAULT_ROOT, CgroupError, CgroupRoot
from cora_sentinel.nftdump import NftNetlinkError

NFT_BASE = "/sys/fs/cgroup"          # nft resolves cgroupv2 paths from here
PATH_RE = re.compile(r"[A-Za-z0-9_./@-]+", re.ASCII)
TABLE_RE = re.compile(r"[a-z][a-z0-9_]{0,31}", re.ASCII)


class FirewallError(Exception):
    pass


class NftTiming(threading.local):
    """A per-THREAD tally of nft time, so the tap-sync worker's numbers are not mixed with the adjudicator's.
    `lock_ms` is time spent waiting for the cross-process tap lock (filled in by nflog.TapRules)."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.ms = 0.0          # wall time inside nft subprocesses
        self.calls = 0
        self.slowest = 0.0     # the slowest single nft call
        self.slowest_cmd = ""  # ... and which one it was (e.g. '-j list chain' is a dump, '-f -' a commit)
        self.lock_ms = 0.0


def _serialized(fn):
    """Firewall's read-then-write steps must not interleave. They used to rely on the CALLER holding the
    registry lock across nft, which stalled everything else that needs that lock for as long as nft took."""
    @functools.wraps(fn)
    def wrap(self, *a, **kw):
        with self._lock:
            return fn(self, *a, **kw)
    return wrap


Runner = Callable[[List[str], Optional[str]], Tuple[int, str, str]]


def _default_runner(nft: str) -> Runner:
    def run(args: List[str], stdin: Optional[str]) -> Tuple[int, str, str]:
        try:
            p = subprocess.run([nft, *args], input=stdin, capture_output=True,
                               text=True, timeout=10)
        except FileNotFoundError:
            raise FirewallError(f"{nft!r} not found (apt install nftables)") from None
        except subprocess.TimeoutExpired:
            raise FirewallError("nft timed out") from None
        return p.returncode, p.stdout, p.stderr
    return run


class Firewall:
    CHAIN = "egress"

    def __init__(self, cgroups: CgroupRoot, table: str = "cora", nft: str = "nft",
                 nft_base: str = NFT_BASE, run: Optional[Runner] = None):
        if not TABLE_RE.fullmatch(table):
            raise FirewallError(f"bad table name {table!r}")
        self.cg, self.table, self.nft_base = cgroups, table, nft_base
        self.timing = NftTiming()
        # Reads go straight to the kernel over netlink (see nftdump: `nft list` costs rules x cgroups). Only for the
        # real nft, and only when its binary is there: an injected runner (a test's fake) must see every read, and a
        # missing nft must stay a clear error from any operation rather than an empty listing.
        self.native = (run is None and os.environ.get("CORA_NFT_NATIVE", "1") != "0"
                       and shutil.which(nft) is not None)
        raw = run or _default_runner(nft)

        def timed(args: List[str], stdin: Optional[str]) -> Tuple[int, str, str]:
            t = time.monotonic()
            try:
                return raw(args, stdin)
            finally:
                ms, tm = (time.monotonic() - t) * 1000.0, self.timing
                tm.ms += ms
                tm.calls += 1
                if ms > tm.slowest:
                    tm.slowest, tm.slowest_cmd = ms, " ".join(args[:3])
        self._run = timed
        self._lock = threading.RLock()

    # ---- reads: netlink first, the nft command as the fallback ------------------
    def _native_off(self, e: Exception) -> None:
        if self.native:
            self.native = False
            print(f"cora: reading nftables over netlink failed ({e}); using the nft command, which is slower "
                  f"(its listing cost grows with the number of cgroups)", file=sys.stderr)

    def chain_rules(self, chain: str) -> List[dict]:
        """[{handle, comment, packets, bytes}] for one chain of our table; [] if the table or chain is missing."""
        if self.native:
            try:
                return nftdump.dump_rules(self.table, chain)
            except NftNetlinkError as e:
                self._native_off(e)
        rc, out, _ = self._run(["-j", "list", "chain", "inet", self.table, chain], None)
        if rc != 0:
            return []                                    # table or chain not there yet = no rules
        res = []
        for item in json.loads(out).get("nftables", []):
            r = item.get("rule")
            if r:
                cnt = next((e["counter"] for e in r.get("expr", []) if "counter" in e), {})
                res.append({"handle": r["handle"], "comment": r.get("comment"),
                            "packets": cnt.get("packets", 0), "bytes": cnt.get("bytes", 0)})
        return res

    def chain_exists(self, chain: str) -> bool:
        if self.native:
            try:
                return nftdump.chain_exists(self.table, chain)
            except NftNetlinkError as e:
                self._native_off(e)
        rc, _, _ = self._run(["list", "chain", "inet", self.table, chain], None)
        return rc == 0

    def set_exists(self, name: str) -> bool:
        if self.native:
            try:
                return nftdump.set_exists(self.table, name)
            except NftNetlinkError as e:
                self._native_off(e)
        rc, _, _ = self._run(["list", "set", "inet", self.table, name], None)
        return rc == 0

    # ---- plumbing ---------------------------------------------------------
    def _nft(self, args: List[str], stdin: Optional[str] = None) -> str:
        rc, out, err = self._run(args, stdin)
        if rc != 0:
            raise FirewallError((err or out).strip().splitlines()[0][:200] if (err or out).strip()
                                else f"nft exited {rc}")
        return out

    def _script(self, text: str) -> None:
        self._nft(["-f", "-"], text)

    @_serialized
    def _ensure_lines(self) -> List[str]:
        return [f"add table inet {self.table}",
                f"add chain inet {self.table} {self.CHAIN} {{ type filter hook output priority 0 ; policy accept ; }}"]

    def ensure(self) -> None:
        """Idempotent. Creates only our own table and chain."""
        self._script("\n".join(self._ensure_lines()) + "\n")

    # ---- rule text --------------------------------------------------------
    def cgroup_match(self, name: str) -> Tuple[int, str, int]:
        """(level, path, cgroup id) for a task. Level is the depth in the v2 tree, path is
        what nft stats on disk, id is the directory inode. A cgroup deleted and recreated
        under the same name gets a NEW id, which is how stale rules are recognised."""
        task = self.cg._dir(name)  # validates the name, refuses escapes
        level = len(Path(os.path.relpath(task, self.cg.mount)).parts)
        path = os.path.relpath(task, self.nft_base)
        if path.startswith("..") or not PATH_RE.fullmatch(path):
            raise FirewallError(f"cgroup path not usable in a rule: {path!r}")
        try:
            cgid = os.stat(task).st_ino
        except OSError:
            cgid = 0
        return level, path, cgid

    def rule_text(self, name: str) -> str:
        level, path, cgid = self.cgroup_match(name)
        return (f'oifname != "lo" socket cgroupv2 level {level} "{path}" '
                f'counter drop comment "cora:{name}:{cgid}"')

    # ---- state (read back from the kernel) --------------------------------
    def rules(self) -> Dict[str, dict]:
        found: Dict[str, dict] = {}
        for r in self.chain_rules(self.CHAIN):             # {} when the table or chain is not there yet
            c = r["comment"] or ""
            if c.startswith("cora:"):
                name, _, cgid = c[5:].partition(":")       # "cora:<name>[:<cgroup id>]"
                found[name] = {"handle": r["handle"], "packets": r["packets"], "bytes": r["bytes"],
                               "cgid": int(cgid) if cgid.isdigit() else None}
        return found

    def is_blocked(self, name: str) -> bool:
        return name in self.rules()

    # ---- actions ----------------------------------------------------------
    @_serialized
    def block(self, name: str) -> bool:
        """Drop the task's egress. True if newly blocked, False if it already was."""
        text = self.rule_text(name)
        cur = self.cgroup_match(name)[2]
        existing = self.rules().get(name)
        lines: List[str] = []
        if existing is not None:
            if existing["cgid"] == cur:
                return False                # genuinely already blocked
            # stale (same name, a recreated cgroup): replaced in the SAME transaction, so there is no moment in
            # which the task is unblocked between the old rule going and the new one arriving
            lines.append(f"delete rule inet {self.table} {self.CHAIN} handle {existing['handle']}")
        elif not self.chain_exists(self.CHAIN):
            lines += self._ensure_lines()   # only when something is missing: it is a commit of its own
        lines.append(f"add rule inet {self.table} {self.CHAIN} {text}")
        self._script("\n".join(lines) + "\n")                 # ONE transaction per ISOLATE
        return True

    @_serialized
    def unblock(self, name: str) -> bool:
        r = self.rules().get(name)
        if r is None:
            return False
        self._script(f"delete rule inet {self.table} {self.CHAIN} handle {r['handle']}\n")
        return True

    @_serialized
    def gc(self, live: Iterable[str]) -> List[str]:
        """Remove rules whose task cgroup no longer exists."""
        live = set(live)
        gone, dead = [], []
        for n, r in self.rules().items():
            if n not in live:
                gone.append(n)
                dead.append(r["handle"])
            else:                           # live name, but a rule for an older cgroup of that name
                cur = self.cgroup_match(n)[2]
                if r["cgid"] is not None and cur and r["cgid"] != cur:
                    gone.append(n)
                    dead.append(r["handle"])
        if dead:                            # ONE transaction however many tasks died (this runs under the lock
            self._script("\n".join(f"delete rule inet {self.table} {self.CHAIN} handle {h}" for h in dead) + "\n")
        return gone

    @_serialized
    def purge(self) -> None:
        rc, _, _ = self._run(["delete", "table", "inet", self.table], None)
        # rc != 0 just means the table was not there


def release_task(cg: CgroupRoot, fw: Firewall, name: str) -> List[str]:
    """The review action: undo every containment measure on a task."""
    undone: List[str] = []
    if cg.freeze_requested(name) or cg.is_frozen(name):   # requested, not just completed: freezing is async
        cg.thaw(name)
        undone.append("thawed")
    if fw.unblock(name):
        undone.append("egress-unblocked")
    undone += cg.reset_limits(name)
    return undone


def main() -> int:
    cg = CgroupRoot(os.environ.get("CORA_CGROUP_ROOT", DEFAULT_ROOT),
                    os.environ.get("CORA_CGROUP_MOUNT", DEFAULT_MOUNT))
    fw = Firewall(cg, table=os.environ.get("CORA_NFT_TABLE", "cora"))
    a = sys.argv[1:]
    try:
        if a[:1] == ["list"]:
            for n, r in sorted(fw.rules().items()):
                print(f"{n:<24} egress=BLOCKED dropped={r['packets']} pkts / {r['bytes']} B")
            return 0
        if a[:1] == ["gc"]:
            print("removed:", fw.gc(cg.names()) or "nothing")
            return 0
        if a[:1] == ["purge"]:
            fw.purge()
            print(f"table inet {fw.table} removed")
            return 0
        if len(a) == 2 and a[0] == "block":
            print("blocked" if fw.block(a[1]) else "already blocked")
            return 0
        if len(a) == 2 and a[0] == "unblock":
            print("unblocked" if fw.unblock(a[1]) else "was not blocked")
            return 0
        if len(a) == 2 and a[0] == "release":
            print("released:", release_task(cg, fw, a[1]) or "nothing to undo")
            return 0
    except (FirewallError, CgroupError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
