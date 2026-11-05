#!/usr/bin/env python3
"""
cora_sentinel.dynpolicy - model verdicts into the kernel's dyn sets, conservatively. Stdlib only.

When the model isolates a task for talking to a public address, the NEXT task to reach that address would still
get its first packet out. This module turns such a verdict into a short-lived, host-wide kernel drop. It is the
riskiest thing in the daemon, because the model is a 3B network of text and a task controls both the address it
connects to and the text the model reads: a hostile task could try to talk the model into cutting off a victim
address. So the policy is boring and bounded on purpose.

  MODES        off | shadow | enforce. SHADOW (the default) computes everything, including budgets and escalation,
               and writes what it WOULD do into the decision log; the kernel is not touched. ENFORCE writes only when
               the adjudicator is itself enforcing; otherwise it stays in shadow.

  WHO          Only a final ISOLATE that the MODEL chose (not the blocklist floor: those addresses are already in
               the static sets), at confidence >= 0.9, whose gate passed and whose action ran. ESCALATE ("needs a
               human") never writes. The target comes from the event's evidence, never from the model.

  NEVER        non-public addresses, anything the allow set or the lockout guard protects (gateway, SSH peers,
               resolvers), and infrastructure ports (DNS 53/853, NTP 123): a task using another public resolver must
               not make the host lose DNS.

  WHAT         The observed flow (address, proto, port), 10 minutes, x4 on each repeat offense up to 24 h.
               WEB PORTS (80/443): flow only, never the whole address. nft cannot see SNI or Host and QUIC names are
               not recoverable, so a flow block on 443 hits every site behind a shared address; the safety there
               is the TTL, the budgets and shadow mode. Promote a web address through the blocklist path, with a human.
               OTHER PORTS: flow first; the whole address (30 min, x4 up to 24 h) once two distinct tasks have hit
               non-web ports of it within an hour.

  LIMITS       20 kernel writes per minute (token bucket), 512 live elements, 8 distinct targets per task per hour.
               A task that goes quiet-but-noisy cannot block the internet one verdict at a time.

  UNDO         `cora-firewall release TASK` drops the elements that task alone caused (and demotes a whole-address
               block that no longer has two distinct tasks behind it). The kernel expires everything else.

The ledger lives in the state directory (one file per mode, flock-guarded, because `release` is a different process
from the daemon). It remembers offenses for 7 days so a repeat offender escalates across days.
"""
from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import json
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from cora_sentinel.firewall import FirewallError

WEB_PORTS = frozenset({80, 443})
INFRA_PORTS = frozenset({53, 853, 123})
FLOW_BASE_S, IP_BASE_S, ESCALATE, TTL_CAP_S = 600, 1800, 4, 86400
WINDOW_S, MEMORY_S, MAX_ENTRIES = 3600, 7 * 86400, 8192
ACTED = ("done:", "dry-run:")
MODES = ("off", "shadow", "enforce")


@dataclass
class DynConfig:
    min_conf: float = 0.9
    write_per_min: int = 20
    max_live: int = 512
    task_cap: int = 8
    promote_tasks: int = 2
    flow_base_s: int = FLOW_BASE_S
    ip_base_s: int = IP_BASE_S


def _unwrap(a):
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def _esc(base: int, offenses: int) -> int:
    return int(min(base * ESCALATE ** max(0, offenses - 1), TTL_CAP_S))


def _active(e: Optional[dict], now: float) -> bool:
    return bool(e) and e["expires"] > now


# --------------------------------------------------------------------------
# the ledger
# --------------------------------------------------------------------------
class DynLedger:
    """A small JSON document under a flock. path=None keeps it in memory (an unwritable state directory)."""

    def __init__(self, path: Optional[str]):
        self.path = Path(path) if path else None
        self._mem: dict = {}
        self._tlock = threading.RLock()

    @staticmethod
    def empty() -> dict:
        return {"v": 1, "flows": {}, "ips": {}, "watch": {}, "targets": {}}

    def _load(self) -> dict:
        if self.path is None:
            return self._mem or self.empty()
        try:
            doc = json.loads(self.path.read_text())
            if isinstance(doc, dict) and doc.get("v") == 1:
                for k, v in self.empty().items():
                    doc.setdefault(k, v)
                return doc
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            with contextlib.suppress(OSError):
                os.replace(self.path, str(self.path) + ".corrupt")          # keep it for a human; start clean
        return self.empty()

    def _save(self, doc: dict) -> None:
        if self.path is None:
            self._mem = doc
            return
        tmp = Path(str(self.path) + ".tmp")
        tmp.write_text(json.dumps(doc, separators=(",", ":")))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    @contextlib.contextmanager
    def txn(self):
        with self._tlock:
            fd = None
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                doc = self._load()
                yield doc
                self._save(doc)                 # not reached if the body raised: nothing half-written
            finally:
                if fd is not None:
                    os.close(fd)

    def read(self) -> dict:
        with self._tlock:
            return self._load()


def _ledger_path(state_dir: Optional[str], eff: str) -> Optional[str]:
    return str(Path(state_dir) / f"dyn-ledger-{eff}.json") if state_dir else None


# --------------------------------------------------------------------------
# the policy
# --------------------------------------------------------------------------
class DynPolicy:
    def __init__(self, mode: str = "shadow", sets=None, exempt: Optional[Callable[[str], Optional[str]]] = None,
                 state_dir: Optional[str] = None, cfg: Optional[DynConfig] = None,
                 clock: Callable[[], float] = time.time,
                 log: Callable[[str], None] = lambda m: print(f"[cora-sentinel] {m}", file=sys.stderr, flush=True)):
        if mode not in MODES:
            raise ValueError(f"bad dyn policy {mode!r}")
        self.mode, self.sets, self.exempt, self.cfg, self.clock, self.log = mode, sets, exempt, cfg or DynConfig(), clock, log
        self.state_dir = state_dir
        self._ledgers: Dict[str, DynLedger] = {}
        self.stats = {"blocked": 0, "would_block": 0, "skipped": 0, "failed": 0}

    def _ledger(self, eff: str) -> DynLedger:
        if eff not in self._ledgers:
            path = _ledger_path(self.state_dir, eff)
            try:
                if path:
                    Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            except OSError as e:
                self.log(f"dyn policy: state directory not writable ({e}); keeping the {eff} ledger in memory only")
                path = None
            self._ledgers[eff] = DynLedger(path)
        return self._ledgers[eff]

    # ---- the one entry point ----
    def consider(self, ev: dict, d: dict) -> Optional[dict]:
        """Called by the adjudicator with the event and its decision. Returns the record to store under
        decision['dyn'], or None when this decision is not the policy's business. Raises nothing the caller must
        handle beyond what it already catches."""
        if self.mode == "off" or d.get("final") != "ISOLATE":
            return None
        m = d.get("model") or {}
        if m.get("verdict") != "ISOLATE":
            return None                                   # the floor or a fallback isolated it, not the model
        skip = self._skip
        act = str(d.get("action", ""))
        if not act.startswith(ACTED):
            return skip("not_acted")                      # the gate refused, or the action failed
        evd = (ev.get("anomaly") or {}).get("evidence") or {}
        if evd.get("blocklist"):
            return skip("blocklist")                      # already in the static sets
        if float(m.get("confidence", 0.0)) < self.cfg.min_conf:
            return skip("low_confidence")
        try:
            ip = _unwrap(ipaddress.ip_address(str(evd.get("remote_ip", ""))))
            port = int(evd.get("remote_port"))
        except (ValueError, TypeError):
            return skip("no_destination")
        if evd.get("dest_class", "public") != "public" or not ip.is_global:
            return skip(f"dest_class:{evd.get('dest_class', 'non-global')}")
        proto = str(evd.get("proto", "tcp")).lower()
        if proto not in ("tcp", "udp") or not 0 < port < 65536:
            return skip("bad_flow")
        if port in INFRA_PORTS:
            return skip("infra_port")
        why = self.exempt(str(ip)) if self.exempt else None
        if why:
            return skip(why)
        subj = ev.get("subject") or {}
        task = subj.get("cgroup") or subj.get("name") or str(subj.get("pid"))
        eff = "enforce" if (self.mode == "enforce" and act.startswith("done:") and self.sets is not None) else "shadow"
        led = self._ledger(eff)
        with led.txn() as L:
            rec = self._decide(L, eff, ip, proto, port, str(task))
        self.stats[{"blocked": "blocked", "refreshed": "blocked", "promoted": "blocked", "would_block": "would_block",
                    "would_refresh": "would_block", "would_promote": "would_block", "failed": "failed"}
                   .get(rec["result"], "skipped")] += 1
        return rec

    def _skip(self, reason: str) -> dict:
        self.stats["skipped"] += 1
        return {"mode": self.mode, "result": "skipped", "reason": reason}

    # ---- budgets ----
    def _take(self, L: dict, now: float) -> bool:
        cap = float(self.cfg.write_per_min)
        b = L.setdefault("bucket", {"tokens": cap, "ts": now})
        b["tokens"] = min(cap, b["tokens"] + max(0.0, now - b["ts"]) * cap / 60.0)
        b["ts"] = now
        if b["tokens"] >= 1.0:
            b["tokens"] -= 1.0
            return True
        return False

    @staticmethod
    def _live(L: dict, now: float) -> int:
        return sum(1 for k in ("flows", "ips") for e in L[k].values() if _active(e, now))

    def _task_ok(self, L: dict, task: str, key: str, now: float) -> bool:
        lst = [x for x in L["targets"].get(task, []) if x[0] > now - WINDOW_S]
        L["targets"][task] = lst
        keys = {k for _, k in lst}
        return key in keys or len(keys) < self.cfg.task_cap

    @staticmethod
    def _note(L: dict, task: str, key: str, now: float) -> None:
        L["targets"].setdefault(task, []).append([now, key])

    # ---- the kernel write (enforce only) ----
    def _write(self, eff: str, kind: str, ip, proto: str, port: int, ttl: int) -> Optional[str]:
        if eff != "enforce":
            return None
        try:
            if kind == "ip":
                self.sets.block_ip(str(ip), ttl)
            else:
                self.sets.block_flow(str(ip), proto, port, ttl)       # re-adding an element refreshes its timeout
        except (FirewallError, ValueError, OSError) as e:
            return f"{e.__class__.__name__}: {e}"[:140]
        return None

    # ---- the decision ----
    def _decide(self, L: dict, eff: str, ip, proto: str, port: int, task: str) -> dict:
        now, cfg = self.clock(), self.cfg
        self._prune(L, now)                            # first: a week-old offense must not be read as memory
        ip_s, web = str(ip), port in WEB_PORTS
        fkey = f"{ip_s}|{proto}|{port}"
        flows, ips = L["flows"], L["ips"]
        verb = (lambda a, w: a if eff == "enforce" else w)                                 # noqa: E731
        base = {"mode": eff, "web": web, "port": port, "proto": proto}

        ntasks = 0
        if not web:                                    # only non-web hits count towards a whole-address block
            w = {t: ts for t, ts in L["watch"].get(ip_s, {}).items() if ts > now - WINDOW_S}
            w[task] = now
            L["watch"][ip_s] = w
            ntasks = len(w)
        ie, fe = ips.get(ip_s), flows.get(fkey)
        ip_active = _active(ie, now)

        def finish(rec: dict) -> dict:
            self._prune(L, now)
            return {**base, **rec}

        # a block that already covers this flow: dedupe, or a repeat offense by a NEW task
        covering = ie if ip_active else (fe if _active(fe, now) else None)
        if covering is not None and not (not web and not ip_active and ntasks >= cfg.promote_tasks):
            kind, key = ("ip", ip_s) if ip_active else ("flow", fkey)
            covering["last"] = now
            covering["hits"] += 1
            if task in covering["tasks"]:
                covering["tasks"][task] = now
                return finish({"result": "dedupe", "kind": kind, "key": key, "tasks": len(covering["tasks"])})
            covering["tasks"][task] = now
            if not self._take(L, now):
                return finish({"result": "skipped", "reason": "budget", "kind": kind, "key": key})
            off = covering["offenses"] + 1
            ttl = _esc(cfg.ip_base_s if kind == "ip" else cfg.flow_base_s, off)
            err = self._write(eff, kind, ip, proto, port, ttl)
            if err:
                return finish({"result": "failed", "error": err, "kind": kind, "key": key})
            covering.update(offenses=off, ttl_s=ttl, expires=now + ttl)
            self._note(L, task, key, now)
            return finish({"result": verb("refreshed", "would_refresh"), "kind": kind, "key": key, "ttl_s": ttl,
                           "offense": off, "tasks": len(covering["tasks"])})

        # a new element: promote to the whole address, or block the flow
        promote = (not web) and ntasks >= cfg.promote_tasks
        kind, key, table, prev = (("ip", ip_s, ips, ie) if promote else ("flow", fkey, flows, fe))
        if self._live(L, now) >= cfg.max_live:
            return finish({"result": "skipped", "reason": "standing_cap", "kind": kind, "key": key})
        if not self._task_ok(L, task, key, now):
            return finish({"result": "skipped", "reason": "task_cap", "kind": kind, "key": key})
        if not self._take(L, now):
            return finish({"result": "skipped", "reason": "budget", "kind": kind, "key": key})
        off = (prev["offenses"] if prev else 0) + 1
        ttl = _esc(cfg.ip_base_s if promote else cfg.flow_base_s, off)
        err = self._write(eff, kind, ip, proto, port, ttl)
        if err:
            return finish({"result": "failed", "error": err, "kind": kind, "key": key})
        tasks = dict(L["watch"][ip_s]) if promote else {task: now}
        entry = {"ip": ip_s, "tasks": tasks, "first": prev["first"] if prev else now, "last": now,
                 "hits": (prev["hits"] if prev else 0) + 1, "offenses": off, "ttl_s": ttl, "expires": now + ttl}
        if kind == "flow":
            entry.update(proto=proto, port=port)
        table[key] = entry
        self._note(L, task, key, now)
        return finish({"result": verb("promoted" if promote else "blocked",
                                      "would_promote" if promote else "would_block"),
                       "kind": kind, "key": key, "ttl_s": ttl, "offense": off, "tasks": len(tasks)})

    def _prune(self, L: dict, now: float) -> None:
        for name in ("flows", "ips"):
            t = L[name]
            for k in [k for k, e in t.items() if e["expires"] <= now and e["last"] < now - MEMORY_S]:
                del t[k]
        total = len(L["flows"]) + len(L["ips"])
        if total > MAX_ENTRIES:                                # bound the file: oldest EXPIRED entries go first
            dead = sorted(((e["last"], name, k) for name in ("flows", "ips") for k, e in L[name].items()
                           if e["expires"] <= now))
            for _, name, k in dead[:total - MAX_ENTRIES]:
                del L[name][k]
        for ipk in list(L["watch"]):
            L["watch"][ipk] = {t: ts for t, ts in L["watch"][ipk].items() if ts > now - WINDOW_S}
            if not L["watch"][ipk]:
                del L["watch"][ipk]
        for t in list(L["targets"]):
            L["targets"][t] = [x for x in L["targets"][t] if x[0] > now - WINDOW_S]
            if not L["targets"][t]:
                del L["targets"][t]

    # ---- keeping the ledger honest ----
    def reconcile(self) -> int:
        """Mark ledger entries whose kernel element has vanished (an operator unblocked it, the floor was removed) as
        expired, so a new hit blocks again instead of being deduplicated against a block that is not there."""
        if self.sets is None:
            return 0
        try:
            live_f, live_i = self.sets.live_flows(), self.sets.live_ips()
        except FirewallError:
            return 0                                                                  # no floor: nothing to compare
        now, n = self.clock(), 0
        with self._ledger("enforce").txn() as L:
            for table, live in ((L["flows"], live_f), (L["ips"], live_i)):
                for key, e in table.items():
                    if _active(e, now) and key not in live:
                        e["expires"], e["vanished"], n = now, True, n + 1
        if n:
            self.log(f"dyn policy: {n} ledger entr{'y' if n == 1 else 'ies'} no longer in the kernel; will block again on a new hit")
        return n


# --------------------------------------------------------------------------
# undo and review
# --------------------------------------------------------------------------
def release_entries(task: str, state_dir: Optional[str], sets=None, promote_tasks: int = 2,
                    clock: Callable[[], float] = time.time) -> List[str]:
    """Drop what `task` alone caused. Used by `cora-firewall release`. Returns what it undid, for printing."""
    undone: List[str] = []
    now = clock()
    for eff in ("enforce", "shadow"):
        path = _ledger_path(state_dir, eff)
        if not path or not Path(path).exists():
            continue
        with DynLedger(path).txn() as L:
            def drop(table: dict, key: str, e: dict, label: str, task_ts: float) -> None:
                """Remove one entry. If the kernel refuses, put the task back so a retry still finds it."""
                if _active(e, now) and eff == "enforce" and sets is not None:
                    try:
                        if label == "ip":
                            sets.unblock_ip(e["ip"])
                        else:
                            sets.unblock_flow(e["ip"], e["proto"], e["port"])
                    except (FirewallError, ValueError, OSError) as err:
                        e["tasks"][task] = task_ts
                        undone.append(f"dyn-unblock-FAILED:{key}:{err}")
                        return
                    undone.append(f"dyn-{label}-unblocked:{key}")
                elif _active(e, now) and eff == "shadow":
                    undone.append(f"dyn-{label}-dropped(shadow):{key}")
                del table[key]
            for key, e in list(L["flows"].items()):
                if task in e["tasks"]:
                    ts = e["tasks"].pop(task)
                    if not e["tasks"]:
                        drop(L["flows"], key, e, "flow", ts)
            for key, e in list(L["ips"].items()):
                if task in e["tasks"]:
                    ts = e["tasks"].pop(task)
                    if len(e["tasks"]) < promote_tasks:        # its promotion no longer has two distinct tasks behind it
                        drop(L["ips"], key, e, "ip", ts)
            for ipk in list(L["watch"]):
                L["watch"][ipk].pop(task, None)
            L["targets"].pop(task, None)
    return undone


def make_release(fw, state_dir: Optional[str]) -> Callable[[str], List[str]]:
    from cora_sentinel.nftsets import NftSets
    sets = NftSets.from_firewall(fw)
    return lambda name: release_entries(name, state_dir, sets)


def summarize_decisions(lines: Iterable[str]) -> dict:
    """What shadow mode would have done, from decisions.jsonl: the data for the shadow-to-enforce call."""
    res: Dict[str, int] = {}
    reasons: Dict[str, int] = {}
    keys: Dict[str, dict] = {}
    n_dyn = n_isolate = 0
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("final") == "ISOLATE":
            n_isolate += 1
        r = d.get("dyn")
        if not r:
            continue
        n_dyn += 1
        res[r["result"]] = res.get(r["result"], 0) + 1
        if r["result"] == "skipped":
            reasons[r.get("reason", "?")] = reasons.get(r.get("reason", "?"), 0) + 1
        if "key" in r:
            k = keys.setdefault(r["key"], {"n": 0, "web": r.get("web"), "kind": r.get("kind"), "max_ttl_s": 0})
            k["n"] += 1
            k["max_ttl_s"] = max(k["max_ttl_s"], r.get("ttl_s", 0))
    top = sorted(keys.items(), key=lambda kv: -kv[1]["n"])
    return {"isolate_decisions": n_isolate, "with_dyn_record": n_dyn, "results": res, "skipped_reasons": reasons,
            "targets": len(keys), "web_targets": sum(1 for _, v in top if v["web"]), "top": top[:20]}


if __name__ == "__main__":
    sys.exit("run `cora-floor dyn` or `cora-floor dyn-report` instead")
