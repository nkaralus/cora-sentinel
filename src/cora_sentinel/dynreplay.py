#!/usr/bin/env python3
"""
cora_sentinel.dynreplay - rehearse the dynamic policy against what the daemon recorded. Stdlib only.

  cora-floor dyn-replay decisions.jsonl [--events events.jsonl] [policy flags]
  zcat -f decisions.jsonl* | cora-floor dyn-replay - --events events.jsonl.1 --events events.jsonl

The decision log has the verdict, the action, the time and what the live policy did; it does NOT have the destination
or the task. Those are in the event log, so the two are joined on event_id (rotated and .gz files are fine, and so is
`-` for stdin). Each recorded ISOLATE is fed back through the real `DynPolicy` with a clock that follows the recorded
timestamps, so TTLs expire, budgets refill and windows slide exactly as they did, in seconds instead of a week.

It never touches the live system: the policy runs on an in-memory ledger (never the one in --state-dir), and kernel mode
(below) runs in a private network namespace and a throwaway table.

WORLDS
  rehearse (default)  "What would enforce have done?" The adjudicator is assumed to be enforcing, so a dry-run ISOLATE
                      counts as done, and once a task is isolated its later events are dropped (an isolated task has no
                      egress, so a shadow log taken with a dry-running adjudicator contains events enforce would never
                      have seen). --keep-isolated keeps them.
  --as-recorded       No assumptions: the recorded actions, the policy in shadow. Here the policy flags below are NOT a
                      tweak: they tell the replay the settings the LIVE daemon ran with (--dyn-min-conf etc.).
  --check             --as-recorded, then compare every decision with the `dyn` record the live policy wrote. It should
                      match exactly given the live settings (first decisions after a rotation may not: the live ledger
                      had history before the log starts). Exit 1 on any mismatch. This is the proof that the harness
                      reproduces the daemon, and the test for drift after an upgrade.

TWEAKS  --min-conf --write-budget --max-live --task-cap --promote-tasks --flow-ttl --ip-ttl, and --allow/--protect for
        exemptions. With any of them the tool runs the shipped defaults (A) and your settings (B) over the same log and
        prints what changed. `--diff-recorded` compares the result with what shadow actually recorded.

KERNEL  By default, if root, nft and unshare are available, every write is also made in a private namespace (`unshare -n`)
        and a throwaway table, and the real nft state is cross-checked against the policy's ledger at the end. Kernel
        timeouts run in real time, so elements are removed at their SIMULATED expiry. --kernel off|on|auto.

EXIT  0 ok, 1 --check found a mismatch, 2 a self-check failed (a web port promoted, or the sets disagree with the ledger).
"""
from __future__ import annotations

import argparse
import collections
import copy
import gzip
import ipaddress
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from cora_sentinel import dynpolicy, floorguard
from cora_sentinel.dynpolicy import WEB_PORTS, DynConfig, DynPolicy
from cora_sentinel.firewall import FirewallError
from cora_sentinel.nftsets import MAX_TTL_S, NftSets

ACT = frozenset({"blocked", "refreshed", "promoted", "would_block", "would_refresh", "would_promote"})
THROTTLE = ("budget", "standing_cap", "task_cap")
NORM = {"would_block": "blocked", "would_refresh": "refreshed", "would_promote": "promoted"}
KERNEL_TABLE = "cora_replay"


# --------------------------------------------------------------------------
# reading the logs
# --------------------------------------------------------------------------
def _open(path: str):
    if path == "-":
        return sys.stdin
    return gzip.open(path, "rt") if str(path).endswith(".gz") else open(path)


def _json_lines(paths: Sequence[str], bad: List[int]) -> Iterator[dict]:
    for p in paths:
        with _open(p) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    bad[0] += 1
                    continue
                if isinstance(obj, dict):
                    yield obj


def parse_ts(s) -> float:
    d = datetime.fromisoformat(str(s))
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


@dataclass
class Rec:
    i: int
    ts: float
    ev: dict
    d: dict

    @property
    def task(self) -> str:
        s = self.ev.get("subject") or {}
        return str(s.get("cgroup") or s.get("name") or s.get("pid"))


def load(decision_paths: Sequence[str], event_paths: Sequence[str], since: Optional[float] = None,
         until: Optional[float] = None) -> Tuple[List[Rec], dict]:
    """Final-ISOLATE decisions joined with their events, in time order. Returns (records, what was skipped and why)."""
    bad = [0]
    decs: Dict[str, Tuple[float, int, dict]] = {}
    total = 0
    for n, d in enumerate(_json_lines(decision_paths, bad)):
        total += 1
        eid = d.get("event_id")
        if d.get("final") != "ISOLATE" or not eid or eid in decs:
            continue
        try:
            ts = parse_ts(d["ts"])
        except (KeyError, ValueError):
            bad[0] += 1
            continue
        if (since is not None and ts < since) or (until is not None and ts >= until):
            continue
        decs[eid] = (ts, n, d)
    evs: Dict[str, dict] = {}
    for ev in _json_lines(event_paths, bad):
        eid = ev.get("event_id")
        if eid in decs and eid not in evs:
            evs[eid] = ev
            if len(evs) == len(decs):
                break
    joined = sorted(((ts, n, eid) for eid, (ts, n, _) in decs.items() if eid in evs))
    recs = [Rec(i, ts, evs[eid], decs[eid][2]) for i, (ts, n, eid) in enumerate(joined)]
    return recs, {"decisions": total, "isolate": len(decs), "joined": len(recs),
                  "no_event": len(decs) - len(recs), "malformed": bad[0]}


# --------------------------------------------------------------------------
# the stand-ins: a clock, a set of "kernel" elements with SIMULATED lifetimes, and exemptions
# --------------------------------------------------------------------------
class Clock:
    def __init__(self, t: float = 0.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _pct(xs: Sequence[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p / 100))] if xs else 0.0


class ReplaySets:
    """Stands in for NftSets. Remembers every element with its simulated expiry (so the policy can be cross-checked), and,
    given a real NftSets, mirrors each write into it. A real element would outlive a fast replay or expire in real time,
    so it is written with the longest timeout and deleted when its SIMULATED time is up."""

    def __init__(self, clock: Clock, inner=None):
        self.clock, self.inner = clock, inner
        self.live: Dict[str, Tuple[float, tuple]] = {}
        self.writes, self.deletes, self.times = 0, 0, []

    def _timed(self, fn, *args):
        t0 = time.perf_counter()
        r = fn(*args)
        self.times.append((time.perf_counter() - t0) * 1000.0)
        return r

    def block_ip(self, ip: str, ttl_s: int) -> None:
        if self.inner is not None:
            self._timed(self.inner.block_ip, ip, MAX_TTL_S)
        self.live[f"i:{ip}"] = (self.clock.t + ttl_s, ("ip", ip))
        self.writes += 1

    def block_flow(self, ip: str, proto: str, port: int, ttl_s: int) -> None:
        if self.inner is not None:
            self._timed(self.inner.block_flow, ip, proto, port, MAX_TTL_S)
        self.live[f"f:{ip}|{proto}|{port}"] = (self.clock.t + ttl_s, ("flow", ip, proto, port))
        self.writes += 1

    def sweep(self, now: float) -> None:
        for k in [k for k, (exp, _) in self.live.items() if exp <= now]:
            _, what = self.live.pop(k)
            if self.inner is not None:
                (self.inner.unblock_ip if what[0] == "ip" else self.inner.unblock_flow)(*what[1:])
                self.deletes += 1

    def active(self, now: float) -> set:
        return {k for k, (exp, _) in self.live.items() if exp > now}

    def kernel_active(self) -> set:
        return ({f"f:{k}" for k in self.inner.live_flows()} | {f"i:{k}" for k in self.inner.live_ips()}) if self.inner else set()


class ReplayExempt:
    """The live allow/protect state is not recoverable, so: honour what the live policy recorded for THAT decision
    (a skip with reason allowed:/protected:), plus any --allow / --protect given now."""

    def __init__(self, allow: Sequence[str] = (), protect: Sequence[str] = ()):
        self.idx = floorguard.net_index(list(allow))
        self.protect = {str(ipaddress.ip_address(p)) for p in protect}
        self.recorded: Optional[str] = None

    def __call__(self, ip: str) -> Optional[str]:
        if self.recorded:
            return self.recorded
        if ip in self.protect:
            return "protected:replay"
        hit = floorguard.covering(ip, self.idx)
        return f"allowed:{hit}" if hit else None


def _recorded_exempt(r: Rec) -> Optional[str]:
    rd = r.d.get("dyn") or {}
    reason = str(rd.get("reason", ""))
    return reason if rd.get("result") == "skipped" and reason.startswith(("allowed:", "protected:")) else None


# --------------------------------------------------------------------------
# one world
# --------------------------------------------------------------------------
@dataclass
class World:
    name: str
    cfg: DynConfig
    assume_enforcing: bool = True
    drop_isolated: bool = True


def run_world(recs: Sequence[Rec], w: World, allow: Sequence[str] = (), protect: Sequence[str] = (), inner=None) -> dict:
    clock = Clock(recs[0].ts if recs else 0.0)
    sets = ReplaySets(clock, inner) if w.assume_enforcing else None
    exempt = ReplayExempt(allow, protect)
    eff = "enforce" if w.assume_enforcing else "shadow"
    pol = DynPolicy(eff, sets=sets, exempt=exempt, state_dir=None, cfg=w.cfg, clock=clock, log=lambda m: None)
    isolated: Dict[str, float] = {}
    out: List[dict] = []
    track = {"live": [], "tokens": [], "task_targets": {}}
    for r in recs:
        clock.t = r.ts
        if sets is not None:
            sets.sweep(r.ts)
        d = {k: v for k, v in r.d.items() if k != "dyn"}
        act = str(d.get("action", ""))
        if w.assume_enforcing and act.startswith("dry-run:"):
            d["action"] = "done:" + act[len("dry-run:"):]
        oc = {"i": r.i, "ts": r.ts, "event_id": r.d.get("event_id"), "task": r.task}
        rd = r.d.get("dyn")
        oc["recorded"] = ({"result": NORM.get(rd["result"], rd["result"]), "key": rd.get("key"), "ttl_s": rd.get("ttl_s"),
                           "reason": rd.get("reason")} if rd else None)
        if w.drop_isolated and r.task in isolated:
            oc.update(result="suppressed", reason="task already isolated")
            out.append(oc)
            continue
        exempt.recorded = _recorded_exempt(r)
        try:
            rec = pol.consider(copy.deepcopy(r.ev), d)
        except Exception as e:                                     # a policy bug must show up, not kill the replay
            rec = {"result": "error", "error": f"{e.__class__.__name__}: {e}"}
        if str(d.get("action", "")).startswith(("done:", "dry-run:")):
            isolated[r.task] = r.ts
        if rec is None:
            oc.update(result="not_model", reason="isolated by the floor, not the model")
        else:
            oc.update({k: rec[k] for k in ("result", "reason", "kind", "key", "ttl_s", "offense", "web", "port", "proto",
                                           "tasks", "error") if k in rec})
            if "port" in oc:                  # classified here, by port, NOT from the policy's own flag: the self-check
                oc["web"] = oc["port"] in WEB_PORTS      # "no web port is ever promoted" must not trust the code it checks
        out.append(oc)
        L = pol._ledger(eff).read()
        track["live"].append((r.ts, DynPolicy._live(L, clock.t)))
        if "bucket" in L:
            track["tokens"].append(L["bucket"]["tokens"])
        n = len({k for t, k in L["targets"].get(r.task, []) if t > clock.t - dynpolicy.WINDOW_S})
        if n > track["task_targets"].get(r.task, 0):
            track["task_targets"][r.task] = n
    consistent = None
    if sets is not None and recs:
        sets.sweep(clock.t)
        L = pol._ledger(eff).read()
        ledger = ({f"f:{k}" for k, e in L["flows"].items() if e["expires"] > clock.t}
                  | {f"i:{k}" for k, e in L["ips"].items() if e["expires"] > clock.t})
        consistent = {"ledger_vs_sets": ledger == sets.active(clock.t)}
        if inner is not None:
            consistent["kernel_vs_sets"] = sets.kernel_active() == sets.active(clock.t)
    return {"world": w, "outcomes": out, "track": track, "sets": sets, "consistent": consistent, "cfg": w.cfg}


# --------------------------------------------------------------------------
# summaries
# --------------------------------------------------------------------------
def _blocked_seconds(outcomes: Sequence[dict]) -> Dict[str, dict]:
    """Per target: how long it would have been blocked (a refresh replaces the expiry, so segments never overlap)."""
    per: Dict[str, dict] = {}
    cur: Dict[str, Tuple[float, float]] = {}
    for o in outcomes:
        if o["result"] not in ACT:
            continue
        k = o["key"]
        e = per.setdefault(k, {"key": k, "kind": o["kind"], "web": o["web"], "tasks": set(), "n": 0, "offenses": 0,
                               "max_ttl_s": 0, "seconds": 0.0, "first": o["ts"]})
        e["tasks"].add(o["task"])
        e["n"] += 1
        e["offenses"] = max(e["offenses"], o.get("offense", 0))
        e["max_ttl_s"] = max(e["max_ttl_s"], o["ttl_s"])
        if k in cur:
            start, until = cur[k]
            e["seconds"] += (min(until, o["ts"]) - start)
        cur[k] = (o["ts"], o["ts"] + o["ttl_s"])
    for k, (start, until) in cur.items():
        per[k]["seconds"] += until - start
    return per


def summarize(res: dict, top: int = 10) -> dict:
    w: World = res["world"]
    out = res["outcomes"]
    cfg = w.cfg
    results = collections.Counter(o["result"] for o in out)
    skipped = collections.Counter(o.get("reason", "?").split(":")[0] for o in out if o["result"] == "skipped")
    throttle_by_task: collections.Counter = collections.Counter(
        o["task"] for o in out if o["result"] == "skipped" and o.get("reason") == "task_cap")
    # writes per minute, peak
    win: collections.deque = collections.deque()
    peak_w, peak_w_at = 0, None
    for o in out:
        if o["result"] in ACT:
            win.append(o["ts"])
            while win and win[0] <= o["ts"] - 60:
                win.popleft()
            if len(win) > peak_w:
                peak_w, peak_w_at = len(win), o["ts"]
    live = res["track"]["live"]
    peak_live, peak_live_at = max(((n, t) for t, n in live), default=(0, None))
    tt = res["track"]["task_targets"]
    max_task, max_task_n = max(tt.items(), key=lambda kv: kv[1], default=(None, 0))
    per = _blocked_seconds(out)
    rows = sorted(per.values(), key=lambda e: -e["seconds"])
    fmt = lambda e: {"key": e["key"], "kind": e["kind"], "web": e["web"], "tasks": len(e["tasks"]), "hits": e["n"],  # noqa: E731
                     "offenses": e["offenses"], "max_ttl_s": e["max_ttl_s"], "blocked_s": round(e["seconds"])}
    web_rows = [e for e in rows if e["web"]]
    web_promotions = [o for o in out if o.get("web") and o["result"] in ("promoted", "would_promote")]
    web_covered = sum(1 for o in out if o.get("web") and o["result"] in ACT | {"dedupe"} and o.get("kind") == "ip")
    hours: Dict[int, dict] = {}
    for o in out:
        h = hours.setdefault(int(o["ts"] // 3600), {"hour": int(o["ts"] // 3600) * 3600, "new": 0, "refresh": 0,
                                                    "promote": 0, "skipped": 0, "dedupe": 0, "suppressed": 0})
        h[{"blocked": "new", "would_block": "new", "refreshed": "refresh", "would_refresh": "refresh",
           "promoted": "promote", "would_promote": "promote", "skipped": "skipped", "dedupe": "dedupe",
           "suppressed": "suppressed"}.get(o["result"], "skipped")] += 1
    for t, n in live:
        if int(t // 3600) in hours:
            hours[int(t // 3600)]["peak_live"] = max(hours[int(t // 3600)].get("peak_live", 0), n)
    return {
        "world": w.name, "assume_enforcing": w.assume_enforcing, "replayed": len(out),
        "span": ({"first": out[0]["ts"], "last": out[-1]["ts"]} if out else None),
        "results": dict(results), "skipped_reasons": dict(skipped),
        "throttled": {"total": sum(results_for(out, r) for r in THROTTLE),
                      **{r: results_for(out, r) for r in THROTTLE}, "task_cap_by_task": dict(throttle_by_task.most_common(5))},
        "limits": {"write_per_min": {"limit": cfg.write_per_min, "peak": peak_w, "at": peak_w_at},
                   "live": {"limit": cfg.max_live, "peak": peak_live, "at": peak_live_at},
                   "task_targets_per_hour": {"limit": cfg.task_cap, "max": max_task_n, "task": max_task},
                   "bucket_min_tokens": (round(min(res["track"]["tokens"]), 2) if res["track"]["tokens"] else None)},
        "web": {"ports": sorted(WEB_PORTS), "targets": len(web_rows),
                "blocks": sum(1 for o in out if o.get("web") and o["result"] in ("blocked", "would_block")),
                "refreshes": sum(1 for o in out if o.get("web") and o["result"] in ("refreshed", "would_refresh")),
                "promotions": len(web_promotions), "covered_by_whole_address": web_covered,
                "top": [fmt(e) for e in web_rows[:top]]},
        "targets": {"n": len(rows), "top": [fmt(e) for e in rows[:top]],
                    "blocked_seconds_total": round(sum(e["seconds"] for e in rows))},
        "timeline": [hours[h] for h in sorted(hours)],
        "consistent": res["consistent"],
    }


def results_for(out: Sequence[dict], reason: str) -> int:
    return sum(1 for o in out if o["result"] == "skipped" and o.get("reason") == reason)


def diff_worlds(a: dict, b: dict, limit: int = 15) -> dict:
    sig = lambda o: (o["result"], o.get("key"), o.get("ttl_s"))              # noqa: E731
    changed = [{"i": x["i"], "ts": x["ts"], "task": x["task"], "a": {k: x.get(k) for k in ("result", "reason", "key", "ttl_s")},
                "b": {k: y.get(k) for k in ("result", "reason", "key", "ttl_s")}}
               for x, y in zip(a["outcomes"], b["outcomes"]) if sig(x) != sig(y)]
    sa, sb = summarize(a), summarize(b)
    num = lambda s, k: sum(v for r, v in s["results"].items() if r in k)      # noqa: E731
    return {"changed": len(changed), "of": len(a["outcomes"]), "first": changed[:limit],
            "delta": {"blocks": num(sb, ACT) - num(sa, ACT), "targets": sb["targets"]["n"] - sa["targets"]["n"],
                      "web_targets": sb["web"]["targets"] - sa["web"]["targets"],
                      "throttled": sb["throttled"]["total"] - sa["throttled"]["total"],
                      "blocked_seconds": sb["targets"]["blocked_seconds_total"] - sa["targets"]["blocked_seconds_total"]}}


def compare_recorded(res: dict, limit: int = 15) -> dict:
    """Replay vs what the live policy recorded, decision by decision (results compared without the would_ prefix)."""
    n = same = no_record = 0
    bad: List[dict] = []
    for o in res["outcomes"]:
        rec = o["recorded"]
        if rec is None:
            no_record += 1
            continue
        n += 1
        ok = (NORM.get(o["result"], o["result"]) == rec["result"]
              and (rec.get("key") is None or o.get("key") == rec["key"])
              and (rec.get("ttl_s") is None or o.get("ttl_s") == rec["ttl_s"]))
        if ok:
            same += 1
        else:
            bad.append({"i": o["i"], "ts": o["ts"], "task": o["task"], "recorded": rec,
                        "replay": {k: o.get(k) for k in ("result", "reason", "key", "ttl_s")}})
    return {"compared": n, "match": same, "mismatch": len(bad), "no_record": no_record, "first": bad[:limit]}


# --------------------------------------------------------------------------
# printing
# --------------------------------------------------------------------------
def _iso(t: Optional[float]) -> str:
    return "-" if t is None else datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _dur(s: float) -> str:
    return f"{s / 86400:.1f} d" if s >= 2 * 86400 else f"{s / 3600:.1f} h" if s >= 3600 else f"{s / 60:.0f} min" if s >= 60 else f"{s:.0f} s"


def render(inputs: dict, kernel: Optional[dict], s: dict, title: str) -> str:
    L: List[str] = []
    p = L.append
    sp = s["span"]
    p(f"== {title}")
    p(f"replayed {s['replayed']} of {inputs['joined']} joined ISOLATE decisions"
      + (f", {_iso(sp['first'])} to {_iso(sp['last'])} ({_dur(sp['last'] - sp['first'])})" if sp else ""))
    p(f"world: {s['world']}")
    r = s["results"]
    p("results   " + (", ".join(f"{k} {v}" for k, v in sorted(r.items(), key=lambda kv: -kv[1])) or "none"))
    if s["skipped_reasons"]:
        p("skipped   " + ", ".join(f"{k} {v}" for k, v in sorted(s["skipped_reasons"].items(), key=lambda kv: -kv[1])))
    lim = s["limits"]
    th = s["throttled"]
    p("limits")
    p(f"  write budget  {lim['write_per_min']['limit']}/min   peak {lim['write_per_min']['peak']}/min"
      + (f" at {_iso(lim['write_per_min']['at'])}" if lim['write_per_min']['at'] else "") + f"   denied {th['budget']}"
      + (f"   lowest bucket {lim['bucket_min_tokens']} tokens" if lim["bucket_min_tokens"] is not None else ""))
    p(f"  live elements {lim['live']['limit']}   peak {lim['live']['peak']}"
      + (f" at {_iso(lim['live']['at'])}" if lim['live']['at'] else "") + f"   denied {th['standing_cap']}")
    p(f"  per-task cap  {lim['task_targets_per_hour']['limit']}/h   max by one task {lim['task_targets_per_hour']['max']}"
      + (f" ({lim['task_targets_per_hour']['task']})" if lim['task_targets_per_hour']['task'] else "") + f"   denied {th['task_cap']}"
      + (f"   {th['task_cap_by_task']}" if th["task_cap_by_task"] else ""))
    w = s["web"]
    p(f"web ports {'/'.join(map(str, w['ports']))}")
    p(f"  flow blocks {w['blocks']}   repeat-offense refreshes {w['refreshes']}   distinct targets {w['targets']}")
    p(f"  promoted to a whole address: {w['promotions']}" + ("" if not w['promotions'] else "   <<< MUST BE 0: THE POLICY IS BROKEN"))
    if w["covered_by_whole_address"]:
        p(f"  web hits covered by a whole-address block that other ports caused: {w['covered_by_whole_address']}")
    for e in w["top"][:5]:
        p(f"    {e['key']:<44} blocked {_dur(e['blocked_s']):>8}  offenses {e['offenses']}  tasks {e['tasks']}")
    t = s["targets"]
    p(f"targets {t['n']}  total blocked time {_dur(t['blocked_seconds_total'])}")
    for e in t["top"]:
        p(f"  {'web' if e['web'] else '   '} {e['kind']:<4} {e['key']:<44} blocked {_dur(e['blocked_s']):>8}  max ttl {_dur(e['max_ttl_s']):>7}  "
          f"offenses {e['offenses']}  tasks {e['tasks']}")
    if s["consistent"] is not None:
        c = s["consistent"]
        p("self-check  ledger vs simulated sets: " + ("agree" if c["ledger_vs_sets"] else "DISAGREE")
          + ("" if "kernel_vs_sets" not in c else "   real nft vs simulated sets: " + ("agree" if c["kernel_vs_sets"] else "DISAGREE")))
    if kernel:
        p(f"kernel     private netns, table {KERNEL_TABLE}: {kernel['writes']} writes accepted"
          + (f" (p50 {kernel['p50_ms']:.2f} ms, p99 {kernel['p99_ms']:.2f} ms)" if kernel["writes"] else "")
          + f", {kernel['deletes']} simulated expiries removed")
    return "\n".join(L)


def render_timeline(s: dict) -> str:
    L = ["timeline (hour, UTC)     new refresh promote dedupe skipped suppressed peak_live"]
    for h in s["timeline"]:
        L.append(f"  {_iso(h['hour'])[:13]}:00   {h['new']:>5} {h['refresh']:>7} {h['promote']:>7} {h['dedupe']:>6} {h['skipped']:>7} "
                 f"{h['suppressed']:>10} {h.get('peak_live', 0):>9}")
    return "\n".join(L)


def render_diff(d: dict, a_name: str, b_name: str) -> str:
    de = d["delta"]
    L = [f"== {b_name} vs {a_name}", f"changed decisions {d['changed']} of {d['of']}",
         f"  blocks {de['blocks']:+d}   targets {de['targets']:+d}   web targets {de['web_targets']:+d}   throttled {de['throttled']:+d}   "
         f"blocked time {'+' if de['blocked_seconds'] >= 0 else '-'}{_dur(abs(de['blocked_seconds']))}"]
    for c in d["first"]:
        a, b = c["a"], c["b"]
        L.append(f"  #{c['i']} {_iso(c['ts'])} {c['task']}: {a['result']}{'/' + a['reason'] if a.get('reason') else ''} -> "
                 f"{b['result']}{'/' + b['reason'] if b.get('reason') else ''}" + (f"  {b['key']} ttl {b['ttl_s']}" if b.get("key") else ""))
    if d["changed"] > len(d["first"]):
        L.append(f"  ... {d['changed'] - len(d['first'])} more (--changes N)")
    return "\n".join(L)


def render_check(c: dict, label: str) -> str:
    L = [f"== {label}: replay vs what the live policy recorded",
         f"compared {c['compared']}   match {c['match']}   mismatch {c['mismatch']}   (no live record: {c['no_record']})"]
    for m in c["first"]:
        r, p = m["recorded"], m["replay"]
        L.append(f"  #{m['i']} {_iso(m['ts'])} {m['task']}: recorded {r['result']}{'/' + r['reason'] if r.get('reason') else ''}"
                 f" {r.get('key') or ''} ttl {r.get('ttl_s')}  |  replay {p['result']}{'/' + p['reason'] if p.get('reason') else ''}"
                 f" {p.get('key') or ''} ttl {p.get('ttl_s')}")
    return "\n".join(L)


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------
def can_kernel() -> bool:
    return os.geteuid() == 0 and bool(shutil.which("nft")) and bool(shutil.which("unshare"))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cora-floor dyn-replay", description=__doc__.split("\n\n")[0],
                                 epilog="Read the module docstring (or docs/dyn-policy.md) for the worlds, tweaks and exit codes.")
    ap.add_argument("decisions", nargs="+", help="decisions.jsonl (rotated and .gz files fine; '-' = stdin)")
    ap.add_argument("--events", action="append", metavar="FILE",
                    help="events.jsonl (repeatable; default: events.jsonl next to the decision log)")
    ap.add_argument("--since", metavar="ISO", help="only decisions at or after this time (UTC if no offset)")
    ap.add_argument("--until", metavar="ISO", help="only decisions before this time")
    g = ap.add_argument_group("policy settings (rehearsing: a tweak, run as B against the defaults as A; "
                              "with --as-recorded/--check: the live daemon's settings)")
    g.add_argument("--min-conf", type=float), g.add_argument("--write-budget", type=int, metavar="PER_MIN")
    g.add_argument("--max-live", type=int), g.add_argument("--task-cap", type=int), g.add_argument("--promote-tasks", type=int)
    g.add_argument("--flow-ttl", type=int, metavar="SEC"), g.add_argument("--ip-ttl", type=int, metavar="SEC")
    g.add_argument("--allow", action="append", default=[], metavar="CIDR", help="never block these (exemption)")
    g.add_argument("--protect", action="append", default=[], metavar="ADDR", help="never block this address")
    w = ap.add_argument_group("world")
    w.add_argument("--as-recorded", action="store_true", help="no assumptions: recorded actions, policy in shadow")
    w.add_argument("--check", action="store_true", help="--as-recorded, then verify it reproduces the live dyn records (exit 1 if not)")
    w.add_argument("--keep-isolated", action="store_true", help="keep later events of an already-isolated task")
    w.add_argument("--diff-recorded", action="store_true", help="also compare the result with what shadow recorded")
    ap.add_argument("--kernel", choices=("auto", "on", "off"), default="auto",
                    help="mirror writes into a private namespace and cross-check (auto: if root, nft and unshare)")
    ap.add_argument("--json", action="store_true"), ap.add_argument("--outcomes", action="store_true", help="with --json: every decision")
    ap.add_argument("--top", type=int, default=10), ap.add_argument("--changes", type=int, default=15)
    ap.add_argument("--timeline", action="store_true")
    ap.add_argument("--in-ns", action="store_true", help=argparse.SUPPRESS)
    return ap


_TWEAKS = {"min_conf": "min_conf", "write_budget": "write_per_min", "max_live": "max_live", "task_cap": "task_cap",
           "promote_tasks": "promote_tasks", "flow_ttl": "flow_base_s", "ip_ttl": "ip_base_s"}


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    a = build_parser().parse_args(argv)
    if a.check:
        a.as_recorded = True
    tweaks = {cfg: getattr(a, arg) for arg, cfg in _TWEAKS.items() if getattr(a, arg) is not None}
    events = a.events
    if not events:
        first = next((p for p in a.decisions if p != "-"), None)
        guess = os.path.join(os.path.dirname(os.path.abspath(first)), "events.jsonl") if first else None
        if not guess or not os.path.exists(guess):
            print("error: the decision log has no destination or task; give the event log with --events FILE "
                  "(the daemon's --out, /var/log/cora-sentinel/events.jsonl)", file=sys.stderr)
            return 2
        events = [guess]
    kernel_wanted = (a.kernel == "on" or (a.kernel == "auto" and can_kernel())) and not a.as_recorded
    if a.kernel == "on" and not can_kernel():
        print("error: --kernel on needs root, nft and unshare", file=sys.stderr)
        return 2
    if kernel_wanted and not a.in_ns:
        os.execvp("unshare", ["unshare", "-n", sys.executable, "-m", "cora_sentinel.dynreplay", "--in-ns", *argv])
    try:
        since = parse_ts(a.since) if a.since else None
        until = parse_ts(a.until) if a.until else None
        recs, inputs = load(a.decisions, events, since, until)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    inner = None
    if kernel_wanted:
        inner = NftSets(table=KERNEL_TABLE)
        try:
            inner.ensure()
        except FirewallError as e:
            print(f"error: cannot prepare the private table: {e}", file=sys.stderr)
            return 2
    if not recs:
        msg = (f"nothing to replay: {inputs['decisions']} decisions, {inputs['isolate']} final ISOLATE, "
               f"{inputs['no_event']} without a matching event")
        print(json.dumps({"inputs": inputs, "worlds": {}}) if a.json else msg)
        return 0

    base_cfg = DynConfig()
    # rehearsing: the flags are a tweak (B) against the shipped defaults (A). Verifying (--as-recorded/--check): there is one
    # world and the flags tell it the settings the LIVE daemon ran with, so it can be compared with what that daemon recorded
    has_b = bool(tweaks or a.allow or a.protect) and not a.as_recorded
    drop = not a.keep_isolated and not a.as_recorded
    name = ("as-recorded (recorded actions, policy in shadow)" if a.as_recorded else
            "rehearse-enforce (adjudicator assumed enforcing" + ("; later events of an isolated task dropped)" if drop else ")"))
    runs: Dict[str, dict] = {}
    live_cfg = replace(base_cfg, **tweaks) if a.as_recorded else base_cfg
    runs["A"] = run_world(recs, World("A", live_cfg, not a.as_recorded, drop),
                          a.allow if a.as_recorded else [], a.protect if a.as_recorded else [],
                          inner=None if has_b else inner)
    if has_b:
        runs["B"] = run_world(recs, World("B", replace(base_cfg, **tweaks), True, drop), a.allow, a.protect, inner=inner)
    main_run = runs.get("B", runs["A"])
    sums = {k: summarize(v, a.top) for k, v in runs.items()}
    for k, sm in sums.items():
        sm["world"] = name + (" - shipped defaults" if k == "A" and has_b else " - your settings" if k == "B" else "")
    kernel = None
    sets = main_run["sets"]
    if inner is not None and sets is not None:
        kernel = {"writes": sets.writes, "deletes": sets.deletes, "p50_ms": _pct(sets.times, 50), "p99_ms": _pct(sets.times, 99)}
    diff = diff_worlds(runs["A"], runs["B"], a.changes) if "B" in runs else None
    check = compare_recorded(main_run, a.changes) if (a.check or a.diff_recorded) else None

    problems: List[str] = []
    for k, s in sums.items():
        if s["web"]["promotions"]:
            problems.append(f"world {k}: a web port was promoted to a whole-address block")
        c = s["consistent"]
        if c and not all(c.values()):
            problems.append(f"world {k}: the simulated/real sets disagree with the ledger ({c})")
    if a.json:
        doc = {"inputs": inputs, "kernel": kernel, "worlds": {k: {"summary": s} for k, s in sums.items()}, "diff": diff,
               "check": check, "problems": problems}
        if a.outcomes:
            for k, v in runs.items():
                doc["worlds"][k]["outcomes"] = v["outcomes"]
        print(json.dumps(doc, indent=1, default=str))
    else:
        print(f"inputs: {inputs['decisions']} decisions, {inputs['isolate']} final ISOLATE, {inputs['joined']} joined with an event"
              + (f", {inputs['no_event']} had no matching event (ignored)" if inputs["no_event"] else "")
              + (f", {inputs['malformed']} malformed lines skipped" if inputs["malformed"] else "")
              + ("" if kernel else "   kernel: not used (simulation only)"))
        for k, s in sums.items():
            print()
            print(render(inputs, kernel if k == ("B" if "B" in runs else "A") else None, s, f"world {k}" if "B" in runs else "replay"))
            if a.timeline:
                print(render_timeline(s))
        if diff:
            print()
            print(render_diff(diff, "A", "B"))
        if check:
            print()
            print(render_check(check, "check" if a.check else "diff-recorded"))
        for pb in problems:
            print(f"SELF-CHECK FAILED: {pb}", file=sys.stderr)
    if problems:
        return 2
    if a.check and check and check["mismatch"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
