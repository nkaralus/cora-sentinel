#!/usr/bin/env python3
"""
cora_exec_fidelity - the labeled eval for cora-exec: does the model write what the operator asked (intent fidelity),
and does what it writes pass the gates (legality)? Measured apart, because retries can buy legality with fidelity.

    python tools/cora_exec_fidelity.py [--model GGUF] [--cases tools/cora_exec_fidelity.json] [--out results.json]

Each case has a numeric ORACLE: the slots a faithful model would write (with an optional tolerance). The expected
legality is not hand-labelled: the oracle is assembled exactly like a model answer and run through the bridge.
  first-attempt fidelity   the model's first answer equals the oracle
  final fidelity           the answer that was finally accepted equals the oracle
  legality                 the request ended with a ticket (passed mule, policy, check_all, lifecycle)
  accepted_unfaithful      the oracle is legal, and the model's (legal) answer was accepted although it is not the
                           oracle: silent substitution, the gates cannot see it
  retry_drift              the first answer was the oracle, the gates refused it, and a retry was accepted: the
                           retries bought legality with intent
  held                     the oracle is illegal and the request was refused (the right outcome)
Runs the real cora_exec.Exec against the demo registry with the real model worker; nothing is staged.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cora_exec as X  # noqa: E402
from cora_exec_bridge import Bridge, demo_registry  # noqa: E402
from cora_model import DEFAULT_MODEL, ModelWorker  # noqa: E402
from cora_stage_harness import Result  # noqa: E402


class NoStage:
    """The three things Exec asks of a harness, without staging anything: every case starts from the same registry."""
    def __init__(self):
        self.reg = demo_registry()

    def live_registry(self):
        return self.reg

    def status(self):
        return {"parked": {}}

    def submit(self, ticket, intent=None):
        return Result(True, "EVAL_ACCEPTED", ticket.id, "EVAL")


class Recorder:
    def __init__(self, inner):
        self.inner, self.calls, self.replies = inner, 0, []

    def complete(self, *a, **k):
        self.calls += 1
        r = self.inner.complete(*a, **k)
        self.replies.append(r)
        return r


def close(slots, oracle, tol):
    return set(slots) == set(oracle) and all(abs(slots[k] - oracle[k]) <= tol for k in oracle)


def oracle_legal(ex: X.Exec, case) -> bool:
    reg = demo_registry()
    node, ref = reg.get(case["target"]), reg.get(case["ref"]) if case.get("ref") else None
    bounds = X.slots_to_bounds(case["op"], case["oracle"], node, ref, case.get("side"))
    block = ex._block(case["op"], node, bounds)
    return Bridge(reg).mint(json.dumps(block, separators=(",", ":")))[0].ok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cora_exec_fidelity.py")
    ap.add_argument("--model", default=str(DEFAULT_MODEL))
    ap.add_argument("--cases", default=str(Path(__file__).resolve().parent / "cora_exec_fidelity.json"))
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    cases = json.loads(Path(a.cases).read_text())["cases"]
    rows = []
    with ModelWorker(a.model) as worker:
        model = Recorder(worker)
        ex = X.Exec(NoStage(), model)
        for i, c in enumerate(cases, 1):
            legal = oracle_legal(ex, c)
            n0, t0 = model.calls, time.monotonic()
            out = ex.run(c["op"], c["target"], c["phrase"], c.get("ref"), c.get("side"))
            tol = c.get("tol", 0)
            first = out.attempts[0]["slots"] if out.attempts else None
            final = out.attempts[-1]["slots"] if out.ok and out.attempts else None
            row = {"n": i, "op": c["op"], "phrase": c["phrase"], "oracle": c["oracle"], "oracle_legal": legal,
                   "first": first, "final": final, "code": out.code, "ok": out.ok, "calls": model.calls - n0,
                   "attempt_codes": [x["code"] for x in out.attempts], "secs": round(time.monotonic() - t0, 2),
                   "first_faithful": bool(first and close(first, c["oracle"], tol)),
                   "final_faithful": bool(final and close(final, c["oracle"], tol))}
            row["accepted_unfaithful"] = out.ok and legal and not row["final_faithful"]
            row["retry_drift"] = out.ok and row["first_faithful"] and not row["final_faithful"]
            row["held"] = not legal and not out.ok
            rows.append(row)
            print(f"{i:2d} {c['op']:<5} oracle {json.dumps(c['oracle']):<38} legal={str(legal):<5} first {json.dumps(first):<38} "
                  f"-> {out.code:<20} calls={row['calls']} {'FAITHFUL' if row['first_faithful'] else 'miss'}"
                  f"{' ACCEPTED-UNFAITHFUL' if row['accepted_unfaithful'] else ''}{' RETRY-DRIFT' if row['retry_drift'] else ''}",
                  flush=True)
    toks = [r.get("completion_tokens", 0) for r in model.replies]
    n, nl = len(rows), sum(r["oracle_legal"] for r in rows)
    summary = {
        "cases": n, "oracle_legal": nl, "oracle_illegal": n - nl,
        "intent_fidelity_first_attempt": f"{sum(r['first_faithful'] for r in rows)}/{n}",
        "intent_fidelity_on_legal_oracles": f"{sum(r['first_faithful'] for r in rows if r['oracle_legal'])}/{nl}",
        "intent_fidelity_on_illegal_oracles": f"{sum(r['first_faithful'] for r in rows if not r['oracle_legal'])}/{n - nl}",
        "legality": f"{sum(r['ok'] for r in rows)}/{n}",
        "legal_and_faithful": f"{sum(r['ok'] and r['final_faithful'] for r in rows)}/{n}",
        "illegal_oracles_held": f"{sum(r['held'] for r in rows)}/{n - nl}",
        "accepted_unfaithful": [r["n"] for r in rows if r["accepted_unfaithful"]],
        "retry_drift": [r["n"] for r in rows if r["retry_drift"]],
        "illegal_oracle_accepted_anyway": [r["n"] for r in rows if not r["oracle_legal"] and r["ok"]],
        "model_calls": sum(r["calls"] for r in rows), "retries": sum(max(0, r["calls"] - 1) for r in rows),
        "median_secs_per_case": statistics.median(r["secs"] for r in rows),
        "completion_tokens_per_call": {"median": statistics.median(toks), "max": max(toks)} if toks else None,
        "codes": {k: sum(r["code"] == k for r in rows) for k in sorted({r["code"] for r in rows})},
    }
    print(json.dumps(summary, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
