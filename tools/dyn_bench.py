#!/usr/bin/env python3
"""
dyn_bench - what the dynamic policy costs per decision.

  shadow   consider() with the ledger only (flock + JSON read/modify/write); the kernel is not touched.
  enforce  the same plus ONE nft commit for the element. Runs inside a throwaway network namespace (`unshare -n`) in a
           throwaway table, so the host ruleset is never touched. Needs root, nft and unshare; skipped without them.

Each row is measured on an empty ledger and on one already holding --entries live elements (the ledger is rewritten on
every decision, so this is the number that grows). Decisions arrive at the model's pace (seconds apart), so these are
costs, not throughput limits; the point is that they stay small next to a 2-4 s model call.

  python tools/dyn_bench.py [--n 200] [--entries 500]
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

from cora_sentinel.dynpolicy import DynConfig, DynPolicy


def event(i, port=8080):
    ip = f"45.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
    return ({"anomaly": {"kind": "unauthorized_connection", "evidence": {
        "remote_ip": ip, "remote_port": port, "local_port": 40000, "dest_class": "public"}},
             "subject": {"cgroup": f"task{i}", "name": "n", "pid": 1}},
            {"final": "ISOLATE", "action": "done:ISOLATE@cgroup:x", "model": {"verdict": "ISOLATE", "confidence": 0.95}})


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p / 100))]


def run(mode, sets, n, entries):
    d = tempfile.mkdtemp(prefix="dynbench")
    try:
        pol = DynPolicy(mode, sets=sets, state_dir=d, log=lambda m: None,
                        cfg=DynConfig(write_per_min=10 ** 7, task_cap=10 ** 7, max_live=10 ** 7))
        for i in range(entries):
            pol.consider(*event(i))
        ms = []
        for i in range(entries, entries + n):
            ev, dec = event(i)
            t = time.perf_counter()
            r = pol.consider(ev, dec)
            ms.append((time.perf_counter() - t) * 1000.0)
            assert r["result"] in ("blocked", "would_block"), r
        return ms
    finally:
        shutil.rmtree(d, ignore_errors=True)


def row(label, ms):
    print(f"{label:<34} p50 {pct(ms, 50):7.2f}   p99 {pct(ms, 99):7.2f}   max {max(ms):7.2f}   (ms, n={len(ms)})", flush=True)


def inner(a):
    from cora_sentinel.nftsets import NftSets
    sets = NftSets(table="cora_bench")
    sets.ensure()
    for e in (0, a.entries):
        row(f"enforce, ledger of {e}", run("enforce", sets, a.n, e))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--entries", type=int, default=500)
    ap.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.inner:
        return inner(a)
    for e in (0, a.entries):
        row(f"shadow, ledger of {e}", run("shadow", None, a.n, e))
    if os.geteuid() == 0 and shutil.which("nft") and shutil.which("unshare"):
        r = subprocess.run(["unshare", "-n", sys.executable, os.path.abspath(__file__), "--inner",
                            "--n", str(a.n), "--entries", str(a.entries)])
        return r.returncode
    print("enforce rows skipped: needs root, nft and unshare")


if __name__ == "__main__":
    sys.exit(main())
