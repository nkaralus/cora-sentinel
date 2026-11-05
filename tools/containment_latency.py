#!/usr/bin/env python3
"""
containment_latency.py - how long from a task's FIRST PACKET to a listed address until its egress is actually cut?

A real task (started with cora-run, in its own cgroup) sends UDP to a listed address in a tight loop and measures how
long until its first EPERM, which is the moment netfilter really drops its egress. That is the number that matters, seen
from the task, with nothing in the system trusted to report it. It runs the full pipeline in this process: the tap, the
sentinel, the adjudicator with the model, the gates, and the nft write. Two modes are measured alternately:

    floor-first ON   (the default): a blocklist hit is isolated at once, before it queues behind the model
    floor-first OFF  (--no-contain-first): the task is isolated only after the model has answered

    sudo python3 tools/containment_latency.py                         # a fake model that takes 2.0 s
    sudo python3 tools/containment_latency.py --model-delay 3.5       # a different fake delay
    sudo python3 tools/containment_latency.py --model ~/models/q.gguf # YOUR real model (needs llama-cpp-python)
    sudo python3 tools/containment_latency.py --check                 # exit 1 if floor-first is not clearly faster

It needs root, a default route, and nft. It touches only a scratch nft table (coralat*), its own cgroup directory and a
documentation address (203.0.113.1, RFC 5737: nothing real is contacted, packets go to the default gateway at most),
and removes them on exit. The first trial of a real model is a throwaway warm-up, so model loading is not counted.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TARGET = "203.0.113.1"
GROUP = 98
PROBE = ("import socket, time\n"
         f"s = socket.socket(2, 2); t0 = time.monotonic()\n"
         "while time.monotonic() - t0 < 30:\n"
         "    try:\n"
         f"        s.sendto(b'x', ('{TARGET}', 9))\n"
         "    except PermissionError:\n"
         "        print(int((time.monotonic() - t0) * 1000), flush=True); time.sleep(30); break\n"
         "    time.sleep(0.001)\n"
         "else:\n"
         "    print(-1, flush=True)\n")


class FakeModel:
    def __init__(self, delay: float):
        self.delay = delay

    def judge(self, ev):
        time.sleep(self.delay)
        return json.dumps({"verdict": "ESCALATE", "confidence": 0.9, "reason": "fake"})


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p / 100.0 * (len(v) - 1))))]


def main() -> int:
    ap = argparse.ArgumentParser(description="time from a task's first packet to its egress being cut")
    ap.add_argument("--trials", type=int, default=8, help="trials per mode")
    ap.add_argument("--model", help="path to a GGUF model (default: a fake model)")
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--model-delay", type=float, default=2.0, help="seconds per event for the fake model")
    ap.add_argument("--check", action="store_true", help="exit 1 unless floor-first is clearly faster")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (it creates a scratch nft table and a cgroup)")
    if not shutil.which("nft"):
        sys.exit("nft not found")
    try:
        if not any(ln.split()[1] == "00000000" for ln in Path("/proc/net/route").read_text().splitlines()[1:]):
            raise OSError
    except OSError:
        sys.exit("no default route: a send would fail before it reaches netfilter, so there is nothing to measure")

    from cora_sentinel.blocklist import Blocklist
    from cora_sentinel.cgroup import CgroupRoot
    from cora_sentinel.daemon import Sentinel
    from cora_sentinel.firewall import Firewall
    from cora_sentinel.netmon import NetMonitor
    from cora_sentinel.nflog import TapService
    from cora_sentinel.verdict import Adjudicator, Executor

    mount = next((m for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified") if (Path(m) / "cgroup.controllers").exists()), None)
    if not mount:
        sys.exit("no cgroup v2 mount found")
    cg = CgroupRoot(f"{mount}/coralat-{os.getpid()}", mount)
    cg.ensure()
    fw = Firewall(cg, table=f"coralat{os.getpid()}")
    bl = Blocklist()
    bl.add_line(f"{TARGET}/32", "rogue")
    model = None
    if args.model:
        from cora_sentinel.verdict import Qwen3B
        model = Qwen3B(os.path.expanduser(args.model), n_threads=args.threads)
        print(f"model: {args.model} (real)")
    else:
        model = FakeModel(args.model_delay)
        print(f"model: fake, {args.model_delay:g} s per event")
    events, decisions = [], []
    s = Sentinel("UNUSED", ["/tmp"], spike_mb=10**6, window_s=5, emit=events.append, net_allow=["0.0.0.0/0"],
                 cgroups=cg, blocklist=bl, cooldown_s=0)
    tap = TapService(fw, GROUP, udp=True)
    nm = NetMonitor(s, interval=0.05, tap=tap)
    s.netmon_active = True
    adj = Adjudicator(s.net, model, Executor(True, cg, fw), None, 0.6, sink=decisions.append)
    s.emit = lambda p: (events.append(p), adj.submit(p))
    nm.start()
    adj.start()
    env = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": mount, "CORA_NFT_TABLE": fw.table,
           "CORA_NFLOG_GROUP": str(GROUP)}
    results = {True: {"task": [], "model": []}, False: {"task": [], "model": []}}
    bad = []

    def trial(first: bool, name: str):
        adj.contain_first = first
        n = len(decisions)
        p = subprocess.Popen([sys.executable, "-m", "cora_sentinel.run", name, sys.executable, "-c", PROBE],
                             env=env, stdout=subprocess.PIPE, text=True)
        try:
            lat = int(p.stdout.readline().strip() or -1)
            end = time.monotonic() + 120
            while len(decisions) <= n and time.monotonic() < end:     # the model's decision, which arrives later
                time.sleep(0.02)
            d = decisions[n] if len(decisions) > n else {}
        finally:
            p.kill()
            p.wait()
            try:
                (cg.root / name).rmdir()
            except OSError:
                pass
            fw.gc(set(cg.names()))
        return lat, d

    try:
        if args.model:
            print("warming the model up (not counted) ...")
            trial(True, "warm")
        print(f"{args.trials} trials per mode, alternating ...\n")
        for i in range(args.trials):
            for first in (True, False):
                lat, d = trial(first, f"t{int(first)}x{i}")
                if lat < 0:
                    bad.append(f"trial {i} floor-first={first}: the task was never cut off")
                    continue
                results[first]["task"].append(lat)
                results[first]["model"].append(d.get("model_ms", 0))
    finally:
        adj.stop()
        nm.stop()
        fw.purge()
        for n in list(cg.names()):
            try:
                (cg.root / n).rmdir()
            except OSError:
                pass
        try:
            cg.root.rmdir()
        except OSError:
            pass
        for base in ("/run/lock", tempfile.gettempdir()):
            try:
                os.unlink(f"{base}/cora-tap-{fw.table}.lock")
            except OSError:
                pass

    print(f"{'':24} {'p50':>9} {'p99':>9} {'min':>9} {'max':>9}   (ms from the task's first packet to its first EPERM)")
    for first, label in ((True, "floor-first ON"), (False, "floor-first OFF")):
        v = results[first]["task"]
        if v:
            print(f"{label:<24} {statistics.median(v):9.0f} {pct(v, 99):9.0f} {min(v):9d} {max(v):9d}")
    m = results[False]["model"]
    if m:
        print(f"{'model, per event':<24} {statistics.median(m):9.0f} {pct(m, 99):9.0f} {min(m):9d} {max(m):9d}")
    on, off = results[True]["task"], results[False]["task"]
    if on and off:
        ratio = statistics.median(off) / max(statistics.median(on), 1)
        print(f"\n-> with floor-first ON a task is cut off in a median of {statistics.median(on):.0f} ms; with it OFF, "
              f"{statistics.median(off):.0f} ms ({ratio:.0f}x slower: that is the model).")
        if args.check and not (pct(on, 99) < 250 and pct(on, 99) * 5 < statistics.median(off)):
            bad.append(f"floor-first p99 {pct(on, 99):.0f} ms is not clearly below the model path "
                       f"(median {statistics.median(off):.0f} ms)")
    elif args.check:
        bad.append("no complete trials")
    for b in bad:
        print(f"   !! {b}")
    return 1 if (bad and args.check) else 0


if __name__ == "__main__":
    sys.exit(main())
