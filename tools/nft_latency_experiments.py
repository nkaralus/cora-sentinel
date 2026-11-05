#!/usr/bin/env python3
"""
nft_latency_experiments.py - does cora-sentinel's tap-sync timing name KNOWN causes correctly on THIS machine?

When the sentinel logs "tap sync took N ms = lock wait A + nft B ... Suggests: ...", that verdict is a heuristic.
This tool earns (or withdraws) your trust in it. It produces each possible cause on purpose, with real nft, a real
flock and real load, runs the same instrumented sync, and shows what the tool says:

    idle     nothing wrong          -> expect: "not slow"
    lock     another process holds the tap lock         -> expect: "waiting for the cross-process tap lock"
    busy     the host is saturated (spinning processes) -> expect: "the whole host is slow"
    kernel   many tiny nft transactions queue on the kernel's commit mutex, with the CPU left free
                                                        -> expect: "points at nft or the kernel's transaction path"

Run it as root, ideally while the machine is otherwise quiet. It touches only scratch tables named coraexp*, its own
cgroup directory and files in a temp directory, and it removes them on exit (also on Ctrl-C).

    sudo python3 tools/nft_latency_experiments.py                    # all four
    sudo python3 tools/nft_latency_experiments.py idle lock --check  # exit 1 if a verdict is wrong

Read the numbers, not only the verdict: "lock" is time waiting for the cross-process tap lock, "nft" is time inside
nft subprocesses, "no-op child" is how long `true` took under the same conditions. On a single core, kernel work and
host load are the same resource, so the kernel scenario cannot be cleanly separated there; more cores separate them.
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.firewall import Firewall
from cora_sentinel.netmon import _fork_exec_ms, diagnose
from cora_sentinel.nflog import TapRules

EXPECT = {"idle": "not slow", "lock": "tap lock", "busy": "whole host is slow",
          "kernel": "points at nft or the kernel"}


class Lab:
    def __init__(self) -> None:
        mount = next((m for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified") if (Path(m) / "cgroup.controllers").exists()), None)
        if not mount:
            sys.exit("no cgroup v2 mount found")
        self.cg = CgroupRoot(f"{mount}/coraexp-{os.getpid()}", mount)
        self.cg.ensure()
        self.fw = Firewall(self.cg, table=f"coraexp{os.getpid()}")
        self.rules = TapRules(self.fw, 97, udp=True)
        self.rules.ensure_chain()
        self.n = 0
        self.base = {"ctl": float("inf"), "slow": float("inf")}   # fastest seen: the idle baseline, as a daemon learns it
        self.tmp = Path(tempfile.mkdtemp(prefix="coraexp-"))
        self.tables = [f"coraexpl{k}" for k in range(64)]

    def sync_once(self) -> dict:
        self.n += 1
        self.cg.create(f"t{self.n}")
        for old in range(1, self.n - 2):                 # keep a few tasks live; drop older (empty cgroups rmdir cleanly)
            try:
                (self.cg.root / f"t{old}").rmdir()
            except OSError:
                pass
        live = {n: os.stat(self.cg.root / n).st_ino for n in self.cg.names()}
        ctl = _fork_exec_ms()
        t = time.monotonic()
        self.rules.sync(live)
        total = (time.monotonic() - t) * 1000.0
        lt = self.rules.last_timing
        self.base["ctl"] = min(self.base["ctl"], ctl)
        self.base["slow"] = min(self.base["slow"], lt["nft_slowest_ms"])
        return {"total": total, "lock": lt["lock_ms"], "nft": lt["nft_ms"], "slow": lt["nft_slowest_ms"], "ctl": ctl}

    def run(self, label: str, n: int, gap: float = 0.25) -> tuple:
        rows = []
        for _ in range(n):
            rows.append(self.sync_once())
            time.sleep(gap)
        w = max(rows, key=lambda r: r["total"])
        verdict = diagnose(w["total"], w["lock"], w["nft"], w["slow"], w["ctl"], self.base["ctl"], self.base["slow"])
        print(f"{label:<44} p50 {statistics.median(r['total'] for r in rows):6.0f} ms   worst sync {w['total']:6.0f} ms = "
              f"lock {w['lock']:5.0f} + nft {w['nft']:5.0f} (slowest call {w['slow']:5.0f}); no-op child {w['ctl']:4.0f} ms")
        print(f"{'':<44} -> {verdict}\n")
        return w, verdict

    def with_lock_hog(self, fn):
        stop = threading.Event()

        def hog():
            while not stop.is_set():
                with self.rules._locked():
                    time.sleep(0.35)
                time.sleep(0.03)
        th = threading.Thread(target=hog, daemon=True)
        th.start()
        time.sleep(0.1)
        try:
            return fn()
        finally:
            stop.set()
            th.join()

    def with_procs(self, cmds, fn, warm: float):
        ps = [subprocess.Popen(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True) for c in cmds]
        time.sleep(warm)
        try:
            return fn()
        finally:
            for p in ps:
                try:
                    os.killpg(p.pid, signal.SIGKILL)       # its own process group: exact, never a pattern match
                except OSError:
                    pass
            for p in ps:
                p.wait()
            for t in self.tables:
                subprocess.run(["nft", "delete", "table", "inet", t], capture_output=True)

    def cleanup(self) -> None:
        try:
            self.fw.purge()
        except Exception:
            pass
        for n in list(self.cg.names()):
            try:
                (self.cg.root / n).rmdir()
            except OSError:
                pass
        try:
            self.cg.root.rmdir()
        except OSError:
            pass
        for base in ("/run/lock", tempfile.gettempdir()):
            try:
                os.unlink(f"{base}/cora-tap-{self.fw.table}.lock")
            except OSError:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="validate the tap-sync diagnosis against known causes")
    ap.add_argument("scenarios", nargs="*", choices=list(EXPECT), help="default: all four")
    ap.add_argument("--syncs", type=int, default=14, help="syncs per scenario")
    ap.add_argument("--spinners", type=int, default=None, help="busy processes (default 40 per core up to 80)")
    ap.add_argument("--loaders", type=int, default=16, help="nft transaction loaders")
    ap.add_argument("--check", action="store_true", help="exit 1 if a scenario that DID stall is named wrongly")
    args = ap.parse_args()
    args.scenarios = args.scenarios or list(EXPECT)
    if os.geteuid() != 0:
        sys.exit("run as root (it creates scratch nft tables and a cgroup)")
    if not shutil.which("nft"):
        sys.exit("nft not found")
    cores = os.cpu_count() or 1
    spinners = args.spinners or min(40 * cores, 80)
    print(f"cores: {cores}   load: {os.getloadavg()[0]:.2f}   (scratch table prefix coraexp; removed on exit)\n")
    lab = Lab()
    bad = []
    try:
        for _ in range(5):                              # seed the idle baseline, whatever was asked for
            lab.sync_once()
            time.sleep(0.1)
        for sc in args.scenarios:
            if sc == "idle":
                w, v = lab.run("idle (control)", args.syncs)
            elif sc == "lock":
                w, v = lab.with_lock_hog(lambda: lab.run("another process holds the tap lock", args.syncs))
            elif sc == "busy":
                w, v = lab.with_procs([[sys.executable, "-c", "while 1: pass"]] * spinners,
                                      lambda: lab.run(f"host busy ({spinners} spinning processes)", args.syncs), 1.5)
            else:
                for k in range(args.loaders):
                    (lab.tmp / f"tiny{k}.nft").write_text(f"add table inet coraexpl{k}\ndelete table inet coraexpl{k}\n")
                loaders = [["nice", "-n", "19", "sh", "-c", f"while :; do nft -f {lab.tmp}/tiny{k}.nft; done"]
                           for k in range(args.loaders)]
                w, v = lab.with_procs(loaders, lambda: lab.run(f"nft commit contention ({args.loaders} loaders, low CPU)",
                                                               args.syncs), 1.5)
            stalled = w["total"] >= 100
            if EXPECT[sc] not in v:
                if sc in ("busy", "kernel") and not stalled:
                    print(f"   (inconclusive: this load did not make the sync slow enough to explain; raise "
                          f"{'--spinners' if sc == 'busy' else '--loaders'})\n")
                else:
                    bad.append(sc)
                    print(f"   !! expected a verdict containing {EXPECT[sc]!r}\n")
    finally:
        lab.cleanup()
    if bad and args.check:
        print("verdict wrong for:", ", ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
