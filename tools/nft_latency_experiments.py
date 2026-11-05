#!/usr/bin/env python3
"""
nft_latency_experiments.py - does cora-sentinel's tap-sync timing name KNOWN causes correctly on THIS machine?

When the sentinel logs "tap sync took N ms = lock wait A + nft B ... Suggests: ...", that verdict is a heuristic.
This tool earns (or withdraws) your trust in it. It produces each possible cause on purpose, with real nft, a real
flock and real load, runs the same instrumented sync, and shows what the tool says:

    idle     nothing wrong          -> expect: "not slow"
    lock     another process holds the tap lock         -> expect: "waiting for the cross-process tap lock"
    busy     the host is saturated (spinning processes) -> expect: "the whole host is slow" (fork slows too, typical
             of few cores) OR "the CPUs were oversubscribed" (typical of MANY cores: nft's commit slows while a fork
             does not, because the kernel threads a transaction waits on compete with the load)
    kernel   many tiny nft transactions queue on the kernel's commit mutex, with the CPU left free
                                                        -> expect: "the CPUs were NOT oversubscribed ... commit
             contention". If the loaders themselves oversubscribe the CPUs (few cores) the result is "inconclusive".
    dump     reading the tap chain two ways as live tasks accumulate: the `nft` command, whose listing resolves each
             rule's cgroup id to a path by walking the cgroup tree (cost: rules x cgroups visited, so QUADRATIC in live
             tasks, plus whatever other cgroups the walk passes first), and a netlink read (cost: O(rules)).
             -> expect: both give the SAME rules, and netlink is far faster wherever nft is slow.
    writes   the nft COMMITS (`-f -`) each write operation performs, and its time, as live tasks accumulate:
             cora-run's install, the sentinel's sync, an ISOLATE, and gc of several dead tasks.
             -> expect: ONE commit each. The ISOLATE time is, in effect, your machine's cost of a single commit.

Run it as root, ideally while the machine is otherwise quiet. It touches only scratch tables named coraexp*, its own
cgroup directory and files in a temp directory, and it removes them on exit (also on Ctrl-C).

    sudo python3 tools/nft_latency_experiments.py                    # all four
    sudo python3 tools/nft_latency_experiments.py idle lock --check  # exit 1 if a verdict is wrong
    sudo python3 tools/nft_latency_experiments.py dump --tasks 160   # the listing cost, nft command vs netlink
    sudo python3 tools/nft_latency_experiments.py writes --tasks 160 # commits and time per write operation

Read the numbers, not only the verdict: "lock" is time waiting for the cross-process tap lock, "nft" is time inside
nft subprocesses, "no-op child" is how long `true` took under the same conditions, and "cpu pressure" is the share of
the sync during which some task was waiting for a CPU (kernel PSI). Two things to keep in mind. A busy host can slow
nft's commit WITHOUT slowing a fork, so a fast no-op child does not mean the host is idle: read the CPU pressure. And
on a single core, kernel work and host load are the same resource, so the kernel scenario cannot be cleanly separated
there; more cores separate them.
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
from cora_sentinel.netmon import _cpu_stall_ms, _fork_exec_ms, diagnose
from cora_sentinel.nflog import TapRules

SCENARIOS = ("idle", "lock", "busy", "kernel", "dump", "writes")
EXPECT = {"idle": ("not slow",), "lock": ("tap lock",),
          "busy": ("whole host is slow", "CPUs were oversubscribed"),
          "kernel": ("NOT oversubscribed", "points at nft")}       # "points at nft": the kernel exposes no PSI


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
        self.base = {"ctl": float("inf"), "slow": float("inf"), "total": float("inf")}   # fastest seen: the idle baseline
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
        psi0 = _cpu_stall_ms()
        t = time.monotonic()
        self.rules.sync(live)
        total = (time.monotonic() - t) * 1000.0
        psi1 = _cpu_stall_ms()
        cpu = None if psi0 is None or psi1 is None or total <= 0 else min(max((psi1 - psi0) / total, 0.0), 1.0)
        lt = self.rules.last_timing
        self.base["ctl"] = min(self.base["ctl"], ctl)
        self.base["slow"] = min(self.base["slow"], lt["nft_slowest_ms"])
        self.base["total"] = min(self.base["total"], total)
        return {"total": total, "lock": lt["lock_ms"], "nft": lt["nft_ms"], "slow": lt["nft_slowest_ms"], "ctl": ctl,
                "cmd": lt.get("nft_slowest_cmd", ""), "cpu": cpu}

    def run(self, label: str, n: int, gap: float = 0.25) -> tuple:
        rows = []
        for _ in range(n):
            rows.append(self.sync_once())
            time.sleep(gap)
        w = max(rows, key=lambda r: r["total"])
        verdict = diagnose(w["total"], w["lock"], w["nft"], w["slow"], w["ctl"], self.base["ctl"], self.base["slow"], w["cpu"], self.base["total"])
        cpu = "n/a" if w["cpu"] is None else f"{w['cpu']:.0%}"
        print(f"{label:<44} p50 {statistics.median(r['total'] for r in rows):6.0f} ms   worst sync {w['total']:6.0f} ms = "
              f"lock {w['lock']:5.0f} + nft {w['nft']:5.0f} (slowest call {w['slow']:5.0f} [{w['cmd']}]); "
              f"no-op child {w['ctl']:4.0f} ms; cpu pressure {cpu}")
        print(f"{'':<44} -> {verdict}\n")
        return w, verdict

    def dump_scaling(self, max_tasks: int) -> tuple:
        """Read the tap chain via the nft command and via netlink while live tasks (5 UDP rules each) accumulate."""
        def med(fn, n=3):
            v = []
            for _ in range(n):
                t = time.monotonic()
                out = fn()
                v.append((time.monotonic() - t) * 1000.0)
            return statistics.median(v), out
        print(f"{'live tasks':>12} {'tap rules':>10} {'nft command':>13} {'netlink':>10}   same rules?")
        made = []
        last = (0.0, 0.0, True)
        try:
            for n in sorted({min(x, max_tasks) for x in (10, 40, 80, 160, max_tasks)}):
                for i in range(len(made), n):
                    made.append(f"d{i}")
                    self.cg.create(made[-1])
                self.rules.sync({x: os.stat(self.cg.root / x).st_ino for x in self.cg.names()})
                self.fw.native = False
                cli, a = med(self.rules.rules)
                self.fw.native = True
                nl, b = med(self.rules.rules)
                same = a == b
                print(f"{n:>12} {5 * n:>10} {cli:10.1f} ms {nl:7.1f} ms   {'yes' if same else 'NO'}")
                last = (cli, nl, same)
        finally:
            self.fw.native = True
            for name in made:
                try:
                    (self.cg.root / name).rmdir()
                except OSError:
                    pass
            self.rules.sync({x: os.stat(self.cg.root / x).st_ino for x in self.cg.names()})    # drop their rules
        return last

    def write_costs(self, max_tasks: int) -> list:
        """[(live tasks, {operation: (commits, ms)})]: what each write operation costs as the table grows."""
        log = []
        orig = self.fw._run

        def logged(args, stdin):
            t = time.monotonic()
            r = orig(args, stdin)
            log.append((args[:2] == ["-f", "-"], (time.monotonic() - t) * 1000.0))
            return r
        view = TapRules(self.fw, 97, udp=None)               # what cora-run builds: UDP follows the live table
        made, jail, rows = [], [], []

        def newtask(prefix):
            name = f"{prefix}{len(made)}"
            made.append(name)
            self.cg.create(name)
            return name

        def timed(op, reps=5):
            commits, ms = [], []
            for i in range(reps):
                arg = op["prep"](i) if op.get("prep") else None
                log.clear()
                t = time.monotonic()
                op["run"](arg)
                ms.append((time.monotonic() - t) * 1000.0)
                commits.append(sum(1 for is_commit, _ in log if is_commit))
            return int(statistics.median(commits)), statistics.median(ms)

        def live():
            return {x: os.stat(self.cg.root / x).st_ino for x in self.cg.names()}

        def prep_gc(i):                                       # five isolated tasks that then die
            names = [newtask("j") for _ in range(5)]
            for x in names:
                self.fw.block(x)
            for x in names:
                (self.cg.root / x).rmdir()
            return None
        ops = {"cora-run install": {"prep": lambda i: newtask("w"), "run": lambda name: view.install(name)},
               "sentinel sync (+1)": {"prep": lambda i: newtask("w"), "run": lambda _: self.rules.sync(live())},
               "ISOLATE block()": {"prep": lambda i: newtask("w"), "run": lambda name: self.fw.block(name)},
               "gc of 5 dead tasks": {"prep": prep_gc, "run": lambda _: self.fw.gc(set(self.cg.names()))}}
        self.fw._run = logged
        try:
            for target in sorted({0, min(40, max_tasks), max_tasks}):
                while len([m for m in made if m.startswith("w")]) < target:
                    newtask("w")
                self.rules.sync(live())
                rows.append((target, {name: timed(op) for name, op in ops.items()}))
        finally:
            self.fw._run = orig
            for name in made:
                try:
                    (self.cg.root / name).rmdir()
                except OSError:
                    pass
            self.rules.sync(live())
            self.fw.gc(set(self.cg.names()))
        return rows

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
    ap.add_argument("scenarios", nargs="*", choices=list(SCENARIOS), help="default: all six")
    ap.add_argument("--tasks", type=int, default=160, help="live tasks for the dump and writes scenarios")
    ap.add_argument("--syncs", type=int, default=14, help="syncs per scenario")
    ap.add_argument("--spinners", type=int, default=None, help="busy processes (default 40 per core up to 80)")
    ap.add_argument("--loaders", type=int, default=16, help="nft transaction loaders")
    ap.add_argument("--check", action="store_true", help="exit 1 if a scenario that DID stall is named wrongly")
    args = ap.parse_args()
    args.scenarios = args.scenarios or list(SCENARIOS)
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
            if sc == "writes":
                rows = lab.write_costs(args.tasks)
                names = list(rows[0][1])
                print(f"{'live tasks':>12} " + " ".join(f"{n:>22}" for n in names))
                for n, ops in rows:
                    print(f"{n:>12} " + " ".join(f"{ops[x][0]} commit{'s' if ops[x][0] != 1 else ' '} {ops[x][1]:7.1f} ms".rjust(22) for x in names))
                many = [(n, x) for n, ops in rows for x in ops if ops[x][0] != 1]
                if many:
                    bad.append(sc)
                    print(f"   !! more than one commit per operation: {many}\n")
                else:
                    iso = rows[0][1]["ISOLATE block()"][1]
                    print(f"   -> one commit per operation. An ISOLATE takes {iso:.1f} ms here, which is about what a "
                          f"single commit costs on this machine.\n")
                continue
            if sc == "dump":
                cli, nl, same = lab.dump_scaling(args.tasks)
                if not same:
                    bad.append(sc)
                    print("   !! the netlink read and the nft command DISAGREE about the rules\n")
                elif cli < 100:
                    print(f"   (inconclusive: the nft command listed {args.tasks} tasks in only {cli:.0f} ms here; "
                          f"raise --tasks)\n")
                elif nl * 5 > cli:
                    bad.append(sc)
                    print(f"   !! netlink ({nl:.0f} ms) is not clearly faster than the nft command ({cli:.0f} ms)\n")
                else:
                    print(f"   -> netlink is {cli / max(nl, 0.1):.0f}x faster at {args.tasks} tasks, same rules\n")
                continue
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
            if not any(e in v for e in EXPECT[sc]):
                if sc in ("busy", "kernel") and not stalled:
                    print(f"   (inconclusive: this load did not make the sync slow enough to explain; raise "
                          f"{'--spinners' if sc == 'busy' else '--loaders'})\n")
                elif sc == "kernel" and "CPUs were oversubscribed" in v:
                    print("   (inconclusive: the loaders themselves oversubscribed the CPUs, so commit contention "
                          "cannot be separated from load here; use fewer --loaders, or a machine with more cores)\n")
                else:
                    bad.append(sc)
                    print(f"   !! expected a verdict containing one of {EXPECT[sc]!r}\n")
    finally:
        lab.cleanup()
    if bad and args.check:
        print("verdict wrong for:", ", ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
