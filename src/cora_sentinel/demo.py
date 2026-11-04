#!/usr/bin/env python3
"""
cora_sentinel.demo - watch Cora catch a live tracker connection, contain it, and write a report.

  sudo ./venv/bin/cora-demo --model models/qwen2.5-3b-instruct-q4_k_m.gguf

Two modes:
  (default)         OFFLINE. The demo hosts its own "tracker" on this machine's LAN address, lists
                    that address as a rogue subnet, and a test task connects to it. Nothing leaves
                    your machine and no DNS is used.
  --domain NAME     REAL. Lists NAME as a tracker domain; the daemon resolves it, the task makes a
                    real TCP connection to it. (Its address must come back the same for the daemon
                    and the task, so pick a stable name; CDN-rotated names can miss.)

Everything it creates is its own: cgroup root `cora-demo`, nft table `coradem`, a temp workdir.
It never touches your production `inet cora` table. Cleanup runs even on Ctrl-C.
Add --dry-run to see detection and the verdict without enforcing anything.
Add --ephemeral for zero-lifetime beacons (connect then close at once): the NFLOG tap attributes
the very first one; with --no-nflog the same beacons mostly slip through.
Add --udp for QUIC-looking UDP datagrams: only the tap can see these at all (sock_diag is TCP-only).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

TABLE, ROOT_NAME, TASK, GROUP = "coradem", "cora-demo", "demotask", 72   # 72: never clashes with a production 71

TASK_CODE = r'''
import socket, struct, sys, time
host, port, probe, deadline = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
mode = sys.argv[5] if len(sys.argv) > 5 else "hold"
t0 = time.time()
def log(m): print(f"[task +{time.time()-t0:5.1f}s] {m}", flush=True)
infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
infos = [i for i in infos if i[0] == socket.AF_INET] or infos
fam, _, _, _, addr = infos[0]
QUIC = bytes([0xC3]) + struct.pack("!I", 1) + b"\0" * 1100          # a QUIC v1 long-header, Initial-looking datagram
if mode == "udp":
    log(f"beaconing {host} ({addr[0]}:{addr[1]}) over UDP: one QUIC-looking datagram per socket, closed at once")
elif mode == "ephemeral":
    log(f"beaconing {host} ({addr[0]}:{addr[1]}): connect() then close() at once, lifetime ~0")
else:
    s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(8)
    try:
        s.connect(addr)
    except OSError as e:
        log(f"could not connect to {host}: {e}"); sys.exit(1)
    log(f"connected to {host} ({addr[0]}:{addr[1]}), behaving like a tracker beacon")
probe = addr[0] if probe == "-" else probe
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
n = 0
while time.time() - t0 < deadline:
    if mode == "udp":
        n += 1
        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b.sendto(QUIC, addr[:2]); b.close()
    elif mode == "ephemeral":
        n += 1
        try:
            socket.create_connection(addr[:2], timeout=1.5).close()
        except OSError:
            pass
    time.sleep(1.0)
    try:
        u.sendto(b"beacon", (probe, 9))
    except OSError as e:
        log(f"egress probe to {probe} FAILED ({e.strerror}): the network is blocked"
            + (f" (after {n} beacons)" if n else "")); sys.exit(0)
log("egress was never blocked before the deadline")
'''


def say(t0: float, msg: str) -> None:
    print(f"[{time.monotonic() - t0:6.1f}s] {msg}", flush=True)


class Tail:
    def __init__(self, path: Path):
        self.p, self.pos = path, 0

    def lines(self) -> List[str]:
        if not self.p.exists():
            return []
        with self.p.open(errors="replace") as f:
            f.seek(self.pos)
            data = f.read()
            self.pos = f.tell()
        return [l for l in data.splitlines() if l.strip()]


def default_route():
    """(gateway, our_source_ip) via the default route, or (None, None)."""
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                gw = socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((gw, 9))
                ip = s.getsockname()[0]
                s.close()
                return gw, ip
    except OSError:
        pass
    return None, None


def find_mount() -> Optional[str]:
    for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified"):
        if (Path(m) / "cgroup.controllers").exists():
            return m
    return None


def find_model(arg: Optional[str]) -> Optional[str]:
    if arg:
        return arg if Path(arg).is_file() else None
    env = os.environ.get("CORA_GGUF")
    if env and Path(env).is_file():
        return env
    found = sorted(glob.glob(str(Path.cwd() / "models" / "*.gguf")))
    return found[0] if found else None


def preflight(a) -> Optional[tuple]:
    ok = True

    def chk(cond, good, bad):
        nonlocal ok
        print(f"  {'ok ' if cond else 'FAIL'}  {good if cond else bad}")
        ok &= bool(cond)
    print("preflight:")
    chk(os.geteuid() == 0, "running as root", "needs root (cgroups + nftables): use sudo with your venv's python")
    chk(shutil.which("nft"), "nft found", "nft missing: sudo apt install nftables")
    mount = find_mount()
    chk(mount, f"cgroup v2 at {mount}", "no cgroup v2 mount found")
    model = find_model(a.model)
    chk(model, f"model {model}", "no model: pass --model PATH.gguf (or set CORA_GGUF)")
    for mod in ("llama_cpp", "subnetbus"):
        try:
            __import__(mod)
            chk(True, f"python module {mod}", "")
        except ImportError:
            chk(False, "", f"python module {mod} missing: run this with your venv's python")
    gw, local = default_route()
    if not a.no_nflog:
        try:
            from cora_sentinel.nflog import available
            ok_tap, why = available(GROUP)
        except Exception as e:
            ok_tap, why = False, str(e)
        print(f"  {'ok ' if ok_tap else 'note'}  " + (f"NFLOG group {GROUP} bindable (SYN tap on)" if ok_tap else
              f"SYN tap unavailable, continuing without it: {why}"))
        a.nflog_ok = ok_tap
    else:
        a.nflog_ok = False
    if not a.domain:
        chk(gw, f"default route via {gw}, local address {local}",
            "offline mode needs a default route (any network); or use --domain")
    return (mount, model, gw, local) if ok else None


def main() -> int:
    ap = argparse.ArgumentParser(description="live Cora demo", formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--model", help="Qwen GGUF path")
    ap.add_argument("--domain", help="use a real tracker domain instead of the offline stand-in")
    ap.add_argument("--port", type=int, default=443, help="port for --domain mode")
    ap.add_argument("--dry-run", action="store_true", help="detect and judge, enforce nothing")
    ap.add_argument("--ephemeral", action="store_true",
                    help="the task makes ZERO-LIFETIME beacons (connect then close at once) instead of "
                         "holding a connection; this is what the SYN tap exists to catch")
    ap.add_argument("--udp", action="store_true",
                    help="the task beacons over UDP (QUIC-looking datagrams to port 443) instead of TCP; "
                         "only the NFLOG tap can see this")
    ap.add_argument("--no-nflog", action="store_true", help="do not use the NFLOG flow tap")
    ap.add_argument("--timeout", type=float, default=150, help="seconds to wait for the whole chain")
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--workdir", help="keep files here (default: a temp dir)")
    a = ap.parse_args()

    pf = preflight(a)
    if pf is None:
        print("\nfix the FAIL lines and rerun.")
        return 2
    mount, model, gw, local = pf

    work = Path(a.workdir or tempfile.mkdtemp(prefix="cora-demo-"))
    (work / "bl").mkdir(parents=True, exist_ok=True)
    reports = work / "reports"
    t0 = time.monotonic()
    root = f"{mount}/{ROOT_NAME}"

    listener = None
    if a.domain:
        (work / "bl" / "demo-tracker.txt").write_text(f"{a.domain}\n")
        target, tport, probe = a.domain, (443 if a.udp else a.port), (gw or "-")
        say(t0, f"REAL mode: listing tracker domain {a.domain}")
    else:
        if a.udp:                                  # UDP needs no listener: the datagram is enough
            target, tport, probe = local, 443, gw
        else:
            listener = socket.socket()
            listener.bind((local, 0))
            listener.listen(4)
            target, tport, probe = local, listener.getsockname()[1], gw
        (work / "bl" / "demo-tracker.txt").write_text(f"{local}/32 ; offline demo stand-in\n")
        say(t0, f"OFFLINE mode: stand-in tracker at {local}:{tport}/{'udp' if a.udp else 'tcp'} "
                f"(nothing leaves this machine)")

    log = (work / "sentinel.log").open("w")
    cmd = [sys.executable, "-m", "cora_sentinel.daemon",
           "--cgroup-root", root, "--cgroup-mount", mount, "--nft", "--nft-table", TABLE,
           "--blocklist", str(work / "bl"), "--model", model, "--interval", "0.5",
           "--out", str(work / "events.jsonl"), "--decisions", str(work / "decisions.jsonl"),
           "--report-dir", str(reports), "--report-salt", str(work / "salt")]
    allow_nets = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"] + ([f"{gw}/32"] if gw else [])
    for net in allow_nets:                         # the egress probe goes to the gateway: not a violation
        cmd += ["--net-allow", net]
    if not a.dry_run:
        cmd.append("--enforce")
    if a.threads:
        cmd += ["--threads", str(a.threads)]
    if getattr(a, "nflog_ok", False):
        cmd += ["--nflog", "--nflog-group", str(GROUP)]
    sentinel = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=log)
    task = None
    try:
        slog, events, decisions = Tail(work / "sentinel.log"), Tail(work / "events.jsonl"), Tail(work / "decisions.jsonl")
        ready = resolved = False
        end = time.monotonic() + 240
        say(t0, f"starting daemon ({'dry-run' if a.dry_run else 'ENFORCING'}), loading model ...")
        while time.monotonic() < end and not (ready and (resolved or not a.domain)):
            for l in slog.lines():
                ready |= "watching" in l
                if "net source" in l:
                    say(t0, l.replace("[cora-sentinel] ", ""))
                resolved |= "resolver cycle done" in l
                if "cannot" in l or "not usable" in l:
                    print("  daemon:", l)
            if sentinel.poll() is not None:
                print("daemon exited early; see", work / "sentinel.log")
                print((work / "sentinel.log").read_text()[-800:])
                return 1
            time.sleep(0.3)
        if not ready:
            print("daemon never became ready; see", work / "sentinel.log")
            return 1
        say(t0, "daemon ready" + (" (domain resolved)" if a.domain else ""))

        env = {**os.environ, "CORA_CGROUP_ROOT": root, "CORA_CGROUP_MOUNT": mount,
               "CORA_NFT_TABLE": TABLE, "CORA_NFLOG_GROUP": str(GROUP)}
        (work / "task.out").write_text("")
        task = subprocess.Popen(
            [sys.executable, "-m", "cora_sentinel.run", TASK, sys.executable, "-c", TASK_CODE,
             target, str(tport), probe, str(a.timeout), "udp" if a.udp else ("ephemeral" if a.ephemeral else "hold")],
            env=env, stdout=(work / "task.out").open("w"), stderr=subprocess.STDOUT)
        say(t0, f"test task started in cgroup '{TASK}'")
        tout = Tail(work / "task.out")

        deadline = time.monotonic() + a.timeout
        report_seen_at = None
        task_gone_at = None
        saw_detection = False
        while time.monotonic() < deadline:
            for l in tout.lines():
                say(t0, l)
            for l in events.lines():
                e = json.loads(l)
                evi = e["anomaly"]["evidence"]
                saw_detection = True
                bl = evi.get("blocklist")
                say(t0, f"DETECTED {e['anomaly']['kind']} -> {evi.get('remote_ip')}:{evi.get('remote_port')}"
                        f"  severity={e['anomaly']['severity']}"
                        + (f"  via={evi['via']}" if evi.get("via") else "")
                        + (f"  proto={evi['proto']}" if evi.get("proto") else "")
                        + (f"  l7={evi['l7']}" if evi.get("l7") else "")
                        + (f"  qname={evi['qname']}" if evi.get("qname") else "")
                        + (f"  blocklist={bl['list']}/{bl['kind']}/{bl['entry']}" if bl else ""))
            for l in decisions.lines():
                d = json.loads(l)
                m = d["model"]
                say(t0, f"MODEL ({d['model_ms']/1000:.1f}s): {m['verdict']} conf={m['confidence']}")
                say(t0, f"DECISION final={d['final']} policy={d.get('policy')} "
                        f"gate={(d.get('gate') or {}).get('code')} action={d['action']}")
            for l in slog.lines():
                if l.startswith("[report]"):
                    say(t0, "REPORT written")
            if list(reports.glob("*.json")) and report_seen_at is None:
                report_seen_at = time.monotonic()
            if report_seen_at and time.monotonic() - report_seen_at > 4:   # let the task show its result
                break
            if task.poll() is not None and not saw_detection:                # the task died: do not wait out the timeout
                task_gone_at = task_gone_at or time.monotonic()
                if time.monotonic() - task_gone_at > 3:
                    say(t0, f"the test task exited (code {task.returncode}) before anything was detected")
                    break
            time.sleep(0.4)
        for l in tout.lines():
            say(t0, l)

        # ---- summary ----
        from cora_sentinel.cgroup import CgroupRoot
        from cora_sentinel.firewall import Firewall
        fw = Firewall(CgroupRoot(root, mount), table=TABLE)
        print("\n=== kernel state ===")
        rules = fw.rules()
        for n, r in rules.items():
            print(f"nft: egress BLOCKED for '{n}' (dropped {r['packets']} packets)")
        if not rules:
            print("nft: no egress rule" + (" (dry-run)" if a.dry_run else " (the model chose another verdict)"))
        files = sorted(reports.glob("*.json"))
        if not files:
            print("\nno report was generated. " + (
                "If the daemon resolved different addresses than the task used (CDN rotation), "
                "retry or pick another --domain." if a.domain else "see " + str(work / "sentinel.log")))
            return 1
        print("\n=== anonymized report (safe to share) ===")
        print(files[0].read_text())
        md = files[0].with_suffix(".md")
        title = json.loads(files[0].read_text())["violation"]
        print(f"file it:  gh issue create --repo nkaralus/cora-security "
              f"--title \"[violation] {title['type']}: {title['entry']}\" --body-file {md}")
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted, cleaning up ...")
        return 130
    finally:
        say(t0, "cleaning up")
        if sentinel.poll() is None:
            sentinel.send_signal(signal.SIGINT)
            try:
                sentinel.wait(timeout=20)
            except subprocess.TimeoutExpired:
                sentinel.kill()
        try:
            for line in (work / "sentinel.log").read_text().splitlines()[::-1]:
                if line.startswith("[net] polls="):
                    print("monitor accounting:", line[len("[net] "):])
                    break
        except OSError:
            pass
        try:
            from cora_sentinel.cgroup import CgroupRoot
            from cora_sentinel.firewall import Firewall
            cg = CgroupRoot(root, mount)
            for n in cg.names():
                for op in (cg.thaw, cg.kill):
                    try:
                        op(n)
                    except Exception:
                        pass
            end = time.monotonic() + 5
            while time.monotonic() < end and any(cg.pids(n) for n in cg.names()):
                time.sleep(0.1)
            Firewall(cg, table=TABLE).purge()
            for d in ("/run/lock", tempfile.gettempdir()):
                # The demo owns table `coradem`, so nothing else can hold this lock. NEVER do this in the
                # real sentinel: unlinking a lock another process has open lets a new opener ignore it.
                try:
                    os.unlink(os.path.join(d, f"cora-tap-{TABLE}.lock"))
                except OSError:
                    pass
            for _ in range(30):
                try:
                    for n in cg.names():
                        (cg.root / n).rmdir()
                    cg.root.rmdir()
                    break
                except OSError:
                    time.sleep(0.1)
        except Exception as e:
            print("cleanup warning:", e)
        if task:
            try:
                task.kill()
            except Exception:
                pass
        if listener:
            listener.close()
        print(f"files kept in {work}  (reports/ is anonymized; events.jsonl and decisions.jsonl "
              f"hold LOCAL detail like pids and command lines, do not share those)")


if __name__ == "__main__":
    sys.exit(main())
