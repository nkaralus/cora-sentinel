#!/usr/bin/env python3
"""
cora_selfcheck.py - confirms this directory holds ONE consistent set of Cora files.
Run it first:   python3 cora_selfcheck.py

A mismatched download (some files from an older version) fails with confusing errors deep
inside tests. This names the stale file and the feature it is missing, and, if MANIFEST.sha256
is present, lists every file that differs from the release.
"""
from __future__ import annotations

import hashlib
import importlib
import inspect
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def src(name: str) -> str:
    return (HERE / f"{name}.py").read_text()


# (file, what it must provide, test)
CHECKS = [
    ("cora_cgroup", "CgroupRoot.reset_limits + freeze_requested (async-freeze fix)",
     lambda m: hasattr(m.CgroupRoot, "reset_limits") and hasattr(m.CgroupRoot, "freeze_requested")),
    ("cora_firewall", "Firewall.cgroup_match (cgroup-id rules, stale-rule fix)", lambda m: hasattr(m.Firewall, "cgroup_match")),
    ("cora_firewall", "release_task thaws on a REQUESTED freeze", lambda m: "freeze_requested" in src("cora_firewall")),
    ("cora_blocklist", "DomainResolver(on_cycle=...)", lambda m: "on_cycle" in inspect.signature(m.DomainResolver.__init__).parameters),
    ("cora_report", "Reporter / validate_report", lambda m: hasattr(m, "Reporter") and hasattr(m, "validate_report")),
    ("cora_sockdiag", "SockDiag + DestroyListener", lambda m: hasattr(m, "SockDiag") and hasattr(m, "DestroyListener")),
    ("cora_nflog", "TapService / NflogListener / TapRules", lambda m: all(hasattr(m, n) for n in ("TapService", "NflogListener", "TapRules"))),
    ("cora_netmon", "NetMonitor(tap=...) SYN-tap support", lambda m: "tap" in inspect.signature(m.NetMonitor.__init__).parameters),
    ("cora_sentinel", "ConnDetector.judge (shared judging)", lambda m: hasattr(m.ConnDetector, "judge")),
    ("cora_sentinel", "--nflog / --nflog-group / --net-source flags", lambda m: all(f in src("cora_sentinel") for f in ("--nflog", "--nflog-group", "--net-source"))),
    ("cora_verdict", "ISOLATE verdict + blocklist floor", lambda m: "ISOLATE" in m.VERDICTS and "blocklist_floor" in inspect.signature(m.Adjudicator.__init__).parameters),
    ("cora_run", "tap pre-install before exec", lambda m: "_preinstall_tap" in src("cora_run")),
    ("cora_demo", "--ephemeral / --no-nflog", lambda m: "--ephemeral" in src("cora_demo") and "--no-nflog" in src("cora_demo")),
]


def main() -> int:
    bad = 0
    print("feature check:")
    for mod, what, test in CHECKS:
        try:
            m = importlib.import_module(mod)
            ok = bool(test(m))
        except Exception as e:
            print(f"  STALE/BROKEN  {mod}.py: cannot verify '{what}' ({e.__class__.__name__}: {e})")
            bad += 1
            continue
        print(f"  {'ok   ' if ok else 'STALE'}  {mod}.py: {what}")
        bad += not ok

    man = HERE / "MANIFEST.sha256"
    if man.exists():
        print("\nmanifest check (files differing from the release):")
        diff = 0
        for line in man.read_text().splitlines():
            digest, _, name = line.partition("  ")
            p = HERE / name
            if not p.exists():
                print(f"  MISSING  {name}")
                diff += 1
            elif hashlib.sha256(p.read_bytes()).hexdigest() != digest:
                print(f"  DIFFERS  {name}")
                diff += 1
        print("  all files match the release" if not diff else f"  {diff} file(s) differ: re-download those")
        bad += diff

    print("\npython dependencies:")
    for mod, need in (("subnetbus", "pip install git+https://github.com/nkaralus/engine-telemetry-bus"),
                      ("llama_cpp", "pip install llama-cpp-python (only for the real model)"),
                      ("jsonschema", "pip install jsonschema (tests only)"), ("pytest", "pip install pytest")):
        try:
            importlib.import_module(mod)
            print(f"  ok     {mod}")
        except ImportError:
            print(f"  absent {mod}   -> {need}")
    print("\nRESULT:", "consistent set" if not bad else f"{bad} problem(s): fix the files above first")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
