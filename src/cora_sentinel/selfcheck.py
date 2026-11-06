#!/usr/bin/env python3
"""
cora-selfcheck - can THIS machine run the sentinel, and is the install complete?

    cora-selfcheck            # exit 0 only if everything REQUIRED is present

Each missing item says which capability it costs you, because most are optional: without nftables
you lose ISOLATE; without NFLOG you lose the connect-time tap; without root you lose all of it.
"""
from __future__ import annotations

import importlib
import inspect
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

PKG = "cora_sentinel"

# (module, what it must provide, test): proves the installed package is the complete, current one.
FEATURES: List[Tuple[str, str, Callable]] = [
    ("cgroup", "freeze_requested (async-freeze fix) + reset_limits", lambda m: hasattr(m.CgroupRoot, "freeze_requested") and hasattr(m.CgroupRoot, "reset_limits")),
    ("firewall", "cgroup-id rules (stale-rule fix)", lambda m: hasattr(m.Firewall, "cgroup_match")),
    ("blocklist", "DNS name matching", lambda m: hasattr(m.Blocklist, "match_name")),
    ("blocklist_store", "pinned, reviewed blocklist updates", lambda m: hasattr(m, "accept") and hasattr(m, "load_verified")),
    ("reload", "SIGHUP blocklist hot reload", lambda m: hasattr(m, "Reloader") and hasattr(m, "load_lists")),
    ("report", "anonymized violation reports", lambda m: hasattr(m, "Reporter") and hasattr(m, "validate_report")),
    ("sockdiag", "sock_diag dump + destroy events", lambda m: hasattr(m, "SockDiag") and hasattr(m, "DestroyListener")),
    ("nflog", "TCP + UDP/QUIC/DNS flow tap", lambda m: all(hasattr(m, n) for n in ("TapService", "classify_udp", "parse_dns_query"))),
    ("netmon", "NetMonitor(tap=...)", lambda m: "tap" in inspect.signature(m.NetMonitor.__init__).parameters),
    ("daemon", "shared judging + --nflog flags", lambda m: hasattr(m.ConnDetector, "judge")),
    ("verdict", "ISOLATE verdict + blocklist floor", lambda m: "ISOLATE" in m.VERDICTS and "blocklist_floor" in inspect.signature(m.Adjudicator.__init__).parameters),
]


def _line(status: str, what: str, note: str = "") -> None:
    print(f"  {status:<7} {what}" + (f"\n          -> {note}" if note else ""))


def nft_latency(root: bool) -> Optional[dict]:
    """Where does an nft call spend its time? Process start (fork/exec, library load) versus a transaction
    (the kernel commit, which waits on RCU). Measured with a scratch table, never touching real rules."""
    import statistics
    import subprocess
    import time
    nft = shutil.which("nft")
    if not nft:
        return None

    def med(cmd, stdin=None):
        v = []
        for _ in range(5):
            t = time.perf_counter()
            subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60)
            v.append((time.perf_counter() - t) * 1000)
        return statistics.median(v)
    out = {"start_ms": med([nft, "--version"])}
    if root:
        t = f"coraselfcheck{os.getpid()}"
        out["txn_ms"] = med([nft, "-f", "-"], f"add table inet {t}\ndelete table inet {t}\n")
    return out


def main() -> int:
    required_failed = 0
    print(f"cora-sentinel selfcheck  (python {platform.python_version()}, {platform.system()} {platform.release()})\n")

    print("required:")
    ok = sys.version_info >= (3, 10)
    _line("ok" if ok else "FAIL", "python >= 3.10", "" if ok else "this package needs Python 3.10+")
    required_failed += not ok
    try:
        importlib.import_module("cora_sentinel._vendor.subnetbus")
        from cora_sentinel import _vendor
        problems = _vendor.verify()
        if problems:
            _line("FAIL", "the vendored safety gate (subnetbus) was modified", "; ".join(problems[:4])
                  + ". Reinstall the package, or re-vendor on purpose: tools/vendor_bus.py")
            required_failed += 1
        else:
            _line("ok", _vendor.describe())
    except ImportError:
        _line("FAIL", "subnetbus (vendored safety gate)", "the install is damaged: reinstall cora-sentinel")
        required_failed += 1
    for mod, what, test in FEATURES:
        try:
            m = importlib.import_module(f"{PKG}.{mod}")
            good = bool(test(m))
        except Exception as e:
            _line("FAIL", f"{PKG}.{mod}: {what}", f"{e.__class__.__name__}: {e}")
            required_failed += 1
            continue
        _line("ok" if good else "FAIL", f"{PKG}.{mod}: {what}", "" if good else "installed package is stale: reinstall")
        required_failed += not good

    print("\nthe machine (each item says what it costs you if missing):")
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    _line("ok" if root else "note", "running as root",
          "" if root else "cgroups, nftables and NFLOG all need root: run privileged commands with sudo")
    mount: Optional[str] = next((m for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified")
                                 if (Path(m) / "cgroup.controllers").exists()), None)
    _line("ok" if mount else "MISSING", f"cgroup v2 ({mount or 'not mounted'})",
          "" if mount else "no per-task containment (SUSPEND/TERMINATE/THROTTLE/ISOLATE, cora-run, the tap)")
    _line("ok" if shutil.which("nft") else "MISSING", "nft binary",
          "" if shutil.which("nft") else "no ISOLATE and no tap: sudo apt install nftables")
    try:
        sd = importlib.import_module(f"{PKG}.sockdiag").available()
    except Exception:
        sd = False
    _line("ok" if sd else "MISSING", "NETLINK_SOCK_DIAG",
          "" if sd else "falls back to polling /proc/net/tcp: short TCP connections can be missed")
    if root:
        try:
            ok_tap, why = importlib.import_module(f"{PKG}.nflog").available(59999)
        except Exception as e:
            ok_tap, why = False, str(e)
        _line("ok" if ok_tap else "MISSING", "NFLOG (nfnetlink_log) bindable", "" if ok_tap else
              f"{why}: no connect-time tap, so zero-lifetime TCP and ALL UDP/QUIC are invisible")
    else:
        _line("skip", "NFLOG (nfnetlink_log) bindable", "needs root to test")
    lat = nft_latency(root)
    if lat:
        slow = lat.get("txn_ms", 0) > 200
        _line("note" if slow else "ok",
              f"nft: process start {lat['start_ms']:.0f} ms" + (f", one transaction {lat['txn_ms']:.0f} ms" if "txn_ms" in lat else "")
              + " (median of 5)",
              "a transaction this slow delays `cora-run` (tap-rule install) and rule syncs; detection is unaffected "
              "since 0.1.3" if slow else "")
    try:
        importlib.import_module("llama_cpp")
        _line("ok", "llama-cpp-python")
    except ImportError:
        _line("MISSING", "llama-cpp-python", "no model verdicts: pip install 'cora-sentinel[model]'")

    print("\nRESULT:", "ready (required items present)" if not required_failed else
          f"{required_failed} required problem(s): fix the FAIL lines first")
    return 1 if required_failed else 0


if __name__ == "__main__":
    sys.exit(main())
