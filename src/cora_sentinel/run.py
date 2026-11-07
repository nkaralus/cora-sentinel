#!/usr/bin/env python3
"""cora-run NAME CMD [ARGS...]  - run CMD as a cora task.

Refuses (exit 3) if <root>/NAME is left over from an earlier run and still carries containment (an nft drop rule,
a freeze, or THROTTLE limits): a relaunch reuses that cgroup, so it would start already severed, frozen or capped,
with nothing saying why. Undo is root-only, and the message names the command. This is about not failing silently;
the containment itself never depends on it (the kernel rule still matches a reused cgroup), so if the firewall
cannot be read, cora-run warns and starts anyway. CORA_NO_PREFLIGHT=1 skips the check on purpose (the task then
starts inside whatever its cgroup carries): the tap tests use it to watch an already-isolated task.

Creates <root>/NAME, moves *this* process into it, then execs CMD. The task and
everything it forks stay in that cgroup from its first instruction (no race,
no marker argument). Root: $CORA_CGROUP_ROOT (default /sys/fs/cgroup/cora).
"""
import os
import sys

from cora_sentinel.cgroup import DEFAULT_MOUNT, DEFAULT_ROOT, CgroupError, CgroupRoot

EXIT_CONTAINED = 3      # the task's cgroup still carries containment from an earlier run: release it first


def _preinstall_tap(cg: CgroupRoot, name: str) -> None:
    """If a sentinel runs the SYN tap (its chain exists), install this task's rule now, so
    the task's very first connect() is already attributed. Best effort: a sentinel that
    misses it installs the rule within one poll interval."""
    try:
        from cora_sentinel.firewall import Firewall
        from cora_sentinel.nflog import (DEFAULT_GROUP, PREINSTALL_LOCK_TIMEOUT_S, TapLockTimeout, TapRules,
                                         lock_timeout_from_env)
        fw = Firewall(cg, table=os.environ.get("CORA_NFT_TABLE", "cora"))
        # udp=None: follow the live table (the sentinel may run with --no-tap-udp)
        # a short lock timeout: never hold up starting the task for long (the sentinel installs the rule anyway)
        tap = TapRules(fw, int(os.environ.get("CORA_NFLOG_GROUP", DEFAULT_GROUP)), udp=None,
                       lock_timeout=lock_timeout_from_env(PREINSTALL_LOCK_TIMEOUT_S))
        if tap.active():
            tap.install(name)
    except TapLockTimeout as e:   # never block starting the task, but say what it costs
        print(f"cora_run: tap pre-install SKIPPED: {e}. The task starts anyway; its first connection may go "
              f"unobserved until the sentinel installs the rule.", file=sys.stderr)
    except Exception as e:   # never block starting the task
        print(f"cora_run: tap pre-install skipped ({e})", file=sys.stderr)


def _firewall(cg: CgroupRoot):
    try:
        from cora_sentinel.firewall import Firewall
        return Firewall(cg, table=os.environ.get("CORA_NFT_TABLE", "cora"))
    except Exception:
        return None


def preflight(cg: CgroupRoot, name: str, fw=None, warn=lambda m: print(m, file=sys.stderr)) -> "str | None":
    """None if NAME may start; otherwise why not. Only a cgroup that already exists can carry containment."""
    try:
        d = cg._dir(name)
    except CgroupError:
        return None                              # a bad name: cg.create() reports it
    if not d.is_dir():
        return None
    cid = cg.cgroup_id(name)
    if fw is not None:
        try:
            rule = fw.rules().get(name)
        except Exception as e:
            warn(f"cora_run: could not read the firewall ({e.__class__.__name__}: {e}); starting anyway. If "
                 f"'{name}' is still isolated, the kernel keeps it isolated: check with 'sudo cora-firewall list'")
            rule = None
        # a rule made for an OLDER cgroup of this name does not hold this one
        if rule is not None and (rule.get("cgid") is None or rule.get("cgid") == cid):
            return (f"task '{name}' is currently isolated in nftables; "
                    f"release it first with 'sudo cora-firewall release {name}'")
    try:
        if (d / "cgroup.freeze").read_text().strip() == "1":
            return f"task '{name}' is currently suspended (frozen); release it first with 'sudo cora-cgroup thaw {name}'"
    except OSError:
        pass
    for fname in ("cpu.max", "memory.high"):
        try:
            if (d / fname).read_text().split()[0] != "max":
                return (f"task '{name}' is currently throttled ({fname}); "
                        f"release it first with 'sudo cora-cgroup reset {name}'")
        except (OSError, IndexError):
            continue
    return None


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cg = CgroupRoot(os.environ.get("CORA_CGROUP_ROOT", DEFAULT_ROOT),
                    os.environ.get("CORA_CGROUP_MOUNT", DEFAULT_MOUNT))
    if os.environ.get("CORA_NO_PREFLIGHT") == "1":
        print(f"cora_run: CORA_NO_PREFLIGHT=1: starting '{sys.argv[1]}' without the containment check; it runs inside "
              "whatever its cgroup carries", file=sys.stderr)
        refusal = None
    else:
        refusal = preflight(cg, sys.argv[1], _firewall(cg))
    if refusal:
        print(f"cora_run: {refusal}", file=sys.stderr)
        return EXIT_CONTAINED
    try:
        path = cg.create(sys.argv[1])
        _preinstall_tap(cg, sys.argv[1])         # BEFORE the move: no unobserved first SYN
        (path / "cgroup.procs").write_text("0")  # 0 = the writing process
    except (CgroupError, OSError) as e:
        print(f"cora_run: cannot enter cgroup: {e}", file=sys.stderr)
        return 1
    # started via sudo? the cgroup move needed root, the task must not keep it
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid and int(uid) != 0:
        os.setgroups([])
        os.setgid(int(gid))
        os.setuid(int(uid))
    os.execvp(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
