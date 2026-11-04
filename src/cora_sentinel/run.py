#!/usr/bin/env python3
"""cora-run NAME CMD [ARGS...]  - run CMD as a cora task.

Creates <root>/NAME, moves *this* process into it, then execs CMD. The task and
everything it forks stay in that cgroup from its first instruction (no race,
no marker argument). Root: $CORA_CGROUP_ROOT (default /sys/fs/cgroup/cora).
"""
import os
import sys

from cora_sentinel.cgroup import DEFAULT_MOUNT, DEFAULT_ROOT, CgroupError, CgroupRoot


def _preinstall_tap(cg: CgroupRoot, name: str) -> None:
    """If a sentinel runs the SYN tap (its chain exists), install this task's rule now, so
    the task's very first connect() is already attributed. Best effort: a sentinel that
    misses it installs the rule within one poll interval."""
    try:
        from cora_sentinel.firewall import Firewall
        from cora_sentinel.nflog import DEFAULT_GROUP, TapRules
        fw = Firewall(cg, table=os.environ.get("CORA_NFT_TABLE", "cora"))
        # udp=None: follow the live table (the sentinel may run with --no-tap-udp)
        tap = TapRules(fw, int(os.environ.get("CORA_NFLOG_GROUP", DEFAULT_GROUP)), udp=None)
        if tap.active():
            tap.install(name)
    except Exception as e:   # never block starting the task
        print(f"cora_run: tap pre-install skipped ({e})", file=sys.stderr)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cg = CgroupRoot(os.environ.get("CORA_CGROUP_ROOT", DEFAULT_ROOT),
                    os.environ.get("CORA_CGROUP_MOUNT", DEFAULT_MOUNT))
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
