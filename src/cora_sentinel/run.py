#!/usr/bin/env python3
"""cora-run NAME CMD [ARGS...]  - run CMD as a cora task.
cora-run --app APP [--memory-max SIZE] [--memory-high SIZE] [--psi-memory TRIGGER|off] [--socket PATH] [--] CMD [ARGS...]

--app: the UNPRIVILEGED path (no root, no sudo). cora-run asks the running cora-sentinel, over its socket, for a new
ephemeral scope "<app>-<6 hex>" with the given memory limits; the daemon moves THIS process into it (it knows the pid
from the socket, not from the request). cora-run then checks /proc/self/cgroup and only then execs CMD, which stays in
the scope with everything it starts. Needs membership of the daemon's --ui-group (usermod -aG cora YOU).
  --app steam      becomes steam-<SteamAppId> when Steam sets SteamAppId: launch options  cora-run --app steam %command%
  --psi-memory     the scope's memory-pressure tripwire, "some|full STALL_US WINDOW_US"; default "some 150000 1000000"
                   (150 ms of stall in any 1 s), "off" for none. SIGNAL ONLY: the tray turns amber and the journal
                   says so; nothing is changed. If the kernel refuses it, the program still starts and you are told.
  APP is lowercased, other characters become '-', at most 32. SIZE: bytes or 512M / 8G. Exit 4 if no scope was made
  (daemon unreachable, permission, refused, or the move cannot be seen in /proc/self/cgroup): CMD never starts unconfined.

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
import re
import sys

from cora_sentinel.cgroup import DEFAULT_MOUNT, DEFAULT_ROOT, CgroupError, CgroupRoot

EXIT_CONTAINED = 3      # the task's cgroup still carries containment from an earlier run: release it first
EXIT_LAUNCH = 4         # --app: no scope was made, so CMD was not started
DEFAULT_SOCKET = "/run/cora-sentinel/ui.sock"
LAUNCH_TIMEOUT_S = 10.0


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


def app_name(raw: str, env=os.environ) -> str:
    """'Dota 2' -> 'dota-2'; 'steam' -> 'steam-570' when Steam set SteamAppId=570. The daemon validates again."""
    name = re.sub(r"[^a-z0-9_-]+", "-", (raw or "").strip().lower()).strip("-_")
    appid = env.get("SteamAppId") or env.get("SteamGameId")
    if name == "steam" and appid and appid.isdigit():
        name = f"steam-{appid}"
    name = name[:32].rstrip("-_")
    if not name:
        raise ValueError(f"--app {raw!r} leaves no usable name (letters or digits needed)")
    return name


SCOPE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}-[0-9a-f]{6}", re.ASCII)


def in_scope(scope: str) -> bool:
    """What the kernel says this process is in (cgroup v2: the "0::" line). Only a real scope name can match: an empty
    or malformed answer must never compare equal to the root cgroup's empty last segment."""
    if not isinstance(scope, str) or not SCOPE_RE.fullmatch(scope):
        return False
    try:
        for line in open("/proc/self/cgroup"):
            if line.startswith("0::"):
                return line.rstrip("\n").rsplit("/", 1)[-1] == scope
    except OSError:
        pass
    return False


def parse_app_args(argv):
    opts = {"app": None, "memory_max": None, "memory_high": None, "psi_memory": None,
            "socket": os.environ.get("CORA_UI_SOCKET", DEFAULT_SOCKET)}
    keys = {"--app": "app", "--memory-max": "memory_max", "--memory-high": "memory_high", "--socket": "socket",
            "--psi-memory": "psi_memory"}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1
            break
        k, eq, v = a.partition("=")
        if k in keys:
            if not eq:
                if i + 1 >= len(argv):
                    raise ValueError(f"{a} needs a value")
                v, i = argv[i + 1], i + 1
            opts[keys[k]] = v
            i += 1
            continue
        if a.startswith("--"):
            raise ValueError(f"unknown option {a}")
        break
    cmd = argv[i:]
    if not cmd:
        raise ValueError("no command to run")
    if opts["app"] is None:
        raise ValueError("--app is required")
    return opts, cmd


def request_scope(path: str, app: str, memory_max=None, memory_high=None, timeout: float = LAUNCH_TIMEOUT_S,
                  psi_memory=None) -> dict:
    """Ask the daemon to put THIS process in a new scope. Returns its reply; raises OSError if it cannot be asked."""
    import json
    import socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(path)
        req = {"cmd": "launch", "app": app, "id": "cora-run"}
        if memory_max is not None:
            req["memory_max"] = memory_max
        if memory_high is not None:
            req["memory_high"] = memory_high
        if psi_memory is not None:
            req["psi_memory"] = psi_memory
        s.sendall((json.dumps(req) + "\n").encode())
        f = s.makefile("rb")
        while True:
            line = f.readline()
            if not line:
                raise OSError("cora-sentinel closed the connection without answering")
            msg = json.loads(line)
            if msg.get("type") == "result" and msg.get("id") == "cora-run":
                return msg
    finally:
        s.close()                                # never inherited by CMD


def launch_main(argv) -> int:
    try:
        opts, cmd = parse_app_args(argv)
        app = app_name(opts["app"])
    except ValueError as e:
        print(f"cora_run: {e}\n\n{__doc__}", file=sys.stderr)
        return 2
    path = opts["socket"]
    try:
        r = request_scope(path, app, opts["memory_max"], opts["memory_high"], psi_memory=opts["psi_memory"])
    except (OSError, ValueError) as e:
        hint = {13: " (are you in the daemon's --ui-group? log out and back in after usermod)",
                2: " (is cora-sentinel running with --ui-socket?)", 111: " (cora-sentinel is not listening)"}
        print(f"cora_run: cannot ask cora-sentinel for a scope at {path}: {e}"
              f"{hint.get(getattr(e, 'errno', None), '')}; not starting {cmd[0]}", file=sys.stderr)
        return EXIT_LAUNCH
    if not r.get("ok"):
        print(f"cora_run: cora-sentinel refused the scope: {r.get('error')}; not starting {cmd[0]}", file=sys.stderr)
        return EXIT_LAUNCH
    scope = r.get("scope") or ""
    if not in_scope(scope):
        print(f"cora_run: cora-sentinel answered {scope!r}, but this process is not in it (/proc/self/cgroup); "
              f"not starting {cmd[0]}", file=sys.stderr)
        return EXIT_LAUNCH
    lim = r.get("memory_max")
    print(f"cora_run: {cmd[0]} runs in scope {scope}" + (f", memory.max {lim} bytes" if lim else "")
          + (f", pressure tripwire '{r['psi_memory']}'" if r.get("psi_memory") else ""), file=sys.stderr, flush=True)
    if r.get("psi_error"):
        print(f"cora_run: WARNING: no pressure tripwire: {r['psi_error']} (the program starts anyway; the "
              f"tripwire only signals)", file=sys.stderr, flush=True)
    os.execvp(cmd[0], cmd)


def main() -> int:
    if sys.argv[1:2] and sys.argv[1].startswith("--app"):
        return launch_main(sys.argv[1:])
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
