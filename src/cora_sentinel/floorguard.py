#!/usr/bin/env python3
"""
cora_sentinel.floorguard - keeps the kernel floor from locking you out. Stdlib only.

The floor is host-wide and outlives the daemon, so a bad allow list can cut off the one session you would use to
fix it. Two independent safeguards:

  PRE-CHECK   Detect the default gateway(s) and the live SSH peers (from /proc, no external tools) and refuse to
              install or reload a floor whose lists would drop one of them. `--floor-allow-detected` adds them to
              the allow set instead of refusing; `--no-floor-precheck` turns the check off.

  DEAD-MAN    `--floor-confirm N`: the floor is installed with a rollback timer. Unless `cora-floor confirm` arrives
              within N seconds the floor is removed. The timer is NOT in the daemon: it is a separate, detached
              watchdog process that is started (and seen to be running) BEFORE the floor goes in, so a daemon that
              crashes, hangs or is killed cannot strand an unconfirmed floor. Under systemd the unit's ExecStopPost
              runs `cora-floor rollback`, because the service's cgroup (and the watchdog with it) is killed on stop.

Rules that exist because the naive version gets them wrong:

  * ARM BEFORE INSTALL, AND PROVE IT. A floor with no working timer is worse than no floor. `arm()` waits for the
    watchdog to report in and raises if it does not, and the caller then refuses to install.
  * A RESTART DOES NOT RE-PROMPT. A human who confirmed an allow set has vouched for it; an unattended restart
    (Restart=on-failure, a reboot) must not silently remove protection 120 s later. The confirmed fingerprint covers
    the allow set, the table and the priorities, and is kept in /var/lib so it survives a reboot. The pending
    state is tied to the boot id, so a stale one from before a reboot is ignored.
  * ONE LOCK, ONE DECISION. confirm, rollback and the watchdog's deadline all decide under the same flock, so a
    confirm at the last second cannot race a rollback.
  * A FAILED REMOVAL IS RETRIED, NOT FORGOTTEN. The pending state is only cleared once the floor is really gone.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from cora_sentinel.firewall import FirewallError

DEFAULT_STATE_DIR = "/var/lib/cora-sentinel"
SSH_PORTS = (22,)
PENDING, CONFIRMED, ROLLEDBACK, LOCK = ("floor.pending.json", "floor.confirmed.json",
                                        "floor.rolledback.json", "floor.lock")


class GuardError(FirewallError):
    pass


# --------------------------------------------------------------------------
# what must never be cut off
# --------------------------------------------------------------------------
def _v4(hexs: str):
    return ipaddress.IPv4Address(struct.pack("=L", int(hexs, 16)))          # /proc prints the host-order u32


def _v6(hexs: str):
    return ipaddress.IPv6Address(b"".join(struct.pack("=L", int(hexs[i:i + 8], 16)) for i in range(0, 32, 8)))


def _unmap(a):
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def _usable(a) -> bool:
    return not (a.is_loopback or a.is_unspecified or a.is_multicast)


def default_gateways(proc: str = "/proc") -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in Path(proc, "net/route").read_text().splitlines()[1:]:
            f = line.split()
            try:
                if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000" and int(f[3], 16) & 2:
                    out[str(_v4(f[2]))] = "default gateway"
            except ValueError:
                continue
    except OSError:
        pass
    try:
        for line in Path(proc, "net/ipv6_route").read_text().splitlines():
            f = line.split()
            try:                                  # dest ::/0, a next hop, RTF_GATEWAY
                if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[4] != "0" * 32 and int(f[8], 16) & 2:
                    out[str(ipaddress.IPv6Address(bytes.fromhex(f[4])))] = "default gateway"
            except ValueError:
                continue
    except OSError:
        pass
    return out


def ssh_peers(proc: str = "/proc", env: Optional[dict] = None, ports: Sequence[int] = SSH_PORTS) -> Dict[str, str]:
    """Peers of established TCP connections to an SSH port, plus the client in $SSH_CONNECTION (which also tells us
    a non-standard server port). A daemon started from a session on port 2222 is therefore covered; one started
    by systemd with sshd on a non-standard port needs `--floor-allow`."""
    env = os.environ if env is None else env
    want = set(ports)
    out: Dict[str, str] = {}
    sc = env.get("SSH_CONNECTION", "").split()
    if len(sc) == 4:
        try:
            out[str(_unmap(ipaddress.ip_address(sc[0])))] = "SSH_CONNECTION client"
            want.add(int(sc[3]))
        except ValueError:
            pass
    for name, dec in (("net/tcp", _v4), ("net/tcp6", _v6)):
        try:
            lines = Path(proc, name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 4 or f[3] != "01":                     # 01 = ESTABLISHED
                continue
            try:
                lport = int(f[1].partition(":")[2], 16)
                if lport not in want:
                    continue
                out.setdefault(str(_unmap(dec(f[2].partition(":")[0]))), f"established session to port {lport}")
            except ValueError:
                continue
    return {k: v for k, v in out.items() if _usable(ipaddress.ip_address(k))}


def protected_addresses(proc: str = "/proc", env: Optional[dict] = None) -> Dict[str, str]:
    """{address: why it must stay reachable}"""
    out = dict(default_gateways(proc))
    for k, v in ssh_peers(proc, env).items():
        out.setdefault(k, v)
    return {k: v for k, v in out.items() if _usable(ipaddress.ip_address(k))}


def net_index(entries: Iterable[str]):
    """Collapsed (v4 nets, v6 nets) for coverage tests."""
    from cora_sentinel.nftsets import parse_entries
    v4, v6 = parse_entries(entries)
    return list(ipaddress.collapse_addresses(v4)), list(ipaddress.collapse_addresses(v6))


def covering(addr: str, index) -> Optional[str]:
    a = ipaddress.ip_address(addr)
    for n in index[0 if a.version == 4 else 1]:
        if a in n:
            return str(n)
    return None


def fingerprint(table: str, in_prio, out_prio, allow_entries: Iterable[str]) -> str:
    v4, v6 = net_index(allow_entries)
    parts = [table, str(in_prio), str(out_prio)] + sorted(map(str, v4)) + ["|"] + sorted(map(str, v6))
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


# --------------------------------------------------------------------------
# the dead-man
# --------------------------------------------------------------------------
def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


class FloorGuard:
    def __init__(self, state_dir: str = DEFAULT_STATE_DIR, spawn_prefix: Sequence[str] = (),
                 sets_factory: Optional[Callable[[str], object]] = None, spawn: bool = True):
        self.dir = Path(state_dir)
        self.spawn_prefix = list(spawn_prefix)           # e.g. ["ip", "netns", "exec", NS] in the tests
        self.spawn = spawn
        self._sets_factory = sets_factory

    # ---- small file layer ----
    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    @contextlib.contextmanager
    def _lock(self):
        self._ensure()
        fd = os.open(self.dir / LOCK, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _read(self, name: str) -> Optional[dict]:
        try:
            return json.loads((self.dir / name).read_text())
        except (OSError, ValueError):
            return None

    def _write(self, name: str, obj: dict) -> None:
        tmp = self.dir / (name + ".tmp")
        tmp.write_text(json.dumps(obj))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.dir / name)

    def _rm(self, name: str) -> None:
        with contextlib.suppress(OSError):
            (self.dir / name).unlink()

    def _sets(self, table: str):
        if self._sets_factory:
            return self._sets_factory(table)
        from cora_sentinel.nftsets import NftSets
        return NftSets(table=table)

    # ---- state ----
    def pending(self) -> Optional[dict]:
        p = self._read(PENDING)
        return p if p and p.get("boot_id") == boot_id() else None        # a pre-reboot leftover is not pending

    def is_confirmed(self, fp: str) -> bool:
        c = self._read(CONFIRMED)
        return bool(c and c.get("fingerprint") == fp)

    def state(self, token: str) -> str:
        p = self.pending()
        if p and p.get("token") == token:
            return "pending"
        for name, label in ((ROLLEDBACK, "rolledback"), (CONFIRMED, "confirmed")):
            r = self._read(name)
            if r and r.get("token") == token:
                return label
        return "gone"

    def remaining(self) -> Optional[float]:
        p = self.pending()
        return max(0.0, p["deadline"] - time.time()) if p else None

    # ---- actions ----
    def arm(self, table: str, seconds: int, fp: str, ready_timeout: float = 5.0) -> str:
        """Write the pending record, start the watchdog, and wait until it reports in. Raises GuardError if it cannot:
        the caller must then NOT install the floor."""
        token = secrets.token_hex(8)
        with self._lock():
            self._rm(ROLLEDBACK)
            self._write(PENDING, {"token": token, "table": table, "fingerprint": fp, "seconds": seconds,
                                  "armed_at": time.time(), "deadline": time.time() + seconds,
                                  "boot_id": boot_id(), "watchdog_pid": None})
        if not self.spawn:
            return token
        cmd = [*self.spawn_prefix, sys.executable, "-m", "cora_sentinel.nftsets", "--state-dir", str(self.dir),
               "watchdog", token, str(seconds)]
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        except OSError as e:
            self.disarm(token)
            raise GuardError(f"cannot start the rollback watchdog: {e}") from None
        end = time.monotonic() + ready_timeout
        while time.monotonic() < end:
            p = self.pending()
            if p and p.get("token") == token and p.get("watchdog_pid"):
                return token
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        self.disarm(token)
        raise GuardError("the rollback watchdog did not start; not installing a floor with no way back")

    def disarm(self, token: str) -> None:
        with self._lock():
            p = self.pending()
            if p and p.get("token") == token:
                self._rm(PENDING)

    def confirm(self) -> Tuple[bool, str]:
        with self._lock():
            p = self.pending()
            if not p:
                return False, "no floor is awaiting confirmation"
            self._write(CONFIRMED, {"fingerprint": p["fingerprint"], "token": p["token"], "table": p["table"],
                                    "at": time.time()})
            self._rm(PENDING)
        return True, "confirmed: the floor stays"

    def unconfirm(self) -> bool:
        with self._lock():
            had = (self.dir / CONFIRMED).exists()
            self._rm(CONFIRMED)
        return had

    def rollback(self, expected_token: Optional[str] = None, reason: str = "not confirmed") -> bool:
        """Remove the floor if one is pending (and, when given, it is the one `expected_token` armed). True if it did.
        Raises FirewallError if the removal fails; the pending record then stays, so a retry still knows."""
        with self._lock():
            p = self.pending()
            if not p or (expected_token and p.get("token") != expected_token):
                return False
            self._sets(p["table"]).remove(best_effort=True)
            self._write(ROLLEDBACK, {"token": p["token"], "table": p["table"], "reason": reason, "at": time.time()})
            self._rm(PENDING)
        return True


def watchdog(state_dir: str, token: str, seconds: float, sets_factory=None,
             sleep: Callable[[float], None] = time.sleep, retries: int = 30) -> int:
    """The detached timer. Exits quietly if the floor is confirmed, disarmed or superseded."""
    g = FloorGuard(state_dir, sets_factory=sets_factory, spawn=False)
    with g._lock():
        p = g.pending()
        if not p or p.get("token") != token:
            return 0
        p["watchdog_pid"] = os.getpid()
        g._write(PENDING, p)                                   # tells arm() that the safety net is live
    end = time.monotonic() + seconds
    while True:
        p = g.pending()
        if not p or p.get("token") != token:
            return 0
        if time.monotonic() >= end:
            break
        sleep(0.2)
    for _ in range(retries):
        try:
            g.rollback(expected_token=token, reason="not confirmed in time")
            return 0
        except FirewallError:
            sleep(1.0)
    return 1


if __name__ == "__main__":
    sys.exit("run `cora-floor` instead")
