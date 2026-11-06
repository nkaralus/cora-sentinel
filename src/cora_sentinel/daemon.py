#!/usr/bin/env python3
"""
cora_sentinel.daemon - the Cora out-of-band sentinel (console script: cora-sentinel).

Loop:  poll /proc -> assign virtual IP -> deterministic anomaly checks
       -> on trip, emit a structured JSON event for the 3B model.

Rules held by this file:
  * Deterministic filters only. The model is NOT called here.
  * Nothing is remediated. Events are written, never acted on.
  * All subnetbus contact goes through VirtualNet (one place to fix if the
    package API differs from the README).

Run:
  cora-sentinel --selftest
  cora-sentinel --match CORA_TASK --allow /tmp --out events.jsonl
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Tuple

from cora_sentinel.report import protocol_of
from cora_sentinel.blocklist import Blocklist, DomainResolver
from cora_sentinel.reload import ListError, Reloader, load_lists
from cora_sentinel.cgroup import CgroupRoot

try:
    from cora_sentinel._vendor.subnetbus import AABB, Registry   # the vendored, pinned copy (cora_sentinel/_vendor)
except ImportError:  # only if the install itself is damaged: the daemon then refuses to act (see verdict.py)
    AABB = Registry = None

SCHEMA_EVENT = "cora.sentinel.event/v1"
SCHEMA_VERDICT = "cora.sentinel.verdict/v1"
VERDICTS = ["ALLOW", "THROTTLE", "ISOLATE", "SUSPEND", "TERMINATE", "ESCALATE"]


# --------------------------------------------------------------------------
# /proc readers (pure, small, individually testable)
# --------------------------------------------------------------------------
def parse_meminfo(text: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            out[key.strip()] = int(parts[0])  # kB
    return out


def parse_status_rss_kb(text: str) -> Optional[int]:
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


def list_pids() -> List[int]:
    return [int(n) for n in os.listdir("/proc") if n.isdigit()]


def read_argv(pid: int) -> Optional[List[str]]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    return [a.decode(errors="replace") for a in raw.split(b"\0") if a]


def read_rss_kb(pid: int) -> Optional[int]:
    try:
        return parse_status_rss_kb(Path(f"/proc/{pid}/status").read_text())
    except OSError:
        return None


def read_starttime(pid: int) -> Optional[int]:
    """Process start time in clock ticks since boot (/proc/<pid>/stat field 22).
    Pid + starttime is a process identity; a pid alone can be reused."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    return int(raw.rsplit(")", 1)[1].split()[19])


def read_open_paths(pid: int) -> List[str]:
    """Absolute file paths behind a process's open fds. Skips pipes/sockets."""
    paths: List[str] = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        names = os.listdir(fd_dir)
    except OSError:
        return paths
    for n in names:
        try:
            target = os.readlink(f"{fd_dir}/{n}")
        except OSError:
            continue
        if target.endswith(" (deleted)"):
            target = target[: -len(" (deleted)")]
        if target.startswith("/"):
            paths.append(target)
    return paths


def read_socket_inodes(pid: int) -> set:
    """Inodes of sockets a process holds open (fd -> 'socket:[inode]')."""
    out = set()
    fd_dir = f"/proc/{pid}/fd"
    try:
        names = os.listdir(fd_dir)
    except OSError:
        return out
    for n in names:
        try:
            t = os.readlink(f"{fd_dir}/{n}")
        except OSError:
            continue
        if t.startswith("socket:["):
            out.add(int(t[8:-1]))
    return out


def _hex_ip(h: str) -> str:
    """/proc/net/tcp prints each 32-bit word in host byte order."""
    def word(w: str) -> bytes:
        b = bytes.fromhex(w)
        return b[::-1] if sys.byteorder == "little" else b
    if len(h) == 8:
        return str(ipaddress.IPv4Address(word(h)))
    return str(ipaddress.IPv6Address(b"".join(word(h[i:i + 8]) for i in range(0, 32, 8))))


def parse_proc_net_tcp(text: str) -> List[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        lip, lport = f[1].rsplit(":", 1)
        rip, rport = f[2].rsplit(":", 1)
        rows.append({"local_ip": _hex_ip(lip), "local_port": int(lport, 16),
                     "remote_ip": _hex_ip(rip), "remote_port": int(rport, 16),
                     "state": f[3], "inode": int(f[9])})
    return rows


def read_tcp_table() -> List[dict]:
    rows: List[dict] = []
    for p in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows += parse_proc_net_tcp(Path(p).read_text())
        except OSError:
            pass
    return rows


# --------------------------------------------------------------------------
# Deterministic detectors
# --------------------------------------------------------------------------
class PathPolicy:
    """Allowlist of roots. Anything outside is a violation."""

    IGNORED = ("/dev/", "/proc/", "/sys/")
    SENSITIVE = ("/etc/", "/root/", "/boot/", "/var/log/")

    def __init__(self, allowed_roots: List[str]):
        self.roots = [Path(os.path.realpath(r)) for r in allowed_roots]

    def check(self, path: str) -> Optional[Tuple[str, str]]:
        """Return (severity, path) if the path is not allowed, else None."""
        if path.startswith(self.IGNORED):
            return None
        p = Path(path)
        if any(p == r or r in p.parents for r in self.roots):
            return None
        sev = "high" if path.startswith(self.SENSITIVE) or "/.ssh/" in path else "medium"
        return sev, path


class MemSpikeDetector:
    """Trips when RSS rises >= spike_kb above the window minimum."""

    def __init__(self, window_s: float, spike_kb: int):
        self.window_s = window_s
        self.spike_kb = spike_kb
        self.hist: Dict[int, Deque[Tuple[float, int]]] = {}

    def feed(self, pid: int, t: float, rss_kb: int) -> Optional[dict]:
        h = self.hist.setdefault(pid, collections.deque())
        h.append((t, rss_kb))
        while h and t - h[0][0] > self.window_s:
            h.popleft()
        base = min(r for _, r in h)
        delta = rss_kb - base
        if delta >= self.spike_kb:
            return {"rss_kb": rss_kb, "baseline_kb": base, "delta_kb": delta,
                    "window_s": self.window_s}
        return None

    def forget(self, pid: int) -> None:
        self.hist.pop(pid, None)


DEFAULT_NET_ALLOW = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]  # loopback + the virtual net


class NetPolicy:
    """Destination allowlist. Anything outside is unauthorized."""

    def __init__(self, allowed: List[str]):
        self.nets = [ipaddress.ip_network(n, strict=False) for n in allowed]

    @staticmethod
    def normalize(ip: str):
        a = ipaddress.ip_address(ip)
        # ::ffff:1.2.3.4 is IPv4 in disguise; unwrap or it dodges the v4 allowlist
        if a.version == 6 and a.ipv4_mapped:
            return a.ipv4_mapped
        return a

    @staticmethod
    def dest_class(a) -> str:
        if a.is_global:
            return "public"
        if a.is_link_local:
            return "link_local"
        if a.is_private:
            return "private"
        return "other"

    def check(self, ip: str) -> Optional[Tuple[str, str]]:
        """Return (severity, dest_class) if the destination is not allowed."""
        a = self.normalize(ip)
        if any(a.version == n.version and a in n for n in self.nets):
            return None
        cls = self.dest_class(a)
        return ("high" if cls == "public" else "medium"), cls


class ConnDetector:
    """Per-pid diff of outbound TCP connections. Flags each NEW one once."""

    LIVE_STATES = ("01", "02")  # ESTABLISHED, SYN_SENT

    def __init__(self, policy: NetPolicy, blocklist: Optional[Blocklist] = None):
        self.policy = policy
        self.blocklist = blocklist
        self.seen: Dict[int, set] = {}

    def scan(self, pid: int, inodes: set, by_inode: Dict[int, dict],
             listen_ports: set) -> List[dict]:
        """/proc path: rows are matched to a pid by socket inode."""
        return self.scan_rows(pid, [by_inode[i] for i in inodes if i in by_inode], listen_ports)

    def scan_rows(self, key, rows: List[dict], listen_ports: set) -> List[dict]:
        """Flag each NEW outbound connection of one subject (a pid or a task name) once.
        Identity is the socket cookie when the source has one (sockdiag), else the
        3-tuple. `seen` is pruned to what is still live, so it cannot grow without
        bound and a reused source port is evaluated again as the new connection it is."""
        seen = self.seen.setdefault(key, set())
        live: set = set()
        out: List[dict] = []
        for r in rows:
            if r["state"] not in self.LIVE_STATES or r["remote_port"] == 0:
                continue
            if r["local_port"] in listen_ports:  # accepted inbound, not outbound
                continue
            ident = r.get("cookie") or (r["local_port"], r["remote_ip"], r["remote_port"])
            live.add(ident)
            if ident in seen:
                continue
            seen.add(ident)
            j = self.judge(r["remote_ip"], r["remote_port"], r["local_port"], r.get("inode"))
            if j:
                out.append(j)
        seen.intersection_update(live)
        return out

    def judge(self, remote_ip: str, remote_port: int, local_port: int,
              inode: Optional[int] = None, proto: str = "tcp", l7: Optional[str] = None,
              qname: Optional[str] = None) -> Optional[dict]:
        """The ONE place that decides whether a destination is a violation. Every source
        (/proc, sockdiag dumps, the SYN/UDP tap) goes through it, so they cannot disagree.
        A DNS query NAME on the blocklist is a hit even when the resolver itself is allowed
        (the lookup is the telemetry); a DNS lookup to an unauthorized resolver with no listed
        name is only 'medium': a lookup is not a connection."""
        addr = self.policy.normalize(remote_ip)
        bl = None
        lists = self.blocklist                      # read ONCE: a hot reload may swap it between two reads
        if lists is not None:                       # a blocklist hit beats the allowlist: listed means listed
            bl = (lists.match_name(qname) if qname else None) or lists.match_ip(addr)
        hit = self.policy.check(remote_ip)
        if bl is None and hit is None:
            return None
        ev = {"remote_ip": str(addr), "remote_port": remote_port, "local_port": local_port,
              "dest_class": hit[1] if hit else NetPolicy.dest_class(addr)}
        if proto != "tcp":
            ev["proto"] = proto
            if l7:
                ev["l7"] = l7
            if qname:
                ev["qname"] = qname
        if bl:
            ev["blocklist"] = bl._asdict()
        sev = "high" if bl else hit[0]
        if bl is None and l7 == "dns":
            sev = "medium"
        return {"severity": sev, "evidence": ev, "inode": inode}

    def forget(self, pid: int) -> None:
        self.seen.pop(pid, None)


# --------------------------------------------------------------------------
# Virtual IP layer - the only code that touches subnetbus
# --------------------------------------------------------------------------
class VirtualNet:
    """pid <-> virtual IP. subnetbus picks the IP; names follow its rule
    %[A-Z][a-zA-Z0-9]{0,63}, so pid 495 -> %Task495."""

    SUBNET = "10.1.1.0/24"  # bus reserves hosts .1-.9 and broadcast
    PIN_MAX_AGE_S = 300.0   # a pin older than this is a bug (a lost unpin): release anyway, so a VIP can never leak for good

    def __init__(self) -> None:
        self.lock = threading.RLock()  # shared with the adjudicator thread
        self.by_pid: Dict[int, str] = {}
        self._pins: Dict[int, int] = {}          # pid -> events in flight that need its VIP to stay registered
        self._pin_since: Dict[int, float] = {}   # pid -> when it was first pinned (monotonic)
        self._deferred: set = set()              # pids that exited while pinned: released at the last unpin
        self._clock = time.monotonic             # tests replace it
        self._stub_next = 10  # only used when subnetbus isn't installed
        self.reg = None
        if Registry is not None:
            self.reg = Registry()
            self.reg.add_subnet(self.SUBNET, label="cora-tasks")

    @staticmethod
    def name_for(pid: int) -> str:
        return f"%Task{pid}"

    def ensure(self, pid: int) -> str:
        ip = self.by_pid.get(pid)                    # steady state takes NO lock, so an adjudicator holding it
        if ip is not None and pid not in self._deferred:   # across nft cannot stall callers for a pid already known
            return ip
        with self.lock:
            return self._ensure(pid)

    def _ensure(self, pid: int) -> str:
        # A pid whose release was deferred (it exited while an event about it was being judged) and that is asked for again is a NEW
        # process with a reused pid number: it takes the VIP over, so the old event's late unpin cannot free a VIP now in use. (If
        # this call was in fact for the dead one, the next tick() finds it gone again and defers it again: self-healing.)
        self._deferred.discard(pid)
        if pid in self.by_pid:
            return self.by_pid[pid]
        if self.reg is not None:
            ip = self.reg.allocate(self.name_for(pid), self.SUBNET, kind="process").ip
        else:
            ip = f"10.1.1.{self._stub_next}"
            self._stub_next += 1
        self.by_pid[pid] = ip
        return ip

    def pin(self, pid: int) -> None:
        """An event about `pid` is queued for the model: keep its VIP registered until unpin(), even if the process exits meanwhile,
        so the safety gate can still act on what the model decides (a verdict can take seconds; a short task is gone by then)."""
        with self.lock:
            self._pins[pid] = self._pins.get(pid, 0) + 1
            self._pin_since.setdefault(pid, self._clock())

    def unpin(self, pid: int) -> None:
        """The matching end of pin(). The last unpin of a pid that exited meanwhile releases its VIP. Unbalanced calls are ignored."""
        with self.lock:
            n = self._pins.get(pid, 0)
            if n <= 0:
                return                                  # never pinned, or its stale pin was already force-released
            if n > 1:
                self._pins[pid] = n - 1
                return
            del self._pins[pid]
            self._pin_since.pop(pid, None)
            if pid in self._deferred:
                self._deferred.discard(pid)
                self._release(pid)

    def release(self, pid: int) -> None:
        with self.lock:
            if self._pins.get(pid):
                if self._clock() - self._pin_since.get(pid, 0.0) <= self.PIN_MAX_AGE_S:
                    self._deferred.add(pid)             # still being judged: tick() asks again every second, and unpin() finishes it
                    return
                self._pins.pop(pid, None)               # a pin this old is a lost unpin: do not leak the VIP for good
                self._pin_since.pop(pid, None)
            self._deferred.discard(pid)
            self._release(pid)

    def _release(self, pid: int) -> None:
        if self.by_pid.pop(pid, None) is not None and self.reg is not None:
            self.reg.release(self.name_for(pid))


# --------------------------------------------------------------------------
# Event payload for the 3B model
# --------------------------------------------------------------------------
def build_payload(pid: int, vip: str, cmdline: str, kind: str,
                  severity: str, evidence: dict,
                  starttime: Optional[int] = None,
                  cgroup: Optional[str] = None,
                  cgroup_id: Optional[int] = None,
                  detection: Optional[dict] = None) -> dict:
    try:
        mem = parse_meminfo(Path("/proc/meminfo").read_text())
    except OSError:
        mem = {}
    payload = {
        "schema": SCHEMA_EVENT,
        "event_id": uuid.uuid4().hex,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "subject": {"pid": pid, "vip": vip, "name": VirtualNet.name_for(pid),
                    "starttime": starttime, "cgroup": cgroup, "cgroup_id": cgroup_id,
                    "subnet": VirtualNet.SUBNET,
                    "cmdline": cmdline[:200]},
        "anomaly": {"kind": kind, "severity": severity, "evidence": evidence},
        "system": {"mem_available_kb": mem.get("MemAvailable"),
                   "mem_total_kb": mem.get("MemTotal")},
        "deterministic_action": "none",
        "expects": {"schema": SCHEMA_VERDICT, "verdict_enum": VERDICTS,
                    "fields": ["verdict", "confidence", "reason"]},
    }
    if detection:                       # how a connection was seen (proto, via): NOT in `anomaly`, so the model's prompt is unchanged
        payload["detection"] = detection
    return payload


# --------------------------------------------------------------------------
# Sentinel
# --------------------------------------------------------------------------
class Sentinel:
    def __init__(self, match: str, allow: List[str], spike_mb: int,
                 window_s: float, emit: Callable[[dict], None],
                 cooldown_s: float = 30.0, net_allow: Optional[List[str]] = None,
                 cgroups: Optional[CgroupRoot] = None,
                 blocklist: Optional[Blocklist] = None):
        self.match = match
        self.netmon_active = False          # True: cora_netmon owns connection detection
        self._fire_lock = threading.Lock()  # tick thread and the net monitor both fire events
        self.cgroups = cgroups
        self._cg: Dict[int, str] = {}  # pid -> task name (cgroup mode)
        self.policy = PathPolicy(allow)
        self.conn = ConnDetector(NetPolicy(net_allow if net_allow is not None
                                           else DEFAULT_NET_ALLOW), blocklist)
        self.mem = MemSpikeDetector(window_s, spike_mb * 1024)
        self.net = VirtualNet()
        self.emit = emit
        self.cooldown_s = cooldown_s
        self._last: Dict[Tuple, float] = {}
        self.vip_skipped = self.tick_errors = 0

    def cgroup_id_of(self, name: Optional[str]) -> Optional[int]:
        """The identity of a task's cgroup NOW (recorded in the event, so the gate can later prove it is still the same one)."""
        return self.cgroups.cgroup_id(name) if (self.cgroups is not None and name) else None

    def _payload(self, pid, vip, cmd, kind, sev, ev, st) -> dict:
        name = self._cg.get(pid)
        det = {"proto": protocol_of(ev), "via": "proc_tcp"} if kind == "unauthorized_connection" else None   # the /proc/net/tcp path
        return build_payload(pid, vip, cmd, kind, sev, ev, st, cgroup=name, cgroup_id=self.cgroup_id_of(name), detection=det)

    def _targets(self) -> Dict[int, str]:
        me = os.getpid()
        found: Dict[int, str] = {}
        if self.cgroups is not None:
            # membership comes from the kernel: children are included, no marker
            self._cg = self.cgroups.discover()
            for pid in self._cg:
                argv = read_argv(pid) if pid != me else None
                if argv:
                    found[pid] = " ".join(argv)
            return found
        for pid in list_pids():
            if pid == me:
                continue
            argv = read_argv(pid)
            # exact token, not substring: `bash -c "...CORA_TASK..."` or an
            # editor with the marker in a filename must never be tagged
            if argv and self.match in argv:
                found[pid] = " ".join(argv)
        return found

    def set_blocklist(self, bl: Optional[Blocklist]) -> None:
        """The one atomic swap behind a hot reload (see cora_sentinel.reload). The allowlist hangs off the
        list, so both change together."""
        self.conn.blocklist = bl

    def _fire(self, key: Tuple, now: float, payload: dict) -> None:
        with self._fire_lock:
            if now - self._last.get(key, -1e9) < self.cooldown_s:
                return
            self._last[key] = now
            payload.setdefault("timing", {})["seen_mono_s"] = now   # when the tap/tick saw it (process-local seconds)
            self.emit(payload)

    def guarded_tick(self) -> None:
        """tick() for the main loop: one bad tick is logged and counted, and the watch goes on (it used to end the daemon)."""
        try:
            self.tick()
        except Exception as e:
            self.tick_errors += 1
            if self.tick_errors <= 3 or self.tick_errors % 1000 == 0:
                print(f"[cora-sentinel] tick failed ({e.__class__.__name__}: {str(e)[:120]}); continuing "
                      f"({self.tick_errors} so far)", file=sys.stderr)

    def tick(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        targets = self._targets()
        by_inode: Dict[int, dict] = {}
        listen_ports: set = set()
        if targets and not self.netmon_active:  # one table read per tick, shared by all tasks
            for r in read_tcp_table():
                if r["state"] == "0A":
                    listen_ports.add(r["local_port"])
                if r["inode"]:
                    by_inode[r["inode"]] = r

        for pid, cmd in targets.items():
            try:
                vip = self.net.ensure(pid)
            except Exception as e:                  # the /24 holds 245 VIPs: a task with more processes must not stop the watch
                self.vip_skipped += 1
                if self.vip_skipped <= 3 or self.vip_skipped % 1000 == 0:
                    print(f"[cora-sentinel] no virtual IP for pid {pid} ({e.__class__.__name__}): it is not monitored this tick "
                          f"({self.vip_skipped} skipped so far)", file=sys.stderr)
                continue
            st = read_starttime(pid)

            rss = read_rss_kb(pid)
            if rss is not None:
                ev = self.mem.feed(pid, now, rss)
                if ev:
                    self._fire((pid, "memory_spike"), now,
                               self._payload(pid, vip, cmd, "memory_spike", "medium", ev, st))

            for path in read_open_paths(pid):
                hit = self.policy.check(path)
                if hit:
                    sev, p = hit
                    self._fire((pid, "path_violation", p), now,
                               self._payload(pid, vip, cmd, "path_violation", sev,
                                             {"path": p, "allowed_roots":
                                              [str(r) for r in self.policy.roots]}, st))

            for c in ([] if self.netmon_active else
                      self.conn.scan(pid, read_socket_inodes(pid), by_inode, listen_ports)):
                ev = c["evidence"]
                self._fire((pid, "unauthorized_connection", ev["remote_ip"], ev["remote_port"]),
                           now, self._payload(pid, vip, cmd, "unauthorized_connection",
                                              c["severity"], ev, st))

        for pid in set(self.net.by_pid) - set(targets):
            self.net.release(pid)
            self.mem.forget(pid)
            self.conn.forget(pid)


# --------------------------------------------------------------------------
# Selftest: spawn a tagged child that opens /etc/hostname and balloons RAM
# --------------------------------------------------------------------------
_CHILD = (
    "import socket,time;c=socket.create_connection(('127.0.0.1',{port}));"
    "time.sleep(1.0);f=open('/etc/hostname');time.sleep(1.0);"
    "b=bytearray(b'x')*(200*1024*1024);time.sleep(4)"
)


SHELL_SYNTAX = re.compile(r"\$[{(\w]|`")          # $VAR, ${VAR}, $(cmd), $1, `cmd`
STRAY_QUOTE = re.compile(r"^['\"]|['\"]$")         # a quote mark stuck to a value


def shell_tokens(argv: List[str]) -> List[Tuple[str, str]]:
    """Arguments that look like shell syntax nothing expanded: [(argument, what it looks like)].

    A systemd EnvironmentFile does no shell expansion and no quoting: `CORA_ARGS=--out $HOME/e.jsonl` reaches the daemon as the
    literal text $HOME/e.jsonl, and `--model "/m x.gguf"` as the tokens "/m and x.gguf" with quote marks still on them. The daemon
    then runs with arguments nobody meant, silently. A `~` is deliberately NOT flagged: the daemon expands it itself (--report-salt).
    """
    out: List[Tuple[str, str]] = []
    for tok in argv:
        if SHELL_SYNTAX.search(tok):
            out.append((tok, "a shell variable or command substitution"))
        elif STRAY_QUOTE.search(tok):
            out.append((tok, "a value with a quote mark stuck to it"))
    return out


def selftest() -> int:
    events: List[dict] = []
    # loopback is outside this allowlist on purpose, so the child's connect trips
    s = Sentinel("CORA_TASK_SELFTEST", ["/tmp"], spike_mb=100, window_s=5.0,
                 emit=events.append, net_allow=["10.0.0.0/8"])
    lis = socket.socket()
    lis.bind(("127.0.0.1", 0))
    lis.listen(1)
    child = subprocess.Popen([sys.executable, "-c", _CHILD.format(port=lis.getsockname()[1]),
                              "CORA_TASK_SELFTEST"])
    try:
        end = time.monotonic() + 7.5
        while time.monotonic() < end:
            s.tick()
            time.sleep(0.25)
    finally:
        child.kill()
        child.wait()
        lis.close()
    s.tick()  # lets the sentinel notice the exit and release the VIP

    kinds = {e["anomaly"]["kind"] for e in events}
    vips = {e["subject"]["vip"] for e in events}
    print(json.dumps(events[0], indent=2) if events else "no events")
    ok = kinds == {"path_violation", "memory_spike", "unauthorized_connection"} and not s.net.by_pid
    print(f"\nkinds={sorted(kinds)} vips={sorted(vips)} "
          f"bus={'subnetbus (vendored)' if Registry else 'STUB (vendored copy missing)'} "
          f"released={not s.net.by_pid}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="cora-sentinel prototype")
    ap.add_argument("--match", default="CORA_TASK", help="argv token marking test tasks (exact match)")
    ap.add_argument("--allow", action="append", default=None, help="allowed path root (repeatable)")
    ap.add_argument("--net-allow", action="append", default=None,
                    help=f"allowed destination CIDR (repeatable). Giving ANY replaces the default {DEFAULT_NET_ALLOW}, so list loopback "
                         f"too if you still want it")
    ap.add_argument("--cgroup-root", help="enable cgroup mode: tasks are dirs under this "
                    "cgroup v2 path (start them with cora-run); --match is ignored")
    ap.add_argument("--blocklist", action="append", metavar="PATH",
                    help="tracker/rogue list file or directory (repeatable)")
    ap.add_argument("--blocklist-store", metavar="DIR",
                    help="a pinned, reviewed store (see `cora-blocklist pull`): refuses to start unless every "
                         "active list is exactly what was approved")
    ap.add_argument("--blocklist-allow", action="append", metavar="PATH",
                    help="exceptions that always win over the blocklist (repeatable)")
    ap.add_argument("--no-resolve", action="store_true",
                    help="do not resolve listed domains to addresses (domain entries then never match)")
    ap.add_argument("--resolve-max", type=int, default=2000, help="domains resolved per hourly cycle")
    ap.add_argument("--no-blocklist-floor", action="store_true",
                    help="let the model downgrade a blocklist hit (default: floor is ISOLATE)")
    ap.add_argument("--no-contain-first", action="store_true",
                    help="wait for the model before isolating a blocklist hit (default: isolate at once, at the "
                         "floor, and let the model only add to it; see docs/containment-latency.md)")
    ap.add_argument("--report-dir", default="cora_reports",
                    help="anonymized violation reports for blocklist hits ('' disables)")
    ap.add_argument("--report-salt", default="~/.config/cora/report_salt",
                    help="file holding the secret salt that pseudonymizes task names in violation reports; created if missing, "
                         "and kept OUTSIDE the report directory on purpose (default %(default)s)")
    ap.add_argument("--report-include-process", action="store_true",
                    help="include the executable basename in reports (off by default)")
    ap.add_argument("--net-source", choices=("auto", "sockdiag", "proc"), default="auto",
                    help="connection source. sockdiag: netlink dumps + destroy events (needs "
                         "--cgroup-root); proc: /proc/net/tcp each tick. auto: sockdiag if usable")
    ap.add_argument("--net-interval", type=float, default=0.1,
                    help="sockdiag dump interval in seconds (default 0.1)")
    ap.add_argument("--nflog", action="store_true",
                    help="connect-time tap: log every task SYN via NFLOG so even zero-lifetime "
                         "connections are attributed (needs --nft, cgroup mode, root)")
    ap.add_argument("--nflog-group", type=int, default=71, help="NFLOG group (default 71; one process per group)")
    ap.add_argument("--no-tap-udp", action="store_true",
                    help="tap TCP only (default: also the first packet of every UDP flow: QUIC, DNS, ...)")
    ap.add_argument("--tap-udp-timeout", type=int, default=30,
                    help="seconds a UDP flow may idle before its next packet counts as a new flow (default 30)")
    ap.add_argument("--slip-log", metavar="PATH",
                    help="JSONL log of blocklisted connections that closed before any poll saw them")
    ap.add_argument("--nft-table", default="cora", help="nftables table name (default: cora)")
    ap.add_argument("--floor", action="store_true",
                    help="drop listed addresses in the KERNEL (nft sets, before the first packet leaves or arrives). "
                         "Host-wide, and it persists if the daemon dies (cora-floor remove). Needs --nft")
    ap.add_argument("--floor-dns", action="store_true",
                    help="also drop the addresses resolved for listed DOMAINS. Many tracker names share CDN addresses, "
                         "so this can break unrelated sites; list them in --blocklist-allow or --floor-allow first")
    ap.add_argument("--floor-allow", action="append", metavar="CIDR", default=[],
                    help="always accepted by the floor (repeatable). Loopback and the resolvers in /etc/resolv.conf "
                         "are always included")
    ap.add_argument("--floor-confirm", type=int, default=0, metavar="SECONDS",
                    help="dead-man switch: the floor is removed unless `cora-floor confirm` arrives within SECONDS "
                         "(10-3600). A watchdog OUTSIDE this process does the removal, so a crashed daemon cannot "
                         "strand it. Asked only when the allow set changed since it was last confirmed")
    ap.add_argument("--floor-allow-detected", action="store_true",
                    help="add the default gateway(s) and live SSH peers to the floor's allow set, instead of "
                         "refusing when the lists would drop them")
    ap.add_argument("--no-floor-precheck", action="store_true",
                    help="do not refuse a floor that would drop the default gateway or a live SSH peer")
    ap.add_argument("--state-dir", default="/var/lib/cora-sentinel",
                    help="where --floor-confirm keeps its state (default /var/lib/cora-sentinel)")
    ap.add_argument("--dyn-policy", choices=("off", "shadow", "enforce"), default="shadow",
                    help="turn the model's ISOLATE verdicts into short-lived kernel drops of the destination "
                         "(default shadow: record what it WOULD do in the decision log, touch nothing). "
                         "enforce needs --model, --enforce and --floor")
    ap.add_argument("--dyn-min-conf", type=float, default=0.9, help="model confidence needed (default 0.9)")
    ap.add_argument("--dyn-write-budget", type=int, default=20, metavar="PER_MIN",
                    help="kernel writes per minute (default 20)")
    ap.add_argument("--dyn-max-live", type=int, default=512, help="live dynamic elements (default 512)")
    ap.add_argument("--dyn-task-cap", type=int, default=8, help="distinct targets per task per hour (default 8)")
    ap.add_argument("--floor-log-group", type=int, default=72,
                    help="NFLOG group for floor drop records (default 72; the tap is 71; unbound = discarded)")
    ap.add_argument("--floor-out-priority", type=int, default=-5,
                    help="priority of the outbound floor chain (default -5: after the tap at -10, so the tap still "
                         "sees the first packet; use -300 to drop before the tap)")
    ap.add_argument("--nft", action="store_true",
                    help="enable the ISOLATE verdict: per-cgroup egress drop via nftables "
                         "(needs --cgroup-root and root/CAP_NET_ADMIN)")
    ap.add_argument("--cgroup-mount", default="/sys/fs/cgroup", help="where cgroup v2 is mounted (default %(default)s)")
    ap.add_argument("--spike-mb", type=int, default=150,
                    help="report a memory spike when a task's resident memory rises by at least this many MB above its minimum "
                         "within --window (default %(default)s)")
    ap.add_argument("--window", type=float, default=10.0, help="seconds of memory history a spike is measured over (default %(default)s)")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds between checks (default %(default)s)")
    ap.add_argument("--out", default="sentinel_events.jsonl", help="write events here, one JSON object per line (default %(default)s)")
    ap.add_argument("--selftest", action="store_true", help="run the built-in self-test, which provokes each kind of event once, and exit (0 on PASS)")
    ap.add_argument("--model", help="path to Qwen GGUF; enables the verdict stage")
    ap.add_argument("--enforce", action="store_true",
                    help="actually act on verdicts (default: dry-run)")
    ap.add_argument("--min-conf", type=float, default=0.6,
                    help="minimum model confidence (0 to 1) for an actionable verdict; below it the verdict becomes ESCALATE (default %(default)s)")
    ap.add_argument("--decisions", default="sentinel_decisions.jsonl",
                    help="write each adjudicator decision here, one JSON object per line (default %(default)s)")
    ap.add_argument("--threads", type=int, default=None, help="CPU threads for the language model (default: the library's choice)")
    ap.add_argument("--allow-shell-chars", action="store_true",
                    help="accept arguments containing $, a backtick or a stray quote mark (normally a sign of an unexpanded "
                         "shell variable in a systemd config, and refused with exit status 2)")
    a = ap.parse_args()

    if not a.selftest:                    # the journal shows what the daemon REALLY runs with: a mangled config is visible at once
        from cora_sentinel import __version__
        print(f"[cora-sentinel] {__version__} starting with: {shlex.join(sys.argv[1:])}", file=sys.stderr, flush=True)
    bad = shell_tokens(sys.argv[1:])
    if bad and not a.allow_shell_chars:
        for tok, why in bad:
            print(f"[cora-sentinel] refusing to start: the argument {tok!r} looks like {why} that nothing expanded.", file=sys.stderr)
        print("  A systemd EnvironmentFile (/etc/cora-sentinel/cora-sentinel.conf) does no shell expansion and no quoting: write literal "
              "values on one line, separated by spaces.\n  If a literal $ or quote mark really is meant, pass --allow-shell-chars.",
              file=sys.stderr)
        return 2

    if a.selftest:
        return selftest()

    # Validate combinations of flags BEFORE touching any file: a usage error must read as one, not as a
    # PermissionError traceback from some unwritable default output path.
    if a.nflog and (not a.cgroup_root or not a.nft or a.net_source == "proc"):
        print("[cora-sentinel] --nflog needs --cgroup-root, --nft and a sockdiag net source", file=sys.stderr)
        return 1
    if (a.floor or a.floor_dns) and not (a.floor and a.nft and a.cgroup_root):
        print("[cora-sentinel] --floor needs --nft and --cgroup-root (and --floor-dns needs --floor)", file=sys.stderr)
        return 1
    if a.dyn_policy == "enforce" and not (a.floor and a.enforce and a.model):
        print("[cora-sentinel] --dyn-policy enforce needs --model, --enforce and --floor "
              "(use shadow to see what it would do first)", file=sys.stderr)
        return 1
    if not 0.5 <= a.dyn_min_conf <= 1.0 or min(a.dyn_write_budget, a.dyn_max_live, a.dyn_task_cap) < 1:
        print("[cora-sentinel] bad --dyn-* limits (--dyn-min-conf 0.5-1.0, the rest at least 1)", file=sys.stderr)
        return 1
    if a.floor_confirm and (not a.floor or not 10 <= a.floor_confirm <= 3600):
        print("[cora-sentinel] --floor-confirm needs --floor and a value between 10 and 3600 seconds", file=sys.stderr)
        return 1
    try:
        out = open(a.out, "a", buffering=1)
    except OSError as e:
        print(f"[cora-sentinel] cannot open --out {a.out!r}: {e.strerror}", file=sys.stderr)
        return 1

    def emit(p: dict) -> None:
        line = json.dumps(p, separators=(",", ":"))
        out.write(line + "\n")
        print(line, flush=True)

    cg = None
    if a.cgroup_root:
        cg = CgroupRoot(a.cgroup_root, a.cgroup_mount)
        try:
            ctl = cg.ensure()
        except OSError as e:
            print(f"[cora-sentinel] cannot prepare cgroup root: {e} (run as root or use a "
                  f"delegated subtree)", file=sys.stderr)
            return 1
        print(f"[cora-sentinel] cgroup mode: {a.cgroup_root} controllers={ctl or 'none'}",
              file=sys.stderr)
    floor_ref: dict = {"sync": None, "track": None}   # filled in once the firewall exists (the resolver may cycle first)

    def reloaded(new: Blocklist) -> None:
        if floor_ref["sync"] is not None:
            floor_ref["sync"].on_reload(new)
        elif floor_ref["track"] is not None:
            floor_ref["track"].track(new)             # dyn policy in shadow without the floor: exemptions only

    def make_resolver(target: Blocklist) -> DomainResolver:
        r = DomainResolver(target, max_per_cycle=a.resolve_max)

        def cycled(n: int) -> None:
            # r.bl, not `target`: after a hot reload the resolver is aimed at the new list
            print(f"[cora-sentinel] resolver cycle done: {r.bl.summary()}", file=sys.stderr, flush=True)
            if floor_ref["sync"] is not None:
                floor_ref["sync"].on_resolver_cycle(r.bl)
        r.on_cycle = cycled
        return r

    has_lists = bool(a.blocklist or a.blocklist_store)
    bl = resolver = None
    if has_lists:
        try:
            bl, warns = load_lists(a.blocklist, a.blocklist_store, a.blocklist_allow)
        except ListError as e:
            print(f"[cora-sentinel] {e}", file=sys.stderr)
            return 1
        for w in warns:
            print(f"[cora-sentinel] warning: {w}", file=sys.stderr)
        print(f"[cora-sentinel] blocklist: {bl.summary()}", file=sys.stderr)
        if bl.domains and not a.no_resolve:
            resolver = make_resolver(bl)
            resolver.start()
            print(f"[cora-sentinel] resolving up to {a.resolve_max} listed domains/hour in the "
                  f"background (their names go to your system resolver; --no-resolve to disable)",
                  file=sys.stderr)
        elif bl.domains:
            print("[cora-sentinel] domain entries are INERT without resolution", file=sys.stderr)
    s = Sentinel(a.match, a.allow or ["/tmp", "/var/tmp"], a.spike_mb, a.window, emit,
                 net_allow=a.net_allow, cgroups=cg, blocklist=bl)
    reloader = Reloader(s, (lambda: load_lists(a.blocklist, a.blocklist_store, a.blocklist_allow))
                        if has_lists else None,
                        resolver=resolver, make_resolver=None if a.no_resolve else make_resolver,
                        on_reload=reloaded)
    reloader.start()
    fw = None
    if a.nft:
        if cg is None:
            print("[cora-sentinel] --nft needs --cgroup-root", file=sys.stderr)
            return 1
        from cora_sentinel.firewall import Firewall, FirewallError
        fw = Firewall(cg, table=a.nft_table)
        try:
            gone = fw.gc(cg.names())
            print(f"[cora-sentinel] nft egress control on; stale rules removed: {gone or 'none'}",
                  file=sys.stderr)
        except FirewallError as e:
            print(f"[cora-sentinel] nft not usable yet: {e}", file=sys.stderr)
        if a.floor:
            from cora_sentinel.floorguard import FloorGuard
            from cora_sentinel.nftsets import FloorSync, NftSets
            try:
                fs = FloorSync(NftSets.from_firewall(fw, log_group=a.floor_log_group,
                                                      out_priority=a.floor_out_priority),
                               extra_allow=a.floor_allow, dns=a.floor_dns,
                               precheck=not a.no_floor_precheck, allow_detected=a.floor_allow_detected,
                               guard=FloorGuard(a.state_dir) if a.floor_confirm else None)
                # pre-check, arm the dead-man (if asked), THEN install; live before the first tick
                fs.start(bl, a.floor_confirm)
            except (FirewallError, ValueError, OSError) as e:
                print(f"[cora-sentinel] --floor unusable: {e}", file=sys.stderr)
                return 1
            floor_ref["sync"] = fs
    adj = dyn = None
    if a.model and a.dyn_policy != "off":
        from cora_sentinel.dynpolicy import DynConfig, DynPolicy
        fsx = floor_ref["sync"]
        if fsx is None:                         # shadow without --floor: only the exemption checks are needed
            from cora_sentinel.nftsets import FloorSync, NftSets
            fsx = FloorSync(NftSets(table=a.nft_table), extra_allow=a.floor_allow,
                            allow_detected=a.floor_allow_detected, precheck=not a.no_floor_precheck,
                            log=lambda m: None)
            fsx.track(bl)
            floor_ref["track"] = fsx
        dyn = DynPolicy(a.dyn_policy, sets=floor_ref["sync"].sets if floor_ref["sync"] else None,
                        exempt=fsx.exempt_reason, state_dir=a.state_dir,
                        cfg=DynConfig(min_conf=a.dyn_min_conf, write_per_min=a.dyn_write_budget,
                                      max_live=a.dyn_max_live, task_cap=a.dyn_task_cap))
        if a.dyn_policy == "enforce":
            dyn.reconcile()
        print(f"[cora-sentinel] dyn policy: {a.dyn_policy} "
              f"({'kernel drops of model-ISOLATEd destinations, flow-level on web ports' if a.dyn_policy == 'enforce' else 'recording what it WOULD block in the decision log; nothing is written to the kernel'})",
              file=sys.stderr)
    if a.model:
        from cora_sentinel.verdict import Adjudicator, Executor, Qwen3B  # lazy: heavy deps
        reporter = None
        if bl is not None and a.report_dir:
            from cora_sentinel.report import Reporter
            reporter = Reporter(a.report_dir, a.report_salt, a.report_include_process)
        adj = Adjudicator(s.net, Qwen3B(a.model, n_threads=a.threads),
                          Executor(enforce=a.enforce, cgroups=cg, firewall=fw), a.decisions,
                          a.min_conf, reporter=reporter,
                          blocklist_floor=not a.no_blocklist_floor, contain_first=not a.no_contain_first,
                          dyn=dyn)
        adj.start()
        base_emit = emit
        emit = lambda p: (base_emit(p), adj.submit(p))  # noqa: E731
        s.emit = emit
    netmon = tap = None
    if a.nflog and (fw is None or cg is None or a.net_source == "proc"):
        print("[cora-sentinel] --nflog needs --cgroup-root, --nft and a sockdiag net source", file=sys.stderr)
        return 1
    if a.net_source != "proc":
        try:
            if cg is None:
                raise ValueError("needs --cgroup-root")
            from cora_sentinel.netmon import NetMonitor
            if a.nflog:
                from cora_sentinel.firewall import FirewallError
                from cora_sentinel.nflog import TapService
                try:
                    tap = TapService(fw, a.nflog_group, udp=not a.no_tap_udp,
                                     udp_timeout=a.tap_udp_timeout)   # binds first: a refusal leaves nft untouched
                except (OSError, FirewallError) as e:
                    print(f"[cora-sentinel] --nflog unusable: {e}", file=sys.stderr)
                    return 1
            netmon = NetMonitor(s, interval=a.net_interval, slip_log=a.slip_log, tap=tap)
            tap_note = ""
            if tap:
                protos = "TCP" if a.no_tap_udp else "TCP+UDP/QUIC"
                tap_note = f" + {protos} flow tap (NFLOG group {a.nflog_group}, connect-time attribution)"
            s.netmon_active = True
            netmon.start()
            print(f"[cora-sentinel] net source: sockdiag (dump every {a.net_interval}s, "
                  f"kernel cgroup attribution) + destroy-event audit"
                  f"{'' if netmon.listener else ' [audit UNAVAILABLE]'}"
                  f"{tap_note}",
                  file=sys.stderr, flush=True)
        except (OSError, ValueError) as e:
            if tap:
                tap.close()
                tap = None
            if a.nflog:
                print(f"[cora-sentinel] --nflog unusable: {e}", file=sys.stderr)
                return 1
            if a.net_source == "sockdiag":
                print(f"[cora-sentinel] --net-source sockdiag unusable: {e}", file=sys.stderr)
                return 1
            print(f"[cora-sentinel] net source: /proc/net/tcp every {a.interval}s "
                  f"(sockdiag not used: {e}). Connections shorter than the tick can be missed.",
                  file=sys.stderr, flush=True)
    else:
        print(f"[cora-sentinel] net source: /proc/net/tcp every {a.interval}s "
              f"(connections shorter than the tick can be missed)", file=sys.stderr, flush=True)
    stop = {"v": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(v=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(v=True))
    signal.signal(signal.SIGHUP, lambda *_: reloader.request())     # only sets a flag; a thread does the work
    if has_lists:
        print("[cora-sentinel] SIGHUP re-reads the blocklists without restarting (kill -HUP <pid>)",
              file=sys.stderr)
    from cora_sentinel import _vendor
    print(f"[cora-sentinel] {_vendor.describe()}", file=sys.stderr)       # the safety gate: where it came from, intact or not
    print(f"[cora-sentinel] watching '{a.match}' every {a.interval}s -> {a.out}",
          file=sys.stderr)
    n = 0
    while not stop["v"]:
        s.guarded_tick()
        n += 1
        if floor_ref["sync"] is not None:
            floor_ref["sync"].poll()            # reports the dead-man's outcome once
        if dyn is not None and a.dyn_policy == "enforce" and n % 3600 == 0:
            dyn.reconcile()                     # an operator unblock must not leave the ledger claiming a block
        if fw and n % 60 == 0:  # housekeeping: drop rules whose task cgroup is gone
            try:                # Firewall serializes itself; holding the registry lock across nft stalled everyone
                fw.gc(cg.names())
            except Exception as e:
                print(f"[cora-sentinel] nft gc failed: {e}", file=sys.stderr)
        time.sleep(a.interval)
    fsync = floor_ref["sync"]
    if fsync is not None and fsync.guard is not None and fsync.token and fsync.guard.state(fsync.token) == "pending":
        print("[cora-sentinel] exiting with the floor still unconfirmed: its watchdog will remove it when the "
              "window ends (under systemd, ExecStopPost does it now)", file=sys.stderr)
    if netmon:
        netmon.stop()
    if adj:
        adj.stop()
    reloader.stop()
    if reloader.resolver:
        reloader.resolver.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
