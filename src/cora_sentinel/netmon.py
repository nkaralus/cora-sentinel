#!/usr/bin/env python3
"""
cora_sentinel.netmon - connection monitor for the sentinel (cgroup mode). One thread, one loop.

Three sources, strongest first:

  1. Flow tap (cora_nflog, optional)  fires at connect()/first-datagram time, TCP SYNs and UDP
                                      (QUIC, DNS...). The kernel names the TASK by
                                      matching the sending socket's cgroup, so even a socket that
                                      lives for microseconds is attributed before it can close.
  2. sock_diag dump                   every poll interval; kernel-attributed by cgroup id. Catches
                                      connections that pre-date the tap and anything the tap's
                                      rules do not cover (a task not yet seen by the monitor).
  3. sock_diag destroy-event stream   every TCP socket, none missed. Carries no cgroup id, so it is
                                      only an AUDIT: a blocklisted destination that neither of the
                                      above attributed is logged as an unattributed SLIP.

Ordering matters and is deliberate: the loop always drains the SYN socket BEFORE the destroy
socket. A SYN is queued before its socket can exist long enough to be destroyed, so a destroy
event for a tapped connection can never be mistaken for a slip.

Guarantees, and their limits:
  * With the tap: a blocklisted/unauthorized TCP connection by a task is attributed at SYN time,
    provided the task's rule exists. cora-run installs it before exec (no gap); otherwise the
    monitor installs it within one poll interval. TCP only; needs root and nfnetlink_log.
  * Without the tap: detection cannot slip, but attribution only exists for sockets that a dump
    saw alive (see tests/test_sockdiag.py for the measured lifetime boundary).
  * Receive-buffer overflow on either netlink socket is counted (LOST), never hidden.
  * Slips are judged against the BLOCKLIST only, never the allowlist policy: unattributed,
    host-wide traffic against "everything outside 10/8" would be pure noise.
"""
from __future__ import annotations

import collections
import errno
import ipaddress
import json
import os
import queue
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from cora_sentinel.daemon import build_payload, read_argv, read_socket_inodes, read_starttime
from cora_sentinel.sockdiag import TCP_LISTEN, DestroyListener, SockDiag

SLIP_RATE_S = 60.0     # log each (ip, port) slip at most once per minute; all are still counted
TUPLE_TTL_S = 150.0    # how long a tapped connection's identity is remembered
TAP_RECHECK_S = 10.0   # re-verify the tap rules this often even if no task came or went
STALL_WARN_MS = 500    # warn once if a poll takes longer than this: events queue up behind it
_NOOP = shutil.which("true") or "/bin/true"
DISPATCH_QUEUE_MAX = 4096   # events waiting for delivery; beyond this they are DROPPED, loudly


def _note(msg: str) -> None:
    print(f"[net] {msg}", file=sys.stderr, flush=True)


def _norm(ip: str) -> str:
    """Unwrap ::ffff:a.b.c.d so a v6 socket and its v4 SYN compare equal."""
    try:
        a = ipaddress.ip_address(ip)
        return str(a.ipv4_mapped) if a.version == 6 and a.ipv4_mapped else str(a)
    except ValueError:
        return ip


def _cpu_stall_ms() -> Optional[float]:
    """Cumulative milliseconds in which at least one runnable task was waiting for a CPU (kernel PSI), or None
    where the kernel does not expose it. The difference across a sync says how oversubscribed the CPUs were."""
    try:
        with open("/proc/pressure/cpu") as f:
            for line in f:
                if line.startswith("some"):
                    return int(line.rsplit("total=", 1)[1]) / 1000.0
    except (OSError, ValueError, IndexError):
        pass
    return None


def _fork_exec_ms() -> float:
    """Wall time of a child process that does nothing, measured under the same load as the nft calls. It separates
    'nft is slow' from 'starting ANY process is slow' (-1 if it could not be measured)."""
    t = time.monotonic()
    try:
        subprocess.run([_NOOP], capture_output=True, timeout=10)
    except Exception:
        return -1.0
    return (time.monotonic() - t) * 1000.0


def _nft_only(ne: float, ce: float, cpu_pressure: Optional[float]) -> str:
    """The no-op child was barely delayed but nft was: say what that does and does NOT show. Forking staying fast
    does not mean the host is idle: load can reach nft's kernel transaction path (kernel threads such as RCU's and
    the kworkers compete with it) without slowing a fork. CPU pressure (PSI) tells the two apart."""
    head = f"nft's slowest call lost {ne:.0f} ms against its best, a no-op process only {ce:.0f} ms: "
    if cpu_pressure is not None and cpu_pressure >= 0.5:
        return head + (f"but the CPUs were oversubscribed during the sync (a task was waiting for a CPU "
                       f"{cpu_pressure:.0%} of it). That is load reaching nft's kernel transaction path (kernel "
                       f"threads such as RCU's and kworkers compete with it) even though forking stays fast; it is "
                       f"not evidence of commit contention")
    if cpu_pressure is not None and cpu_pressure < 0.10:
        return head + (f"and the CPUs were NOT oversubscribed ({cpu_pressure:.0%} pressure). This points at nft or "
                       f"the kernel's nftables transaction path itself: consistent with commit contention from other "
                       f"nft/netlink users, or a slow commit (for example waiting for an RCU grace period)")
    why = (f"CPU pressure {cpu_pressure:.0%}: inconclusive" if cpu_pressure is not None
           else "CPU pressure unavailable on this kernel")
    return head + f"this points at nft or the kernel's nftables transaction path; host load can still slow that path without slowing fork ({why})"


def diagnose(total_ms: float, lock_ms: float, nft_ms: float, slowest_ms: float, ctl_ms: float,
             ctl_base: Optional[float] = None, slow_base: Optional[float] = None,
             cpu_pressure: Optional[float] = None, total_base: Optional[float] = None) -> str:
    """Where a slow tap sync spent its time, in words. A heuristic: it says what the numbers SUGGEST.

    The lock wait is measured directly, so that verdict is firm. For nft the question is "what slowed it", and a
    bare comparison with the no-op child cannot answer it (an nft call costs several no-op processes even on an
    idle host). So compare EXTRA milliseconds against each one's own fastest this run (a no-op child going from
    1 ms to 4 ms is a x4 "slowdown" that is only jitter): what share of nft's extra delay does the child also
    suffer? Under 10% (and under 30 ms): nft alone, and then CPU pressure says whether the CPUs were oversubscribed
    anyway. Over 15%: the whole host. A busy many-core host can slow nft's commit WITHOUT slowing a fork."""
    # Fast outright, or within 2x of what this machine has shown before. But never for a sync that is itself a stall
    # (over the loud-note threshold): a machine that has only ever been slow must not call a 13 s sync "not slow".
    if total_ms < 100 or (total_base and total_ms <= 2 * total_base and total_ms < STALL_WARN_MS):
        return "not slow: nothing to explain"
    if lock_ms >= 0.5 * total_ms:
        return ("mostly waiting for the cross-process tap lock: another holder (e.g. cora-run installing rules) "
                "kept it that long")
    if nft_ms < 0.5 * total_ms:
        return "mostly neither the tap lock nor nft (Python, the GIL, or disk)"
    if ctl_ms < 0:
        return "nft is slow (the no-op control could not be measured, so host load cannot be ruled out)"
    if ctl_base and slow_base:
        ce, ne = max(ctl_ms - ctl_base, 0.0), max(slowest_ms - slow_base, 1.0)     # EXTRA delay, in ms, vs best seen
        if ce < 30 and ce <= 0.10 * ne:
            return _nft_only(ne, ce, cpu_pressure)
        if ce >= 0.15 * ne:
            return (f"a no-op process lost {ce:.0f} ms along with nft ({ne:.0f} ms): the whole host is slow "
                    f"(CPU or fork pressure), which is not a netlink problem")
        return (f"mixed: nft lost {ne:.0f} ms and a no-op process {ce:.0f} ms; host load is part of it but does "
                f"not explain all of it")
    if ctl_ms >= 50:                                 # no baseline yet: an absolute rule is all there is
        return "nft is slow AND so is starting a no-op process: the host is too busy to fork or schedule"
    return ("nft is slow while a no-op process started promptly (no idle baseline yet to compare against): "
            "inside nft or the kernel's nftables transaction path (host load can still slow it without slowing fork)")


class NetMonitor:
    def __init__(self, sentinel, interval: float = 0.1, slip_log: Optional[str] = None,
                 diag: Optional[SockDiag] = None, listener=None, cookie_cap: int = 50_000, tap=None):
        if sentinel.cgroups is None:
            raise ValueError("NetMonitor needs cgroup mode (--cgroup-root)")
        self.s, self.interval, self.cookie_cap, self.tap = sentinel, interval, cookie_cap, tap
        self.diag = diag or SockDiag()
        self._probe_cgroup_ids()                      # fail loudly, not silently blind
        if listener is None:
            try:
                listener = DestroyListener()
            except OSError as e:
                _note(f"destroy-event audit unavailable ({e}): sockets shorter than the poll "
                      f"interval cannot be detected" + ("" if tap else " or attributed"))
        self.listener = listener
        self._seen: "collections.OrderedDict[int, None]" = collections.OrderedDict()
        self._tap_tuples: Dict[tuple, float] = {}     # (sport, dst, dport) -> when: matches destroy events
        self._syn_ids: Dict[tuple, float] = {}        # (sport, dst, dport, ISN): one TCP connection ATTEMPT
        self._tap_checked = -1e9
        self._owners: Dict[str, tuple] = {}           # task -> (pid, argv, starttime) last seen ALIVE
        self.owner_diag: list = []                    # why an owner could not be resolved (first 20)
        # The event loop never blocks on nft, a file lock or the registry lock. Those go to two workers:
        self._dq: "queue.Queue" = queue.Queue(maxsize=DISPATCH_QUEUE_MAX)   # delivery (needs the registry lock)
        self._dthread: Optional[threading.Thread] = None
        self._sthread: Optional[threading.Thread] = None                    # tap rule sync (runs nft)
        self._sync_req = threading.Event()
        self._sync_lock = threading.Lock()
        self._sync_want: Optional[Dict[str, int]] = None
        self._sync_requested: Optional[Dict[str, int]] = None
        self.worst_sync: dict = {}                                          # the breakdown of the slowest sync
        self._ctl_base = self._slow_base = float('inf')                     # fastest no-op child / nft call seen
        self._total_base = float('inf')                                     # fastest whole sync seen
        self._sync_warn_at = 0.0
        self._tap_synced: Dict[str, int] = {}
        self._tap_err_at = -1e9
        self.listen_ports: set = set()
        self.stats: collections.Counter = collections.Counter()
        self.syn_by_task: collections.Counter = collections.Counter()
        self.udp_by_task: collections.Counter = collections.Counter()
        self._slip_f = open(slip_log, "a", buffering=1) if slip_log else None
        self._slip_logged: Dict[tuple, float] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---- setup ------------------------------------------------------------
    def _probe_cgroup_ids(self) -> None:
        """Make sure this kernel/privilege level reports cgroup ids; otherwise we would be blind."""
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", 0))
            probe.listen(1)
            port = probe.getsockname()[1]
            found = [k for k in self.diag.dump(states=1 << TCP_LISTEN, families=(socket.AF_INET,))
                     if k.local_port == port]
        finally:
            probe.close()
        if not found or found[0].cgroup_id is None:
            raise OSError(errno.ENOTSUP, "sock_diag reports no cgroup ids here "
                                         "(needs CAP_NET_ADMIN and a recent kernel)")

    # ---- shared helpers ---------------------------------------------------
    def _task_ids(self) -> Dict[int, str]:
        cg, ids = self.s.cgroups, {}
        for n in cg.names():
            try:
                ids[os.stat(cg.root / n).st_ino] = n       # cgroup id == directory inode
            except OSError:
                pass
        return ids

    def _remember(self, cookie: int) -> None:
        self._seen[cookie] = None
        self._seen.move_to_end(cookie)
        if len(self._seen) > self.cookie_cap:
            self._seen.popitem(last=False)

    @staticmethod
    def _why_unreadable(pid: int) -> str:
        """One line on why a pid in the task's cgroup could not be used (for the diagnostics)."""
        bits = [f"pid {pid}"]
        try:
            st = Path(f"/proc/{pid}/status").read_text()
            bits.append("state=" + next((l.split(None, 1)[1].strip() for l in st.splitlines() if l.startswith("State:")), "?"))
        except OSError as e:
            bits.append(f"no /proc entry ({e.__class__.__name__})")
        try:
            bits.append(f"cmdline_bytes={len(Path(f'/proc/{pid}/cmdline').read_bytes())}")
        except OSError as e:
            bits.append(f"cmdline unreadable ({e.__class__.__name__})")
        return " ".join(bits)

    def _resolve_owner(self, name: str, prefer: Optional[int] = None):
        """First LIVE member of the task: (pid, argv, starttime, reasons). In cgroup mode any live member
        will do (the action targets the task), so one unreadable pid (mid-exec, a zombie, a helper) must
        not cost us the event."""
        pids = list(self.s.cgroups.pids(name))
        if prefer in pids:
            pids.remove(prefer)
            pids.insert(0, prefer)
        reasons = []
        for pid in pids:
            argv, st = read_argv(pid), read_starttime(pid)
            if argv and st is not None:
                return pid, argv, st, reasons
            reasons.append(self._why_unreadable(pid))
        if not pids:
            reasons.append(f"task {name!r}: cgroup.procs empty")
        return None, None, None, reasons

    def _dispatch(self, name: str, prefer: Optional[int], j: dict, now: float, via: Optional[str]) -> None:
        pid, argv, st, reasons = self._resolve_owner(name, prefer)
        ev = dict(j["evidence"])
        if via:
            ev["via"] = via
        if pid is not None:
            self._owners[name] = (pid, argv, st)
        elif name in self._owners:
            # The tap attributed this flow to a KNOWN task that has since exited. Do not let the violation
            # vanish: report it from its last known identity. The gate still refuses to act on the dead
            # pid (start-time and cgroup checks), so nothing is ever done to a reused pid.
            pid, argv, st = self._owners[name]
            ev["owner_exited"] = True
            self.stats["owner_cached"] += 1
        else:
            self.stats["owner_gone"] += 1          # never seen alive and already gone: nothing to dispatch
            for r in reasons:
                if len(self.owner_diag) < 20:
                    self.owner_diag.append(r)
            if self.stats["owner_gone"] <= 3:
                _note(f"owner of task {name!r} unresolvable: {'; '.join(reasons) or 'unknown'}")
            self._log_slip({"kind": "task_exited_before_action", "attributed": True, "task": name,
                            "remote_ip": ev["remote_ip"], "remote_port": ev["remote_port"],
                            "blocklist": ev.get("blocklist"),
                            "note": "the task contacted this destination and no live process could be found for it"},
                           (ev["remote_ip"], ev["remote_port"]))
            return
        self._enqueue((name, pid, argv, st, j["severity"], ev, now))

    def _enqueue(self, item: tuple) -> None:
        """The owner's identity is captured NOW (cheap, from /proc). Delivery needs the registry lock, which
        the adjudicator holds while it runs nft, so it is handed to a worker: only delivery may wait."""
        if self._dthread is None:                    # no worker (unit tests, library use): deliver inline
            self._deliver(item)
            return
        try:
            self._dq.put_nowait(item)
        except queue.Full:
            self.stats["dispatch_dropped"] += 1
            n = self.stats["dispatch_dropped"]
            if n <= 3 or n % 1000 == 0:
                _note(f"dispatch queue full ({self._dq.maxsize}): event for task {item[0]!r} DROPPED "
                      f"(delivery is stalled; {n} dropped so far)")

    def _deliver(self, item: tuple) -> None:
        name, pid, argv, st, severity, ev, now = item
        payload = build_payload(pid, self.s.net.ensure(pid), " ".join(argv),
                                "unauthorized_connection", severity, ev, st, cgroup=name,
                                cgroup_id=self.s.cgroup_id_of(name))
        self.s._fire((name, "unauthorized_connection", ev["remote_ip"], ev["remote_port"], ev.get("qname")),
                     now, payload)

    def _dispatch_loop(self) -> None:
        while True:
            item = self._dq.get()
            try:
                if item is None:
                    return
                self._deliver(item)
            except Exception as e:
                self.stats["errors"] += 1
                _note(f"delivery error: {e!r}")
            finally:
                self._dq.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued event has been delivered."""
        end = time.monotonic() + timeout
        while self._dq.unfinished_tasks and time.monotonic() < end:
            time.sleep(0.005)
        return not self._dq.unfinished_tasks

    # ---- source 2: dumps --------------------------------------------------
    def poll_once(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        t_poll = time.monotonic()
        socks = self.diag.dump()
        if self.tap:
            # A socket enters SYN_SENT microseconds BEFORE its SYN is logged, so a dump can show a
            # connection whose tap message is still unread. By the time we have the dump in hand
            # that SYN has long been queued: drain it first, or the dump path would judge (and
            # dispatch) a connection the tap is about to attribute.
            self._drain_tap()
        self.stats["polls"] += 1
        ids = self._task_ids()
        if self.tap is not None:
            self._sync_tap({n: i for i, n in ids.items()})
        listen, by_task = set(), {}
        for k in socks:
            if k.cookie is not None:
                self._remember(k.cookie)
            if k.state == TCP_LISTEN:
                listen.add(k.local_port)
            elif k.remote_port and k.cgroup_id in ids:
                by_task.setdefault(ids[k.cgroup_id], []).append(k.row())
        self.listen_ports = listen
        for name in ids.values():
            for c in self.s.conn.scan_rows(("task", name), by_task.get(name, []), listen):
                ev = c["evidence"]
                if self.tap and (ev["local_port"], _norm(ev["remote_ip"]), ev["remote_port"]) in self._tap_tuples:
                    self.stats["dump_dup"] += 1    # its SYN was already tapped and dispatched
                    continue
                self.stats["live_hits"] += 1
                self._dispatch(name, self._owner(name, c.get("inode")), c, now, None)
        for key in [k for k in self.s.conn.seen
                    if isinstance(k, tuple) and k[:1] == ("task",) and k[1] not in ids.values()]:
            self.s.conn.forget(key)
        for name in ids.values():                    # remember who each task is while it is alive
            pid, argv, st, _ = self._resolve_owner(name)
            if pid is not None:
                self._owners[name] = (pid, argv, st)
        for name in [n for n in self._owners if n not in ids.values()]:
            del self._owners[name]
        ms = (time.monotonic() - t_poll) * 1000
        if ms > self.stats["poll_ms_max"]:
            self.stats["poll_ms_max"] = int(ms)
        if ms > STALL_WARN_MS and not self.stats["stall_warned"]:
            self.stats["stall_warned"] = 1
            _note(f"a poll took {ms:.0f} ms (> {STALL_WARN_MS}): events queue up behind it, and a short-lived "
                  f"task can exit before they are processed")

    def _owner(self, name: str, inode: Optional[int]) -> Optional[int]:
        pids = self.s.cgroups.pids(name)
        for pid in pids:
            if inode and inode in read_socket_inodes(pid):
                return pid
        return pids[0] if pids else None           # in cgroup mode the action targets the task anyway

    def _sync_tap(self, cur: Dict[str, int]) -> None:
        """Reconcile tap rules with the task set. Costs an nft call, so ONLY when the set changed."""
        now = time.monotonic()
        if cur == self._sync_requested and now - self._tap_checked < TAP_RECHECK_S:
            return                                   # unchanged and recently verified: no nft call
        self._sync_requested, self._tap_checked = dict(cur), now
        if self._sthread is None:                    # no worker (unit tests, library use): sync inline
            self._sync_now(cur)
            return
        with self._sync_lock:                        # the worker applies only the LATEST wanted state
            self._sync_want = dict(cur)
        self._sync_req.set()

    def _sync_now(self, cur: Dict[str, int]) -> None:
        ctl = _fork_exec_ms()                        # control: is starting a process slow right now?
        psi0 = _cpu_stall_ms()                       # and: were the CPUs oversubscribed during the sync?
        t = time.monotonic()
        try:
            added, removed = self.tap.sync(cur)      # runs nft under a cross-process lock; also repairs damage
            self._tap_synced = dict(cur)
            self.stats["tap_installed"] += len(added)
        except Exception as e:
            self.stats["errors"] += 1
            self._sync_requested = None              # force a retry on the next poll
            if time.monotonic() - self._tap_err_at > 30:      # retry often, complain every 30 s
                self._tap_err_at = time.monotonic()
                _note(f"tap rule sync failed: {e}")
        finally:
            psi1 = _cpu_stall_ms()
            self._record_sync((time.monotonic() - t) * 1000.0, ctl, dict(getattr(self.tap, "last_timing", None) or {}),
                              (psi1 - psi0) if psi0 is not None and psi1 is not None else None)

    def _record_sync(self, ms: float, ctl: float, tm: dict, cpu_stall_ms: Optional[float] = None) -> None:
        """Split one sync into lock wait / nft / other, keep the maxima and the worst case, and say so loudly
        when it was slow: that is the evidence for WHY a tap rule was late."""
        lock, nft, slow = tm.get("lock_ms", 0.0), tm.get("nft_ms", 0.0), tm.get("nft_slowest_ms", 0.0)
        for k, v in (("tap_sync_ms_max", ms), ("tap_lock_wait_ms_max", lock), ("tap_nft_ms_max", nft),
                     ("tap_nft_call_ms_max", slow), ("tap_ctl_ms_max", ctl)):
            if int(v) > self.stats[k]:
                self.stats[k] = int(v)
        pressure = None if cpu_stall_ms is None or ms <= 0 else min(max(cpu_stall_ms / ms, 0.0), 1.0)
        if pressure is not None and int(pressure * 100) > self.stats["tap_cpu_pressure_pct_max"]:
            self.stats["tap_cpu_pressure_pct_max"] = int(pressure * 100)
        prior_total = self._total_base                  # the baseline from EARLIER syncs: this one must not define it
        self._total_base = min(self._total_base, ms)
        if ctl > 0:
            self._ctl_base = min(self._ctl_base, ctl)
        if slow > 0:
            self._slow_base = min(self._slow_base, slow)
        this = {"total_ms": ms, "lock_ms": lock, "nft_ms": nft, "calls": tm.get("nft_calls", 0),
                "slowest_ms": slow, "ctl_ms": ctl, "slowest_cmd": tm.get("nft_slowest_cmd", ""),
                "cpu_pressure": pressure,
                "total_base": prior_total if prior_total != float("inf") else None,
                "ctl_base": self._ctl_base if self._ctl_base != float("inf") else None,
                "slow_base": self._slow_base if self._slow_base != float("inf") else None}
        if ms >= self.worst_sync.get("total_ms", -1.0):
            self.worst_sync = this
        if ms > STALL_WARN_MS and time.monotonic() - self._sync_warn_at > 30:
            self._sync_warn_at = time.monotonic()
            _note(self._describe(this))                 # the sync that WAS slow, not merely the worst so far

    @staticmethod
    def _describe(w: dict) -> str:
        other = max(w["total_ms"] - w["lock_ms"] - w["nft_ms"], 0.0)
        cmd = f" [{w['slowest_cmd']}]" if w.get("slowest_cmd") else ""
        press = f" CPU pressure during it: {w['cpu_pressure']:.0%}." if w.get("cpu_pressure") is not None else ""
        return (f"tap sync took {w['total_ms']:.0f} ms = lock wait {w['lock_ms']:.0f} + nft {w['nft_ms']:.0f} "
                f"({w['calls']} calls, slowest {w['slowest_ms']:.0f}{cmd}) + other {other:.0f}; a no-op child took "
                f"{w['ctl_ms']:.0f} ms.{press} Suggests: "
                f"{diagnose(w['total_ms'], w['lock_ms'], w['nft_ms'], w['slowest_ms'], w['ctl_ms'], w.get('ctl_base'), w.get('slow_base'), w.get('cpu_pressure'), w.get('total_base'))}")

    def _sync_loop(self) -> None:
        while not self._stop.is_set():
            if not self._sync_req.wait(0.5):
                continue
            self._sync_req.clear()
            with self._sync_lock:
                want = self._sync_want
            if want is not None:
                self._sync_now(want)

    # ---- source 1: SYN tap ------------------------------------------------
    def _drain_tap(self) -> None:
        for _ in range(1000):                       # bounded so a flood cannot starve the loop
            batch = self.tap.listener.poll(0)
            if not batch:
                return
            for syn in batch:
                self._on_syn(syn)

    def _on_udp(self, syn, now: float) -> None:
        """First packet of a UDP flow. The kernel's once-per-flow set already deduped it, and sock_diag
        has no UDP view, so there is nothing to cross-check or coalesce: judge it and dispatch."""
        self.stats["udp"] += 1
        self.udp_by_task[syn.task] += 1
        if syn.l7:
            self.stats[f"udp_{syn.l7}"] += 1
        j = self.s.conn.judge(syn.dst, syn.dport, syn.sport, proto="udp", l7=syn.l7, qname=syn.qname)
        if j is None:
            return
        self.stats["udp_hits"] += 1
        self._dispatch(syn.task, None, j, now, "udp_tap")

    def _on_syn(self, syn) -> None:
        now = time.monotonic()
        if syn.proto == "udp":
            return self._on_udp(syn, now)
        key = (syn.sport, _norm(syn.dst), syn.dport)
        # A SYN, its retransmits (a full accept queue) and any duplicate message (a duplicated tap
        # rule) all share one initial sequence number; a NEW connection that reuses the port does not.
        # Keying on the ISN, not just the 3-tuple, means a straggler arriving after the socket's
        # destroy event is still recognised, and a genuine port reuse is never swallowed.
        ident = key + (syn.seq,)
        if now - self._syn_ids.get(ident, -1e9) < TUPLE_TTL_S:
            self.stats["syn_retrans"] += 1
            return
        self._syn_ids[ident] = now
        self.stats["syn"] += 1
        self.syn_by_task[syn.task] += 1
        self._tap_tuples[key] = now
        if len(self._syn_ids) > 100_000:
            self._syn_ids = {k: t for k, t in self._syn_ids.items() if now - t < TUPLE_TTL_S}
        if len(self._tap_tuples) > 100_000:
            self._tap_tuples = {k: t for k, t in self._tap_tuples.items() if now - t < TUPLE_TTL_S}
        j = self.s.conn.judge(syn.dst, syn.dport, syn.sport)
        if j is None:
            return
        self.stats["syn_hits"] += 1
        self._dispatch(syn.task, None, j, now, "syn_tap")

    # ---- source 3: destroy events (audit) ----------------------------------
    def _on_destroy(self, k) -> None:
        self.stats["destroyed"] += 1
        if k.cookie is not None and self._seen.pop(k.cookie, "absent") != "absent":
            return                                  # a dump already saw and judged this socket
        if not k.remote_port or k.local_port in self.listen_ports:
            return                                  # not an outbound connection
        if self._tap_tuples.pop((k.local_port, _norm(k.remote_ip), k.remote_port), None) is not None:
            self.stats["tap_handled"] += 1          # its SYN was tapped and attributed: not a slip
            return
        bl = self.s.conn.blocklist
        hit = bl.match_ip(k.remote_ip) if bl else None
        if hit is None:
            return
        self.stats["slips"] += 1
        self._log_slip({"kind": "slipped_connection", "attributed": False,
                        "remote_ip": k.remote_ip, "remote_port": k.remote_port,
                        "local_port": k.local_port, "uid": k.uid, "blocklist": hit._asdict(),
                        "note": "closed before any poll saw it; destroy events carry no cgroup id, so no task can be named"},
                       (k.remote_ip, k.remote_port))

    def _log_slip(self, rec: dict, key: tuple) -> None:
        now = time.monotonic()
        if now - self._slip_logged.get(key, -1e9) < SLIP_RATE_S:
            return
        self._slip_logged[key] = now
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **rec}
        if self._slip_f:
            self._slip_f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        bl = rec.get("blocklist") or {}
        _note(f"{rec['kind'].upper().replace('_', ' ')}: {rec['remote_ip']}:{rec['remote_port']}"
              f"{' on ' + repr(bl.get('list')) if bl else ''}"
              f"{' (unattributed)' if not rec['attributed'] else ''}")

    # ---- loop -------------------------------------------------------------
    def _run(self) -> None:
        socks = [x.s for x in ((self.tap.listener if self.tap else None), self.listener) if x]
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                self.poll_once(t0)
            except Exception as e:                  # a bad poll must not kill monitoring
                self.stats["errors"] += 1
                _note(f"poll error: {e!r}")
            deadline = t0 + self.interval
            while not self._stop.is_set():
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                if socks:
                    select.select(socks, [], [], min(rem, 0.05))
                else:
                    time.sleep(min(rem, 0.05))
                try:
                    if self.tap:
                        self._drain_tap()           # ALWAYS before destroy events (see module doc)
                    if self.listener:
                        for k in self.listener.poll(0):
                            self._on_destroy(k)
                except Exception as e:
                    self.stats["errors"] += 1
                    _note(f"event error: {e!r}")

    def start(self) -> None:
        if self.tap is not None:
            self._sthread = threading.Thread(target=self._sync_loop, name="netmon-tapsync", daemon=True)
            self._sthread.start()
        self._dthread = threading.Thread(target=self._dispatch_loop, name="netmon-deliver", daemon=True)
        self._dthread.start()
        self._thread = threading.Thread(target=self._run, name="netmon", daemon=True)
        self._thread.start()

    def lost(self) -> int:
        return (self.listener.lost if self.listener else 0) + (self.tap.listener.lost if self.tap else 0)

    def summary(self) -> str:
        s = self.stats
        tap = (f" syn={s['syn']} syn_retrans={s['syn_retrans']} syn_hits={s['syn_hits']} "
               f"tap_handled={s['tap_handled']} udp={s['udp']} udp_dns={s['udp_dns']} "
               f"udp_quic={s['udp_quic']} udp_hits={s['udp_hits']}"
               if self.tap else "")
        return (f"polls={s['polls']} live_hits={s['live_hits']}{tap} slips={s['slips']} "
                f"destroyed_seen={s['destroyed']} owner_gone={s['owner_gone']} "
                f"owner_cached={s['owner_cached']} dispatch_dropped={s['dispatch_dropped']} errors={s['errors']} "
                f"poll_ms_max={s['poll_ms_max']} tap_sync_ms_max={s['tap_sync_ms_max']} "
                f"(lock_wait_max={s['tap_lock_wait_ms_max']} nft_max={s['tap_nft_ms_max']} "
                f"slowest_nft_call={s['tap_nft_call_ms_max']} noop_child_max={s['tap_ctl_ms_max']} "
                f"cpu_pressure_max={s['tap_cpu_pressure_pct_max']}%) "
                f"LOST={self.lost()}"
                + (f" | worst_tap_sync: {self._describe(self.worst_sync)}"
                   if self.worst_sync.get("total_ms", 0) > STALL_WARN_MS else ""))

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._dthread:                            # let queued events be delivered before we stop
            try:
                self._dq.put(None, timeout=2)
            except queue.Full:
                pass
            self._dthread.join(timeout=5)
        if self._sthread:
            self._sthread.join(timeout=2)
        _note(self.summary())
        for c in (self.diag, self.listener):
            try:
                c and c.close()
            except Exception:
                pass
        if self.tap:
            try:
                self.tap.close()
            except Exception as e:
                _note(f"tap teardown: {e}")
