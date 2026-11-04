#!/usr/bin/env python3
"""
cora_netmon.py - connection monitor for cora_sentinel (cgroup mode). One thread, one loop.

Three sources, strongest first:

  1. SYN tap (cora_nflog, optional)   fires at connect() time. The kernel names the TASK by
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
    provided the task's rule exists. cora_run.py installs it before exec (no gap); otherwise the
    monitor installs it within one poll interval. TCP only; needs root and nfnetlink_log.
  * Without the tap: detection cannot slip, but attribution only exists for sockets that a dump
    saw alive (see test_cora_sockdiag.py for the measured lifetime boundary).
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
import select
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from cora_sentinel import build_payload, read_argv, read_socket_inodes, read_starttime
from cora_sockdiag import TCP_LISTEN, DestroyListener, SockDiag

SLIP_RATE_S = 60.0     # log each (ip, port) slip at most once per minute; all are still counted
TUPLE_TTL_S = 150.0    # how long a tapped connection's 3-tuple is remembered for destroy matching


def _note(msg: str) -> None:
    print(f"[net] {msg}", file=sys.stderr, flush=True)


def _norm(ip: str) -> str:
    """Unwrap ::ffff:a.b.c.d so a v6 socket and its v4 SYN compare equal."""
    try:
        a = ipaddress.ip_address(ip)
        return str(a.ipv4_mapped) if a.version == 6 and a.ipv4_mapped else str(a)
    except ValueError:
        return ip


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
        self._tap_tuples: Dict[tuple, float] = {}
        self._tap_synced: Dict[str, int] = {}
        self._tap_err_at = -1e9
        self.listen_ports: set = set()
        self.stats: collections.Counter = collections.Counter()
        self.syn_by_task: collections.Counter = collections.Counter()
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

    def _dispatch(self, name: str, pid: Optional[int], j: dict, now: float, via: Optional[str]) -> None:
        argv = read_argv(pid) if pid else None
        st = read_starttime(pid) if pid else None
        ev = dict(j["evidence"])
        if via:
            ev["via"] = via
        if not argv or st is None:
            self.stats["owner_gone"] += 1          # the task emptied out under us: nothing to act on
            self._log_slip({"kind": "task_exited_before_action", "attributed": True, "task": name,
                            "remote_ip": ev["remote_ip"], "remote_port": ev["remote_port"],
                            "blocklist": ev.get("blocklist"),
                            "note": "the task contacted this destination and had exited by the time it was processed"},
                           (ev["remote_ip"], ev["remote_port"]))
            return
        payload = build_payload(pid, self.s.net.ensure(pid), " ".join(argv),
                                "unauthorized_connection", j["severity"], ev, st, cgroup=name)
        self.s._fire((name, "unauthorized_connection", ev["remote_ip"], ev["remote_port"]), now, payload)

    # ---- source 2: dumps --------------------------------------------------
    def poll_once(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
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

    def _owner(self, name: str, inode: Optional[int]) -> Optional[int]:
        pids = self.s.cgroups.pids(name)
        for pid in pids:
            if inode and inode in read_socket_inodes(pid):
                return pid
        return pids[0] if pids else None           # in cgroup mode the action targets the task anyway

    def _sync_tap(self, cur: Dict[str, int]) -> None:
        """Reconcile tap rules with the task set. Costs an nft call, so ONLY when the set changed."""
        if cur == self._tap_synced:
            return
        try:
            added, removed = self.tap.sync(cur)
            self._tap_synced = dict(cur)
            self.stats["tap_installed"] += len(added)
        except Exception as e:
            self.stats["errors"] += 1
            if time.monotonic() - self._tap_err_at > 30:      # retry every poll, complain every 30 s
                self._tap_err_at = time.monotonic()
                _note(f"tap rule sync failed: {e}")

    # ---- source 1: SYN tap ------------------------------------------------
    def _drain_tap(self) -> None:
        for _ in range(1000):                       # bounded so a flood cannot starve the loop
            batch = self.tap.listener.poll(0)
            if not batch:
                return
            for syn in batch:
                self._on_syn(syn)

    def _on_syn(self, syn) -> None:
        now = time.monotonic()
        key = (syn.sport, _norm(syn.dst), syn.dport)
        if now - self._tap_tuples.get(key, -1e9) < TUPLE_TTL_S:
            self.stats["syn_retrans"] += 1          # TCP retransmitting a SYN (e.g. full accept queue):
            return                                  # same connection, already counted and dispatched
        self.stats["syn"] += 1
        self.syn_by_task[syn.task] += 1
        self._tap_tuples[key] = now
        if len(self._tap_tuples) > 100_000:
            self._tap_tuples = {k: t for k, t in self._tap_tuples.items() if now - t < TUPLE_TTL_S}
        j = self.s.conn.judge(syn.dst, syn.dport, syn.sport)
        if j is None:
            return
        self.stats["syn_hits"] += 1
        pids = self.s.cgroups.pids(syn.task)
        self._dispatch(syn.task, pids[0] if pids else None, j, now, "syn_tap")

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
        self._thread = threading.Thread(target=self._run, name="netmon", daemon=True)
        self._thread.start()

    def lost(self) -> int:
        return (self.listener.lost if self.listener else 0) + (self.tap.listener.lost if self.tap else 0)

    def summary(self) -> str:
        s = self.stats
        tap = (f" syn={s['syn']} syn_retrans={s['syn_retrans']} syn_hits={s['syn_hits']} "
               f"tap_handled={s['tap_handled']}"
               if self.tap else "")
        return (f"polls={s['polls']} live_hits={s['live_hits']}{tap} slips={s['slips']} "
                f"destroyed_seen={s['destroyed']} owner_gone={s['owner_gone']} "
                f"errors={s['errors']} LOST={self.lost()}")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
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
