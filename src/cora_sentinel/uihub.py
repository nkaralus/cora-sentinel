"""
cora_sentinel.uihub - the daemon's read-only status feed for desktop clients (cora-tray). Stdlib only.

    cora-sentinel --ui-socket /run/cora-sentinel/ui.sock --ui-group cora

The daemon never waits on a client. A thread owns the socket; the daemon only calls the note_*() methods, which take a
lock for microseconds and return. Every client gets newline-delimited JSON:

    {"schema": "cora.sentinel.ui/v1", "type": "state", "seq": N, "ts": "...", "status": "clear|evaluating|contained|alarm",
     "mode": "enforce|dry-run|detect-only", "evaluating": K, "tasks": [...], "session": {...}}

sent on every change (at most 4 a second) and as a heartbeat every 2 s even when nothing changed. A client that hears
nothing for longer than STALE_AFTER_S must show "unreachable", never the last colour: a dead daemon must not look clear.

Status precedence (the worst wins):
  alarm       an event was DROPPED without being contained, or an action FAILED, this session (stays until restart:
              the operator has to look at the log; a light that heals itself hides exactly the event that mattered)
  contained   at least one live task is isolated, throttled or suspended right now
  evaluating  the model has events queued or in flight
  clear       none of the above

The socket lives in /run/cora-sentinel (systemd RuntimeDirectory, root-owned), never in /tmp, where any local user
could create the path first and impersonate the daemon. It is mode 0660, group --ui-group; without a group, 0600 (root
only). Each connection's uid is read with SO_PEERCRED and logged.

EMERGENCY BREAKERS: a one-way ratchet. A client may send one JSON line
    {"cmd": "sever" | "cap", "task": NAME, "cgroup_id": ID, "id": "client-chosen tag"}
"sever" is ISOLATE (nft drops the task's egress), "cap" is THROTTLE (memory.high = current, cpu.max 20%). Nothing that
loosens exists here: releasing stays root-only on the command line (`cora-firewall release`, `cora-cgroup`). A command
is accepted only from uid 0 or a member of --ui-group (checked with SO_PEERCRED, on top of the socket's mode), for a
task that is live AND still the same cgroup (`cgroup_id` from the snapshot: a relaunch under the same name is refused),
at most one per second per client and MAX_ACTIONS at once. It runs in its own thread, so a slow nft never stalls the
feed, and it acts even when the daemon is in dry-run: a person pressing the button is an explicit override, recorded
as policy "manual_operator_override" with the operator's uid. The reply is {"type": "result", "id": ..., "ok": ...}.
"""
from __future__ import annotations

import grp
import pwd
import json
import os
import re
import selectors
import socket
import stat
import struct
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

SCHEMA = "cora.sentinel.ui/v1"
HEARTBEAT_S = 2.0
MIN_INTERVAL_S = 0.25
STALE_AFTER_S = 3 * HEARTBEAT_S
MAX_CLIENTS = 8
MAX_OUTBUF = 256 * 1024
MAX_LINE_IN = 1024
COMMANDS = {"sever": "ISOLATE", "cap": "THROTTLE"}      # tighten only: there is deliberately no "release" here
MAX_ACTIONS = 4
COMMAND_INTERVAL_S = 1.0
MANUAL_POLICY = "manual_operator_override"
COMMUNITY_PREFIX = "community-"
ACTION_RE = re.compile(r"^(done|dry-run):(ISOLATE|THROTTLE|SUSPEND|TERMINATE)@cgroup:(.+?)(\[.*\])?$")
CONTAINING = ("ISOLATE", "THROTTLE", "SUSPEND")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def peer_uid(conn: socket.socket) -> Optional[int]:
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", creds)[1]
    except OSError:
        return None


class Hub:
    def __init__(self, path: str, group: Optional[str] = None, mode: str = "detect-only",
                 tasks: Optional[Callable[[], Dict[str, dict]]] = None,
                 evaluating: Optional[Callable[[], int]] = None,
                 cgroup_id: Optional[Callable[[str], Optional[int]]] = None,
                 act: Optional[Callable[[str, str], str]] = None,
                 record: Optional[Callable[[dict], None]] = None,
                 log: Callable[[str], None] = lambda m: print(f"[ui] {m}", file=sys.stderr, flush=True),
                 clock: Callable[[], float] = time.monotonic):
        self.path, self.group, self.mode, self.log, self.clock = Path(path), group, mode, log, clock
        self._tasks_fn = tasks or (lambda: {})
        self._eval_fn = evaluating or (lambda: 0)
        self._id_fn = cgroup_id or (lambda name: None)
        self._act, self._record = act, record
        self._gid: Optional[int] = None
        self._results: List[tuple] = []           # (conn, reply) finished by action threads, sent by the hub thread
        self._acting = 0
        self._lock = threading.Lock()
        self._contained: Dict[str, tuple] = {}     # task -> (cgroup id when acted on, {"ISOLATE": "done"|"dry-run"})
        self._baseline: Dict[str, int] = {}        # task -> memory.current when first seen
        self.session = {"started": _now_iso(), "blocked_total": 0, "community_blocked": 0, "contained_actions": 0,
                        "dropped_uncontained": 0, "failed_actions": 0, "manual_overrides": 0}
        self._dirty = True
        self._seq = 0
        self._sock: Optional[socket.socket] = None
        self._clients: Dict[socket.socket, dict] = {}
        self._sel = selectors.DefaultSelector()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._wake_r, self._wake_w = os.pipe()

    # ------------------------------------------------------------------ fed by the daemon (cheap, never block)
    def note_event(self, ev: dict) -> None:
        """Every detection the daemon emits."""
        try:
            bl = ev["anomaly"]["evidence"].get("blocklist")
        except (KeyError, TypeError, AttributeError):
            return
        if not bl:
            return
        with self._lock:
            self.session["blocked_total"] += 1
            if str(bl.get("list", "")).startswith(COMMUNITY_PREFIX):
                self.session["community_blocked"] += 1
            self._dirty = True
        self._wake()

    def note_decision(self, d: dict) -> None:
        """Every decision record the adjudicator writes (its `sink`)."""
        actions = [d.get("action") or ""]
        ids = {}
        for a in actions + [((d.get("contained_first") or {}) if isinstance(d.get("contained_first"), dict) else {}).get("action") or ""]:
            m = ACTION_RE.match(a)
            if m:
                ids[m.group(3)] = self._id_fn(m.group(3))     # outside the lock: a stat()
        early = d.get("contained_first")
        if isinstance(early, dict) and early.get("action"):
            actions.append(early["action"])
        with self._lock:
            if d.get("final") == "DROPPED" or (d.get("queue_dropped") and d.get("final") != "ISOLATE"):
                self.session["dropped_uncontained"] += 1
            manual = d.get("policy") == MANUAL_POLICY
            if manual and d.get("action", "").startswith(("done:", "dry-run:")):
                self.session["manual_overrides"] += 1
            for a in actions:
                if a.startswith("failed:") and not manual:
                    self.session["failed_actions"] += 1
                m = ACTION_RE.match(a)
                if m and m.group(2) in CONTAINING:
                    name, cid = m.group(3), ids.get(m.group(3))
                    prev = self._contained.get(name)
                    if prev is None or prev[0] != cid:
                        prev = (cid, {})
                    if prev[1].get(m.group(2)) != "done":          # done beats dry-run, never the reverse
                        prev[1][m.group(2)] = m.group(1)
                    self._contained[name] = prev
                    self.session["contained_actions"] += 1
            self._dirty = True
        self._wake()

    # ------------------------------------------------------------------ the snapshot
    def snapshot(self) -> dict:
        live = self._tasks_fn()                          # {name: {"pids": n, "mem_bytes": b | None}}
        evaluating = int(self._eval_fn() or 0)
        with self._lock:
            for name in list(self._contained):
                # gone, or the same NAME on a NEW cgroup (a relaunch): what was done to the old one does not carry over
                if name not in live or live[name].get("id") != self._contained[name][0]:
                    del self._contained[name]
            for name in list(self._baseline):
                if name not in live:
                    del self._baseline[name]
            tasks = []
            for name in sorted(live):
                info = live[name]
                mem = info.get("mem_bytes")
                if mem is not None:
                    self._baseline.setdefault(name, mem)
                tasks.append({"name": name, "cgroup_id": info.get("id"), "pids": info.get("pids", 0), "mem_bytes": mem,
                              "mem_delta_bytes": None if mem is None else mem - self._baseline[name],
                              "contained": sorted(self._contained[name][1]) if name in self._contained else [],
                              # what was really done (not dry-run): the tray offers a breaker only if it is not here
                              "enforced": sorted(v for v, k in self._contained[name][1].items() if k == "done")
                                          if name in self._contained else []})
            s = dict(self.session)
            if s["dropped_uncontained"] or s["failed_actions"]:
                status = "alarm"
            elif any(t["contained"] for t in tasks):
                status = "contained"
            elif evaluating:
                status = "evaluating"
            else:
                status = "clear"
            self._seq += 1
            return {"schema": SCHEMA, "type": "state", "seq": self._seq, "ts": _now_iso(), "status": status,
                    "mode": self.mode, "evaluating": evaluating, "tasks": tasks, "session": s,
                    "breakers": sorted(COMMANDS) if self._act else []}

    # ------------------------------------------------------------------ socket
    def start(self) -> None:
        self._bind()
        self._thread = threading.Thread(target=self._loop, name="ui-hub", daemon=True)
        self._thread.start()

    def _bind(self) -> None:
        d = self.path.parent
        st = d.stat()
        if st.st_mode & stat.S_IWOTH or (os.geteuid() == 0 and st.st_uid != 0):
            raise OSError(f"{d}: must be root-owned and not world-writable (use systemd RuntimeDirectory=cora-sentinel)")
        try:
            if stat.S_ISSOCK(self.path.lstat().st_mode):
                self.path.unlink()                       # our own stale socket from a previous run
            else:
                raise OSError(f"{self.path} exists and is not a socket: refusing to replace it")
        except FileNotFoundError:
            pass
        gid = None
        if self.group:
            try:
                gid = grp.getgrnam(self.group).gr_gid
            except KeyError:
                raise OSError(f"--ui-group {self.group!r}: no such group (groupadd {self.group}; usermod -aG {self.group} YOU)")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)                            # born 0600: never briefly open to everyone
        try:
            s.bind(str(self.path))
        finally:
            os.umask(old)
        self._gid = gid
        if gid is not None:
            os.chown(self.path, -1, gid)
            os.chmod(self.path, 0o660)
        s.listen(MAX_CLIENTS)
        s.setblocking(False)
        self._sock = s
        self._sel.register(s, selectors.EVENT_READ, "accept")
        self._sel.register(self._wake_r, selectors.EVENT_READ, "wake")
        self.log(f"status feed on {self.path} ({'group ' + self.group + ', 0660' if gid is not None else 'root only, 0600'})")

    def _wake(self) -> None:
        try:
            os.write(self._wake_w, b"x")
        except (BlockingIOError, OSError):
            pass

    def _loop(self) -> None:
        last_sent = 0.0
        while not self._stop.is_set():
            for key, ev in self._sel.select(timeout=MIN_INTERVAL_S):
                if key.data == "accept":
                    self._accept()
                elif key.data == "wake":
                    try:
                        os.read(self._wake_r, 4096)
                    except BlockingIOError:
                        pass
                elif key.data == "client":
                    if ev & selectors.EVENT_READ:
                        self._read(key.fileobj)
                    if ev & selectors.EVENT_WRITE and key.fileobj in self._clients:
                        self._flush(key.fileobj)
            with self._lock:
                done, self._results = self._results, []
            for conn, reply in done:
                if conn in self._clients:
                    self._send(conn, reply)
            now = self.clock()
            with self._lock:
                dirty = self._dirty
            if self._clients and ((dirty and now - last_sent >= MIN_INTERVAL_S) or now - last_sent >= HEARTBEAT_S):
                with self._lock:
                    self._dirty = False
                self._broadcast(self.snapshot())
                last_sent = now

    def _accept(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except (BlockingIOError, OSError):
            return
        if len(self._clients) >= MAX_CLIENTS:
            conn.close()
            self.log(f"refused a client: {MAX_CLIENTS} already connected")
            return
        conn.setblocking(False)
        uid = peer_uid(conn)
        self._clients[conn] = {"out": bytearray(), "uid": uid, "inbuf": b"", "last_cmd": -1e9}
        self._sel.register(conn, selectors.EVENT_READ, "client")
        self.log(f"client connected (uid {uid})")
        self._send(conn, self.snapshot())                # a new client gets the picture at once

    def _read(self, conn) -> None:
        try:
            data = conn.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            self._drop(conn, "disconnected")
            return
        c = self._clients[conn]
        c["inbuf"] += data
        while b"\n" in c["inbuf"]:
            line, c["inbuf"] = c["inbuf"].split(b"\n", 1)
            if len(line) > MAX_LINE_IN:
                self._drop(conn, "sent an oversized line")
                return
            self._command(conn, line)
            if conn not in self._clients:
                return
        if len(c["inbuf"]) > MAX_LINE_IN:
            self._drop(conn, "sent an oversized line")

    def may_command(self, uid: Optional[int]) -> bool:
        if uid == 0:
            return True
        if uid is None or self._gid is None:
            return False
        try:
            pw = pwd.getpwuid(uid)
            return self._gid in os.getgrouplist(pw.pw_name, pw.pw_gid)
        except (KeyError, OSError):
            return False

    def _command(self, conn, line: bytes) -> None:
        c = self._clients[conn]
        try:
            msg = json.loads(line)
        except ValueError:
            msg = None
        tag = msg.get("id") if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int)) else None
        tag = str(tag)[:64] if tag is not None else None

        def refuse(why: str) -> None:
            self._send(conn, {"schema": SCHEMA, "type": "result", "id": tag, "ok": False, "error": why})

        if not isinstance(msg, dict):
            return refuse("not a JSON object")
        cmd, task = msg.get("cmd"), msg.get("task")
        if cmd not in COMMANDS:
            return refuse(f"unknown command {cmd!r}: the tray can only tighten ({', '.join(sorted(COMMANDS))}); "
                          "releasing is root-only: cora-firewall release / cora-cgroup")
        if not self.may_command(c["uid"]):
            self.log(f"refused {cmd} from uid {c['uid']}: not root and not in --ui-group")
            return refuse("not permitted: you are not in the --ui-group group")
        if self._act is None:
            return refuse("breakers unavailable: cora-sentinel runs without --cgroup-root")
        now = self.clock()
        if now - c["last_cmd"] < COMMAND_INTERVAL_S:
            return refuse("slow down: one command per second")
        live = self._tasks_fn()
        if not isinstance(task, str) or task not in live:
            return refuse(f"no live task named {task!r}")
        if live[task].get("id") != msg.get("cgroup_id"):
            return refuse(f"{task} is not the task you saw (it exited or was relaunched): look again")
        with self._lock:
            if self._acting >= MAX_ACTIONS:
                return refuse("busy: too many breakers already running")
            self._acting += 1
        c["last_cmd"] = now
        verdict, uid = COMMANDS[cmd], c["uid"]
        self.log(f"uid {uid} pressed {cmd} on {task}")
        threading.Thread(target=self._run_action, args=(conn, tag, verdict, task, uid),
                         name=f"ui-{cmd}", daemon=True).start()

    def _run_action(self, conn, tag, verdict: str, task: str, uid) -> None:
        try:
            try:
                action = self._act(verdict, task)
            except Exception as e:                       # never kill the hub over one button
                action = f"failed:{e.__class__.__name__}@cgroup:{task}"
            d = {"ts": _now_iso(), "event_id": f"manual-{uuid.uuid4().hex[:12]}", "pid": 0, "vip": None,
                 "kind": "manual", "mode": self.mode, "final": verdict, "policy": MANUAL_POLICY,
                 "action": action, "operator_uid": uid, "task": task, "model": None}
            if self._record:
                try:
                    self._record(d)
                except Exception as e:
                    self.log(f"could not record the manual action: {e!r}")
            self.note_decision(d)
            ok = action.startswith("done:")
            reply = {"schema": SCHEMA, "type": "result", "id": tag, "ok": ok, "action": action}
            if not ok:
                reply["error"] = action
        finally:
            with self._lock:
                self._acting -= 1
        with self._lock:
            self._results.append((conn, reply))
        self._wake()

    def _send(self, conn, msg: dict) -> None:
        c = self._clients.get(conn)
        if c is None:
            return
        c["out"] += (json.dumps(msg, separators=(",", ":")) + "\n").encode()
        if len(c["out"]) > MAX_OUTBUF:
            self._drop(conn, "too slow to read; dropped so it cannot stall the daemon")
            return
        self._flush(conn)

    def _flush(self, conn) -> None:
        c = self._clients[conn]
        try:
            n = conn.send(c["out"])
            del c["out"][:n]
        except (BlockingIOError, InterruptedError):
            pass
        except OSError:
            self._drop(conn, "write failed")
            return
        want = selectors.EVENT_READ | (selectors.EVENT_WRITE if c["out"] else 0)
        self._sel.modify(conn, want, "client")

    def _broadcast(self, msg: dict) -> None:
        for conn in list(self._clients):
            self._send(conn, msg)

    def _drop(self, conn, why: str) -> None:
        c = self._clients.pop(conn, None)
        try:
            self._sel.unregister(conn)
        except (KeyError, ValueError):
            pass
        conn.close()
        self.log(f"client (uid {c and c['uid']}) {why}")

    def stop(self) -> None:
        self._stop.set()
        self._wake()
        if self._thread:
            self._thread.join(timeout=2)
        for conn in list(self._clients):
            self._drop(conn, "daemon stopping")
        if self._sock:
            self._sock.close()
            try:
                self.path.unlink()
            except OSError:
                pass


def cgroup_tasks(cg) -> Callable[[], Dict[str, dict]]:
    """Live tasks and their memory, read from the cgroup tree (memory.current is the whole subtree)."""
    def read() -> Dict[str, dict]:
        out = {}
        try:
            names = cg.names()
        except OSError:
            return out
        for name in names:
            mem = None
            try:
                mem = int((cg._dir(name) / "memory.current").read_text())
            except (OSError, ValueError):
                pass
            try:
                pids = len(cg.pids(name))
            except OSError:
                pids = 0
            out[name] = {"pids": pids, "mem_bytes": mem, "id": cg.cgroup_id(name)}
        return out
    return read
