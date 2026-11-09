"""
cora_sentinel.uiclient - the client side of the status feed: connection, staleness, and the view a tray draws.
Stdlib only, no GUI: cora-tray is a thin shell over StatusClient.view(), and this module doubles as a terminal HUD:

    python -m cora_sentinel.uiclient [--socket /run/cora-sentinel/ui.sock] [--once]

The one rule that matters: silence is never "clear". No connection, or no message for STALE_AFTER_S, is shown as
"unreachable" (grey), whatever the last colour was. A fresh connection starts its own clock and shows "connecting"
(grey) until the first snapshot arrives; the previous connection's snapshot is never shown again.

And anything the client does not understand is loud, never quiet: a status that is missing, null or not one it knows,
an enforcement verb it does not know, or a snapshot it cannot read is "unknown" (red), with the raw value in the
detail line. A daemon that cannot read the kernel's state ("blind", or any truth_errors) is red too, never green.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import itertools
import time
from typing import Callable, List, Optional

from cora_sentinel.uihub import HEARTBEAT_S, SCHEMA, STALE_AFTER_S
from cora_sentinel.ring_buffer import human_bytes  # noqa: F401  (shared; uiclient.human_bytes still works)

DEFAULT_SOCKET = "/run/cora-sentinel/ui.sock"
COLOURS = {"clear": "green", "evaluating": "amber", "pressure": "amber", "contained": "indigo", "alarm": "red",
           "blind": "red", "unknown": "red", "connecting": "grey", "unreachable": "grey", "psi_refused": "amber"}
KNOWN_STATUS = frozenset({"clear", "evaluating", "pressure", "psi_refused", "contained", "blind", "alarm"})   # what the daemon may send
KNOWN_VERBS = frozenset({"ISOLATE", "THROTTLE", "SUSPEND"})                                       # what can be in force
PSI_STATES = frozenset({"armed", "refused", "disabled", "unmonitored"})   # anything else, or nothing: "unknown"
# worst wins when several faults are true at once; alarm outranks unknown (an unknown never hides a known alarm)
# psi_refused (client-side: a launch scope asked for a memory-pressure tripwire and the kernel refused it, so that
# task is unwatched) ranks with contained; on a tie real containment wins, because it is listed first in the votes
RANK = {"clear": 0, "evaluating": 1, "pressure": 2, "contained": 3, "psi_refused": 3, "blind": 4, "unknown": 5, "alarm": 6}
_MISSING = object()
MAX_LINE = 1024 * 1024
BREAKER_VERB = {"sever": "ISOLATE", "cap": "THROTTLE"}
SEND_TIMEOUT_S = 2.0                    # a socket nobody reads cannot hold a send() longer than this
TIMED_OUT = "timed out (daemon unresponsive)"
CAP_CPU_MAX = "20000 100000"            # what "cap" writes to cpu.max (20 %); memory.high gets memory.current
ACK_TIMEOUT_S = 2 * HEARTBEAT_S + 0.5   # an acknowledged breaker must be in force by then (the feed shows it at once)


class StatusClient:
    def __init__(self, path: str = DEFAULT_SOCKET, clock: Callable[[], float] = time.monotonic):
        self.path, self.clock = path, clock
        self.sock: Optional[socket.socket] = None
        self.buf = b""
        self.state: Optional[dict] = None
        self.last_rx: Optional[float] = None
        self.connected_at: Optional[float] = None
        self.error: Optional[str] = "not connected yet"
        self.results: dict = {}                     # tag -> the daemon's {"type": "result", ...} reply
        self._tags = itertools.count(1)
        self._sent: dict = {}                       # tag -> the press (cmd, task, cgroup_id, before) not yet answered
        self.awaiting: dict = {}                    # tag -> an acknowledged breaker not yet seen in force
        self._sent_at: dict = {}                    # tag -> when it was sent (this client's clock)
        self.timed_out: dict = {}                   # tag -> a breaker the daemon never answered within ACK_TIMEOUT_S
        self.on_state: Optional[Callable[[dict], None]] = None   # called with EVERY state frame (a poll may read several)

    def connect(self) -> bool:
        self.close()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(self.path)
        except OSError as e:
            s.close()
            self.error = {13: "permission denied (are you in the --ui-group group? log out and back in after usermod)",
                          2: "no socket (is cora-sentinel running with --ui-socket?)",
                          111: "refused (cora-sentinel is not listening)"}.get(e.errno, e.strerror or str(e))
            return False
        s.setblocking(False)
        self.sock, self.buf, self.error = s, b"", None
        # the silence watchdog starts now, and nothing from the previous connection is shown again
        self.state, self.last_rx, self.connected_at = None, None, self.clock()
        return True

    def close(self) -> None:
        if self.sock:
            self.sock.close()
        self.sock = None
        self._forget_breakers()                     # a dropped link (or a reconnect) ends every pending check

    def _forget_breakers(self) -> None:
        """Pending breaker checks are only meaningful against the feed they were pressed on."""
        self._sent.clear()
        self._sent_at.clear()
        self.awaiting.clear()
        self.timed_out.clear()

    def poll(self) -> bool:
        """Read whatever is waiting, never block. True if the state changed. Reconnect is the caller's timer."""
        if self.sock is None:
            return False
        data = b""
        while True:
            try:
                chunk = self.sock.recv(65536)
            except BlockingIOError:
                break
            except OSError as e:
                self.error = f"connection lost ({e.strerror})"
                self.close()
                return True
            if not chunk:
                self.error = "cora-sentinel closed the connection"
                self.close()
                return True
            data += chunk
            if len(self.buf) + len(data) > MAX_LINE:
                break                                    # ingest() appends it and reports the oversize
        return self.ingest(data)

    def ingest(self, data: bytes) -> bool:
        """Take bytes as they came off the socket (any split: half a frame, several frames) and apply every complete
        frame. True if the state or a result changed. poll() feeds it from the socket; a replay or a simulator can feed
        it directly, with the virtual time in the clock this client was made with."""
        changed = False
        self.buf += data
        if len(self.buf) > MAX_LINE:
            self.error = "oversized message from the socket: disconnected"
            self.close()
            return True
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not (isinstance(msg, dict) and msg.get("schema") == SCHEMA):
                continue
            if msg.get("type") == "state":
                if self.state is not None and _went_back(self.state, msg):
                    self._forget_breakers()             # a restarted daemon: the press it acknowledged is gone
                self.state, self.last_rx, changed = msg, self.clock(), True
                self._reflect(msg)
                if self.on_state is not None:
                    self.on_state(msg)
            elif msg.get("type") == "result" and msg.get("id") is not None:
                self.results[str(msg["id"])] = msg
                tag = str(msg["id"])
                self._sent_at.pop(tag, None)
                late = self.timed_out.pop(tag, None)     # an answer after the timeout still counts, and un-latches
                sent = self._sent.pop(tag, None) or (late and late["sent"])
                if sent is not None and msg.get("ok") is True:
                    cmd, task, cid, before = sent
                    self.awaiting[str(msg["id"])] = {"cmd": cmd, "task": task, "cgroup_id": cid,
                                                     "verb": BREAKER_VERB[cmd], "before": before, "since": self.clock()}
                changed = True
        return changed

    def send(self, cmd: str, task: str, cgroup_id) -> Optional[str]:
        """Ask the daemon to tighten one task ("sever" or "cap"). Returns the tag its reply will carry, or None if
        it could not be sent. The daemon decides; this only asks."""
        if self.sock is None or cmd not in ("sever", "cap"):
            return None
        tag = f"t{next(self._tags)}"
        self._forget_breakers()                     # a new press supersedes the old checks (and their alert)
        self._sent[tag] = (cmd, task, cgroup_id, _press_state(self.state, task, cgroup_id))
        self._sent_at[tag] = self.clock()
        line = json.dumps({"cmd": cmd, "task": task, "cgroup_id": cgroup_id, "id": tag}) + "\n"
        try:
            self.sock.setblocking(True)
            self.sock.settimeout(SEND_TIMEOUT_S)
            self.sock.sendall(line.encode())
        except OSError as e:
            self.error = f"could not send ({e.strerror or e})"
            self.close()
            return None
        finally:
            if self.sock:
                self.sock.setblocking(False)
        return tag

    def expire(self) -> None:
        """A breaker the daemon has not answered within ACK_TIMEOUT_S is timed out: shown, never waited on forever."""
        now = self.clock()
        for tag, at in list(self._sent_at.items()):
            if now - at > ACK_TIMEOUT_S:
                sent = self._sent.pop(tag)
                del self._sent_at[tag]
                self.timed_out[tag] = {"cmd": sent[0], "task": sent[1], "cgroup_id": sent[2], "since": at, "sent": sent}

    def _reflect(self, state: dict) -> None:
        """An acknowledged breaker is settled when the feed shows a CHANGE it made: sever, ISOLATE in force that was not
        at press time; cap, THROTTLE in force with cpu.max or memory.high different from press time. A verb that was
        already there proves nothing. It is dropped, not settled, when its task is gone or has exited (pids 0)."""
        tasks = state.get("tasks") if isinstance(state.get("tasks"), list) else []
        for tag, a in list(self.awaiting.items()):
            t = next((t for t in tasks if isinstance(t, dict) and t.get("name") == a["task"]
                      and t.get("cgroup_id") == a["cgroup_id"]), None)
            if t is None or t.get("pids") == 0 or _reflected(a, t):
                del self.awaiting[tag]

    def reachable(self) -> bool:
        return (self.sock is not None and self.state is not None and self.last_rx is not None
                and self.clock() - self.last_rx <= STALE_AFTER_S)

    def view(self) -> dict:
        """What to draw. Everything a tray needs, nothing it has to work out."""
        def quiet(status: str, title: str, detail: str) -> dict:
            return {"status": status, "colour": COLOURS[status], "title": title, "detail": detail, "mode": None,
                    "tasks": [], "session": None, "replay": None}
        self.expire()
        if self.sock is None:
            return quiet("unreachable", "cora: unreachable", self.error or "not connected")
        if self.state is None:
            waited = self.clock() - (self.connected_at if self.connected_at is not None else self.clock())
            if waited <= STALE_AFTER_S:
                return quiet("connecting", "cora: connecting", "connected, awaiting first snapshot")
            return quiet("unreachable", "cora: unreachable", f"connected, no data for {waited:.0f} s")
        if not self.reachable():                     # open but silent: a wedged daemon, not a dead socket
            return quiet("unreachable", "cora: unreachable", f"connected, no data for {self.clock() - self.last_rx:.0f} s")
        try:
            return self._view(self.state)
        except Exception as e:                      # a snapshot this client cannot read is never drawn as fine
            return {"status": "unknown", "colour": COLOURS["unknown"], "title": "cora: UNKNOWN snapshot from cora-sentinel",
                    "detail": f"unreadable snapshot ({e.__class__.__name__}: {e})"[:300], "mode": None, "tasks": [],
                    "session": None, "replay": _replay_of(self.state)}

    @staticmethod
    def _verbs(t: dict, key: str) -> List[str]:
        v = t.get(key) or []
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            return [f"<malformed {key}: {v!r}>"[:60]]
        return v

    def _enforced(self, t: dict) -> List[str]:
        """What is in force on a task. A THROTTLE knob (cpu.max, or memory.high) whose provenance is not exactly
        "launch" is the sentinel's, whatever `enforced` says: missing or null provenance never downgrades a limit."""
        e = list(self._verbs(t, "enforced"))
        lim = t.get("limits")
        if isinstance(lim, dict) and lim.get("source") == "unknown":
            # the registry is unreadable: a THROTTLE read off memory.high may be nothing but the launch ceiling, so it
            # is not claimed as containment, and Cap stays offered (a tightening: harmless if a cap is already set)
            return [v for v in e if v != "THROTTLE"]
        if isinstance(lim, dict) and "THROTTLE" not in e:
            if lim.get("cpu_max") is not None or (lim.get("memory_high") is not None and lim.get("source") != "launch"):
                e.append("THROTTLE")
        return e

    def _shown_contained(self, t: dict) -> List[str]:
        v = self._verbs(t, "contained")
        if (t.get("limits") or {}).get("source") == "unknown":
            v = [x for x in v if x != "THROTTLE"]       # shown as "limit provenance unknown" instead
        return v

    def task_status(self, t: dict) -> str:
        """One task's own status, by the same ranks as the whole view's: what the HUD sorts its rows by. Only what the
        feed says about THIS task votes (a session-wide alarm names no task; the daemon puts it on the task it can)."""
        votes = ["clear"]
        if t.get("alarm"):
            votes.append("alarm")
        if t.get("errors") or (isinstance(t.get("limits"), dict) and t["limits"].get("source") == "unknown"):
            votes.append("blind")
        if any(v not in KNOWN_VERBS for key in ("enforced", "contained", "unknown") for v in self._verbs(t, key)):
            votes.append("unknown")
        if self._enforced(t):
            votes.append("contained")
        if t.get("psi_state") == "refused" and t.get("pids") != 0:
            votes.append("psi_refused")
        if (t.get("pressure") or {}).get("active"):
            votes.append("pressure")
        return max(votes, key=RANK.__getitem__)

    def _view(self, s: dict) -> dict:
        mode = s.get("mode")
        raw = s.get("status", _MISSING)
        status_ok = isinstance(raw, str) and raw in KNOWN_STATUS
        truth = [str(e) for e in (s.get("truth_errors") or [])]
        sess = s.get("session") or {}
        raw_tasks = s.get("tasks") or []
        if not isinstance(raw_tasks, list):
            raise ValueError(f"tasks is {type(raw_tasks).__name__}, not a list")
        odd = []                                     # (task, verb) the client does not know
        for t in raw_tasks:
            for key in ("enforced", "contained", "unknown"):
                odd += [(t["name"], v) for v in self._verbs(t, key) if v not in KNOWN_VERBS]
        odd = list(dict.fromkeys(odd))               # the same verb in enforced and contained is one problem
        unproven = [t["name"] for t in raw_tasks if "THROTTLE" in self._enforced(t) and "THROTTLE" not in self._verbs(t, "enforced")]
        # every fault that is true votes; the worst wins, and the detail line lists them all
        refused = [t["name"] for t in raw_tasks if t.get("psi_state") == "refused" and t.get("pids") != 0]
        prov_unknown = [t["name"] for t in raw_tasks if isinstance(t.get("limits"), dict)
                        and t["limits"].get("source") == "unknown"]
        now = self.clock()
        unreflected = [a for a in self.awaiting.values() if now - a["since"] > ACK_TIMEOUT_S]
        unanswered = list(self.timed_out.values())
        votes = [raw if status_ok else "unknown"] + ["blind"] * bool(truth) + ["unknown"] * bool(odd) + \
            ["contained"] * bool(unproven) + ["psi_refused"] * bool(refused) + ["blind"] * bool(prov_unknown) + \
            ["unknown"] * bool(unreflected) + ["unknown"] * bool(unanswered)
        st = max(votes, key=RANK.__getitem__)
        hot = [t["name"] for t in raw_tasks if (t.get("pressure") or {}).get("active")]
        label = {"clear": "all clear", "evaluating": f"model evaluating ({s.get('evaluating', 0)})",
                 "pressure": f"memory pressure: {', '.join(hot)}",
                 "contained": "containment active", "alarm": "ALARM: check the decision log",
                 "blind": "BLIND: cannot read what is enforced",
                 "unknown": "UNKNOWN status from cora-sentinel" if not status_ok else "UNKNOWN verb from cora-sentinel",
                 "psi_refused": "memory-pressure tripwire refused"}[st]
        if st == "unknown" and status_ok and not odd and unreflected:
            label = "breaker acknowledged but not in force"
        elif st == "unknown" and status_ok and not odd and unanswered:
            label = "breaker unanswered: daemon unresponsive"
        enforced = any(self._enforced(t) for t in raw_tasks)
        if st == "contained" and not enforced and mode != "enforce":
            label = "WOULD contain (dry-run: nothing was done)"
        elif st == "contained" and enforced and mode != "enforce":
            label = "containment active (manual override)"
        breakers = set(s.get("breakers") or [])
        unknown_verb = lambda v: v if v in KNOWN_VERBS else f"{v}: unknown verb"
        tasks = [{"name": t["name"], "cgroup_id": t.get("cgroup_id"),
                  "line": f"{t['name']}: {human_bytes(t.get('mem_bytes'))}"
                          + (f" / {human_bytes((t.get('scope') or {}).get('memory_max'))}"
                             if (t.get("scope") or {}).get("memory_max") else "")
                          + f" ({human_bytes(t.get('mem_delta_bytes'), True)})"
                          + (f" [{', '.join(map(unknown_verb, shown))}]" if (shown := self._shown_contained(t)) else "")
                          + (" [limit provenance unknown]" if (t.get("limits") or {}).get("source") == "unknown" else "")
                          + (f" [{', '.join(unknown_verb(u) + '?' for u in self._verbs(t, 'unknown'))}]"
                             if t.get("unknown") else "")
                          + (f" [PRESSURE some {(t.get('pressure') or {}).get('some_avg10', '?')}%]"
                             if (t.get("pressure") or {}).get("active") else "")
                          + (" [PSI REFUSED]" if t.get("psi_state") == "refused" else "")
                          + (" \u2014 exited" if t.get("pids") == 0 else ""),
                  # offered only if the daemon has the breaker AND it is not already in force on this task
                  "psi_state": t.get("psi_state") if t.get("psi_state") in PSI_STATES else "unknown",
                  "psi_threshold": t.get("psi_threshold") if t.get("psi_state") == "armed"
                                   and isinstance(t.get("psi_threshold"), dict) else None,
                  "mem_bytes": t.get("mem_bytes") if type(t.get("mem_bytes")) is int else None,
                  "status": self.task_status(t),
                  "pending": TIMED_OUT if (late := _timed_out_on(unanswered, t)) else None,
                  "pending_cmd": late["cmd"] if late else None,
                  "can_sever": "sever" in breakers and "ISOLATE" not in self._enforced(t),
                  "can_cap": "cap" in breakers and "THROTTLE" not in self._enforced(t)}
                 for t in raw_tasks]
        alarm_bits = [f"{sess.get(k)} {w}" for k, w in (("dropped_uncontained", "dropped uncontained"),
                                                          ("failed_actions", "failed actions")) if sess.get(k)]
        detail = ", ".join(alarm_bits) or f"{sess.get('community_blocked', 0)} community trackers blocked"
        if prov_unknown:                                 # a consequence: it goes after its cause (the truth error)
            detail = "; ".join(f"limit provenance unknown (registry unreadable) on {n}" for n in prov_unknown[:3]) \
                + " | " + detail
        if truth:
            detail = "; ".join(truth) + " | " + detail          # the exact error first: it is why the light is red
        if not (isinstance(raw, str) and raw in KNOWN_STATUS):
            detail = f"received status: {'<missing>' if raw is _MISSING else repr(raw)[:80]} | " + detail
        if refused:
            detail = "; ".join(f"psi refused on {n}" for n in refused[:3]) + " | " + detail
        if unproven:
            detail = "; ".join(f"limit without launch provenance on {n}: treated as THROTTLE" for n in unproven[:3]) + " | " + detail
        if odd:
            detail = "; ".join(f"unknown verb {v!r} on {n}" for n, v in odd[:3]) + " | " + detail
        if unanswered:
            detail = "; ".join(f"COMMAND_TIMEOUT: {a['cmd']} on {a['task']} sent {now - a['since']:.0f} s ago, no reply "
                               f"(unconfirmed)" for a in unanswered[:3]) + " | " + detail
        if unreflected:
            detail = "; ".join(f"ACK_NOT_REFLECTED: {a['cmd']} on {a['task']} acknowledged {now - a['since']:.0f} s ago, "
                               f"{a['verb']} not in force" for a in unreflected[:3]) + " | " + detail
        return {"status": st, "colour": COLOURS[st], "title": f"cora: {label}",
                "detail": detail,
                "mode": mode, "tasks": tasks, "session": sess, "replay": _replay_of(s)}


def _timed_out_on(unanswered: list, t: dict) -> Optional[dict]:
    return next((a for a in unanswered if a["task"] == t.get("name") and a["cgroup_id"] == t.get("cgroup_id")), None)


def _replay_of(state) -> Optional[str]:
    """The source a replay harness stamps on its frames (tools/cora-replay.py), or None: the daemon never sends it."""
    r = state.get("replay") if isinstance(state, dict) else None
    if r is None:
        return None
    return str(r.get("source") if isinstance(r, dict) else r)[:80] or "replay"


def _press_state(state: Optional[dict], task: str, cgroup_id) -> Optional[dict]:
    """What the press was made against: the task's verbs in force and its THROTTLE numbers, or None if unseen."""
    for t in (state or {}).get("tasks") or []:
        if isinstance(t, dict) and t.get("name") == task and t.get("cgroup_id") == cgroup_id:
            lim = t.get("limits") if isinstance(t.get("limits"), dict) else {}
            return {"enforced": list(t.get("enforced") or []), "cpu_max": lim.get("cpu_max"),
                    "memory_high": lim.get("memory_high")}
    return None


def _reflected(a: dict, t: dict) -> bool:
    before = a.get("before") or {"enforced": [], "cpu_max": None, "memory_high": None}
    now = t.get("enforced") or []
    if a["verb"] not in now:
        return False
    if a["cmd"] == "sever":
        return "ISOLATE" not in before["enforced"]
    lim = t.get("limits") if isinstance(t.get("limits"), dict) else {}
    return (lim.get("cpu_max"), lim.get("memory_high")) != (before["cpu_max"], before["memory_high"])


def _went_back(old: dict, new: dict) -> bool:
    """A seq or a daemon mono that went backwards: a restarted daemon (or a replay that wrapped)."""
    a, b = old.get("seq"), new.get("seq")
    if type(a) is int and type(b) is int and b < a:
        return True
    a, b = old.get("mono"), new.get("mono")
    return isinstance(a, (int, float)) and isinstance(b, (int, float)) and b < a


UNDO = {"sever": "sudo cora-firewall release {task}", "cap": "sudo cora-cgroup reset {task}"}
BREAKER_LABEL = {"sever": "Sever network\u2026", "cap": "Cap memory\u2026"}


def confirm_text(cmd: str, task: str, mem_bytes: Optional[int] = None) -> tuple:
    """(heading, body) for the confirmation dialog. Says plainly that the tray cannot take it back. For cap, the body
    names the values it will write (memory.high: what the task uses at that moment, last seen as mem_bytes)."""
    what = {"sever": f"Cut ALL network access for \u201c{task}\u201d?",
            "cap": f"Cap \u201c{task}\u201d at the memory it uses now, and its CPU at 20%?"}[cmd]
    targets = ""
    if cmd == "cap":
        targets = (f"It will set memory.high = its memory.current at that moment (last seen {human_bytes(mem_bytes)}) "
                   f"and cpu.max = {CAP_CPU_MAX} (20% of one CPU).\n")
    body = (targets + "It takes effect at once, for the whole task, even if cora-sentinel runs in dry-run.\n"
            "The tray cannot undo it. To undo, run as root:\n\n    " + UNDO[cmd].format(task=task))
    return what, body


def menu_spec(v: dict, last: Optional[str] = None) -> list:
    """The tray menu as data: ("label", text) | ("sep",) | ("task", text, [(cmd, label, enabled), ...], cgroup_id)
    | ("quit", text). Breakers appear only while the daemon is reachable and offers them."""
    items = [("label", v["title"]), ("label", v["detail"])]
    if v.get("mode") == "dry-run":
        items.append(("label", "dry-run: the model's verdicts are not acted on; breakers still act"))
    elif v.get("mode") == "detect-only":
        items.append(("label", "detect-only: no model; breakers still act"))
    if last:
        items.append(("label", last))
    items.append(("sep",))
    if v["status"] not in ("unreachable", "connecting"):
        if not v["tasks"]:
            items.append(("label", "no sandboxed tasks running"))
        for t in v["tasks"]:
            items.append(("task", t["line"], [("sever", BREAKER_LABEL["sever"], t["can_sever"]),
                                              ("cap", BREAKER_LABEL["cap"], t["can_cap"])], t["name"], t["cgroup_id"]))
        items.append(("sep",))
    items.append(("quit", "Quit cora-tray"))
    return items


def render_line(v: dict) -> str:
    out = f"[{v['colour'].upper():^6}] {v['title']}"
    if v.get("mode") and v["mode"] != "enforce":
        out += f"  <{v['mode']}>"
    out += f"  | {v['detail']}"
    for t in v["tasks"]:
        out += f"\n         {t['line']}"
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cora_sentinel.uiclient")
    ap.add_argument("--socket", default=DEFAULT_SOCKET)
    ap.add_argument("--once", action="store_true", help="print one status and exit (0 reachable, 1 not)")
    a = ap.parse_args(argv)
    c = StatusClient(a.socket)
    if a.once:
        c.connect()
        end = time.monotonic() + 3
        while c.sock and c.state is None and time.monotonic() < end:
            c.poll()
            time.sleep(0.05)
        v = c.view()
        print(render_line(v))
        return 0 if v["status"] != "unreachable" else 1
    last, next_try = None, 0.0
    try:
        while True:
            if c.sock is None and time.monotonic() >= next_try:
                c.connect()
                next_try = time.monotonic() + 2
            c.poll()
            line = render_line(c.view())
            if line != last:
                print(line, flush=True)
                last = line
            time.sleep(0.2)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
