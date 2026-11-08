"""
cora_sentinel.uiclient - the client side of the status feed: connection, staleness, and the view a tray draws.
Stdlib only, no GUI: cora-tray is a thin shell over StatusClient.view(), and this module doubles as a terminal HUD:

    python -m cora_sentinel.uiclient [--socket /run/cora-sentinel/ui.sock] [--once]

The one rule that matters: silence is never "clear". No connection, or no message for STALE_AFTER_S, is shown as
"unreachable" (grey), whatever the last colour was.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import itertools
import time
from typing import Callable, Optional

from cora_sentinel.uihub import SCHEMA, STALE_AFTER_S

DEFAULT_SOCKET = "/run/cora-sentinel/ui.sock"
COLOURS = {"clear": "green", "evaluating": "amber", "pressure": "amber", "contained": "indigo", "alarm": "red", "unreachable": "grey"}
MAX_LINE = 1024 * 1024


def human_bytes(n: Optional[int], signed: bool = False) -> str:
    if n is None:
        return "?"
    sign = ("+" if n >= 0 else "-") if signed else ("-" if n < 0 else "")
    v = float(abs(n))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if v < 1024 or unit == "GiB":
            return f"{sign}{v:.0f} {unit}" if unit == "B" else f"{sign}{v:.1f} {unit}"
        v /= 1024
    return f"{sign}{v:.1f} GiB"


class StatusClient:
    def __init__(self, path: str = DEFAULT_SOCKET, clock: Callable[[], float] = time.monotonic):
        self.path, self.clock = path, clock
        self.sock: Optional[socket.socket] = None
        self.buf = b""
        self.state: Optional[dict] = None
        self.last_rx: Optional[float] = None
        self.error: Optional[str] = "not connected yet"
        self.results: dict = {}                     # tag -> the daemon's {"type": "result", ...} reply
        self._tags = itertools.count(1)

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
        return True

    def close(self) -> None:
        if self.sock:
            self.sock.close()
        self.sock = None

    def poll(self) -> bool:
        """Read whatever is waiting, never block. True if the state changed. Reconnect is the caller's timer."""
        if self.sock is None:
            return False
        changed = False
        while True:
            try:
                data = self.sock.recv(65536)
            except BlockingIOError:
                break
            except OSError as e:
                self.error = f"connection lost ({e.strerror})"
                self.close()
                return True
            if not data:
                self.error = "cora-sentinel closed the connection"
                self.close()
                return True
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
                self.state, self.last_rx, changed = msg, self.clock(), True
            elif msg.get("type") == "result" and msg.get("id") is not None:
                self.results[str(msg["id"])] = msg
                changed = True
        return changed

    def send(self, cmd: str, task: str, cgroup_id) -> Optional[str]:
        """Ask the daemon to tighten one task ("sever" or "cap"). Returns the tag its reply will carry, or None if
        it could not be sent. The daemon decides; this only asks."""
        if self.sock is None or cmd not in ("sever", "cap"):
            return None
        tag = f"t{next(self._tags)}"
        line = json.dumps({"cmd": cmd, "task": task, "cgroup_id": cgroup_id, "id": tag}) + "\n"
        try:
            self.sock.setblocking(True)
            self.sock.settimeout(2)
            self.sock.sendall(line.encode())
        except OSError as e:
            self.error = f"could not send ({e.strerror or e})"
            self.close()
            return None
        finally:
            if self.sock:
                self.sock.setblocking(False)
        return tag

    def reachable(self) -> bool:
        return (self.sock is not None and self.state is not None and self.last_rx is not None
                and self.clock() - self.last_rx <= STALE_AFTER_S)

    def view(self) -> dict:
        """What to draw. Everything a tray needs, nothing it has to work out."""
        if not self.reachable():
            why = self.error or (f"no update for {self.clock() - self.last_rx:.0f} s" if self.last_rx is not None else "waiting")
            return {"status": "unreachable", "colour": COLOURS["unreachable"], "title": "cora: unreachable",
                    "detail": why, "mode": None, "tasks": [], "session": None}
        s = self.state
        mode = s.get("mode")
        st = s.get("status", "clear")
        sess = s.get("session") or {}
        hot = [t["name"] for t in s.get("tasks", []) if (t.get("pressure") or {}).get("active")]
        label = {"clear": "all clear", "evaluating": f"model evaluating ({s.get('evaluating', 0)})",
                 "pressure": f"memory pressure: {', '.join(hot)}",
                 "contained": "containment active", "alarm": "ALARM: check the decision log"}.get(st, st)
        enforced = any(t.get("enforced") for t in s.get("tasks", []))
        if st == "contained" and not enforced and mode != "enforce":
            label = "WOULD contain (dry-run: nothing was done)"
        elif st == "contained" and enforced and mode != "enforce":
            label = "containment active (manual override)"
        breakers = set(s.get("breakers") or [])
        tasks = [{"name": t["name"], "cgroup_id": t.get("cgroup_id"),
                  "line": f"{t['name']}: {human_bytes(t.get('mem_bytes'))}"
                          + (f" / {human_bytes((t.get('scope') or {}).get('memory_max'))}"
                             if (t.get("scope") or {}).get("memory_max") else "")
                          + f" ({human_bytes(t.get('mem_delta_bytes'), True)})"
                          + (f" [{', '.join(t['contained'])}]" if t.get("contained") else "")
                          + (f" [{', '.join(u + '?' for u in t['unknown'])}]" if t.get("unknown") else "")
                          + (f" [PRESSURE some {(t.get('pressure') or {}).get('some_avg10', '?')}%]"
                             if (t.get("pressure") or {}).get("active") else "")
                          + (" \u2014 exited" if t.get("pids") == 0 else ""),
                  # offered only if the daemon has the breaker AND it is not already in force on this task
                  "can_sever": "sever" in breakers and "ISOLATE" not in (t.get("enforced") or []),
                  "can_cap": "cap" in breakers and "THROTTLE" not in (t.get("enforced") or [])}
                 for t in s.get("tasks", [])]
        alarm_bits = [f"{sess.get(k)} {w}" for k, w in (("dropped_uncontained", "dropped uncontained"),
                                                          ("failed_actions", "failed actions")) if sess.get(k)]
        detail = ", ".join(alarm_bits) or f"{sess.get('community_blocked', 0)} community trackers blocked"
        if s.get("truth_errors"):
            detail += " | " + "; ".join(s["truth_errors"])
        return {"status": st, "colour": COLOURS.get(st, "grey"), "title": f"cora: {label}",
                "detail": detail,
                "mode": mode, "tasks": tasks, "session": sess}


UNDO = {"sever": "sudo cora-firewall release {task}", "cap": "sudo cora-cgroup reset {task}"}
BREAKER_LABEL = {"sever": "Sever network\u2026", "cap": "Cap memory\u2026"}


def confirm_text(cmd: str, task: str) -> tuple:
    """(heading, body) for the confirmation dialog. Says plainly that the tray cannot take it back."""
    what = {"sever": f"Cut ALL network access for \u201c{task}\u201d?",
            "cap": f"Cap \u201c{task}\u201d at the memory it uses now, and its CPU at 20%?"}[cmd]
    body = ("It takes effect at once, for the whole task, even if cora-sentinel runs in dry-run.\n"
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
    if v["status"] != "unreachable":
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
