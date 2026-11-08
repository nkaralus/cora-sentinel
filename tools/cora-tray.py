#!/usr/bin/env python3
"""
cora-tray.py - a Qt (PySide6) tray for cora-sentinel's status feed, for desktops where the GTK/AppIndicator tray in
deploy/cora-tray/ does not fit (KDE, XFCE, sway with a tray bar, ...). A thin shell like that one: the connection,
staleness, colours, breaker eligibility and confirmation text all come from cora_sentinel.uiclient, so the two trays
cannot disagree. What this one adds is memory pressure: a status window with every task's PSI.

    python3 tools/cora-tray.py [--socket /run/cora-sentinel/ui.sock]

Needs: pip install PySide6, and cora_sentinel importable (installed, or PYTHONPATH=src).

Icon: green all clear, amber evaluating or memory pressure, indigo containment active, red ALARM (see the decision
log), grey unreachable. Grey whenever the daemon is silent for STALE_AFTER_S: a dead daemon never looks clear.

PSI per task: the kernel's rolling some/full avg10 and avg60 (%), and "stall", the EXACT fraction of wall time some
task was stalled on memory over the last WINDOW_S, from two updates: d(some_total_us) / (d(mono) * 1e6), with mono
the DAEMON's clock (uihub's contract; our own clock would mix in socket and timer jitter). A task without PSI shows
"-", never 0: not measured is not a pass.

Breakers only tighten (Sever network = ISOLATE, Cap memory = THROTTLE), always ask first with Cancel as the default,
and carry the cgroup id from the snapshot, so a relaunch under the same name is refused by the daemon. Undo is
root-only on the command line (cora-firewall release / cora-cgroup reset).

Testing aids (not for daily use): --dump-after SECONDS prints the icon, menu and status table, then exits;
--press CMD:TASK presses a breaker once the task appears, with --yes to skip the confirmation dialog.
With QT_QPA_PLATFORM=offscreen these run headless.
"""
from __future__ import annotations

import argparse
import collections
import grp
import os
import sys
import time

try:
    from cora_sentinel.uiclient import BREAKER_LABEL, DEFAULT_SOCKET, StatusClient, confirm_text, human_bytes
except ImportError:
    sys.exit("cora-tray: cannot import cora_sentinel (install it, or run with PYTHONPATH=/path/to/cora-sentinel/src)")

QT_ERROR = None
try:
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
    from PySide6.QtWidgets import (QApplication, QHeaderView, QLabel, QMenu, QMessageBox, QPushButton,
                                   QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
except ImportError as e:
    QT_ERROR = e

HERE = os.path.dirname(os.path.realpath(__file__))
ICONS = None
for candidate in ("/usr/share/cora-sentinel/cora-tray/icons", os.path.join(HERE, "..", "deploy", "cora-tray", "icons")):
    if os.path.isdir(candidate):
        ICONS = os.path.normpath(candidate)
        break
FALLBACK_RGB = {"green": "#2e7d32", "amber": "#f9a825", "indigo": "#3949ab", "red": "#c62828", "grey": "#757575"}
TICK_MS = 250
RECONNECT_S = 2.0
WINDOW_S = 10.0                       # the exact stall fraction is taken over (about) this much daemon time
VERB = {"sever": "severed network for", "cap": "capped memory for"}
COLUMNS = ["Task", "Memory", "Change", "some avg10", "full avg10", "some avg60", "full avg60",
           f"stall {WINDOW_S:.0f}s", "In force", "", ""]


def pct(v) -> str:
    return "-" if v is None else f"{v:.2f}%"


class StallMeter:
    """Exact stall fractions from the cumulative PSI counters. Keyed by (task, cgroup id): a relaunch starts over,
    and so does a counter that went backwards (a new cgroup we were not told about)."""

    def __init__(self, window: float = WINDOW_S):
        self.window = window
        self.samples: dict = {}                          # (name, cgroup_id) -> deque[(mono, some_us, full_us)]

    def feed(self, state: dict) -> None:
        mono = state.get("mono")
        seen = set()
        for t in state.get("tasks", []):
            key = (t.get("name"), t.get("cgroup_id"))
            seen.add(key)
            psi = t.get("psi") or {}
            some, full = psi.get("some_total_us"), psi.get("full_total_us")
            if mono is None or some is None:
                self.samples.pop(key, None)
                continue
            q = self.samples.setdefault(key, collections.deque())
            if q and (mono <= q[-1][0] or some < q[-1][1]):
                if mono == q[-1][0]:
                    continue                             # the same update twice
                q.clear()
            q.append((mono, some, full))
            while len(q) > 2 and mono - q[1][0] >= self.window:
                q.popleft()
        for key in list(self.samples):
            if key not in seen:
                del self.samples[key]

    def fraction(self, name, cgroup_id) -> tuple:
        """(some, full) as fractions of wall time, or (None, None) before there are two samples."""
        q = self.samples.get((name, cgroup_id))
        if not q or len(q) < 2:
            return None, None
        (m0, s0, f0), (m1, s1, f1) = q[0], q[-1]
        dt = (m1 - m0) * 1e6
        if dt <= 0:
            return None, None
        return (s1 - s0) / dt, (None if f0 is None or f1 is None else (f1 - f0) / dt)


def icon_for(colour: str) -> "QIcon":
    path = os.path.join(ICONS, f"cora-{colour}.svg") if ICONS else None
    if path and os.path.exists(path):
        ic = QIcon(path)
        if not ic.pixmap(22, 22).isNull():              # null if Qt has no SVG image plugin
            return ic
    pm = QPixmap(64, 64)                                 # no icons (or no SVG plugin): a plain disc in the colour
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(FALLBACK_RGB.get(colour, FALLBACK_RGB["grey"])))
    p.setPen(Qt.NoPen)
    p.drawEllipse(4, 4, 56, 56)
    p.end()
    return QIcon(pm)


class StatusWindow(QWidget):
    def __init__(self, tray: "Tray"):
        super().__init__()
        self.tray = tray
        self.setWindowTitle("cora-sentinel")
        self.resize(1000, 320)
        lay = QVBoxLayout(self)
        self.head = QLabel()
        self.head.setTextFormat(Qt.PlainText)
        f = self.head.font()
        f.setBold(True)
        self.head.setFont(f)
        self.detail = QLabel()
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.PlainText)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.NoSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.empty = QLabel("no sandboxed tasks running")
        self.footer = QLabel("Breakers only tighten. Undo, as root:  sudo cora-firewall release TASK   |   "
                             "sudo cora-cgroup reset TASK")
        self.footer.setTextFormat(Qt.PlainText)
        lay.addWidget(self.head)
        lay.addWidget(self.detail)
        lay.addWidget(self.table)
        lay.addWidget(self.empty)
        lay.addWidget(self.footer)
        self.row_keys = None

    def render(self, v: dict, rows: list, notes: list) -> None:
        self.head.setText(v["title"])
        self.detail.setText("\n".join([v["detail"]] + notes))
        self.table.setVisible(bool(rows))
        self.empty.setVisible(v["status"] != "unreachable" and not rows)
        keys = [(r["name"], r["cgroup_id"], r["can_sever"], r["can_cap"]) for r in rows]
        if keys != self.row_keys:                        # buttons are rebuilt only when what they act on changes
            self.row_keys = keys
            self.table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                for col, cmd, ok in ((9, "sever", r["can_sever"]), (10, "cap", r["can_cap"])):
                    b = QPushButton(BREAKER_LABEL[cmd])
                    b.setEnabled(ok)
                    b.clicked.connect(lambda _=False, c=cmd, n=r["name"], cid=r["cgroup_id"]:
                                      self.tray.on_breaker(c, n, cid))
                    self.table.setCellWidget(i, col, b)
        for i, r in enumerate(rows):
            for col, text in enumerate(r["cells"]):
                item = self.table.item(i, col)
                if item is None:
                    item = QTableWidgetItem()
                    if col:
                        item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                    self.table.setItem(i, col, item)
                if item.text() != text:
                    item.setText(text)

    def closeEvent(self, ev):
        if self.tray.has_tray:                           # the tray keeps running; the window just hides
            ev.ignore()
            self.hide()
        else:
            QApplication.quit()


class Tray:
    def __init__(self, app: "QApplication", args):
        self.app, self.args = app, args
        self.client = StatusClient(args.socket)
        self.meter = StallMeter()
        self.pending: dict = {}                          # tag -> (cmd, task)
        self.last = None
        self.next_connect = 0.0
        self.pressed = False
        self.seq = None
        self.colour, self.menu_spec = None, None
        self.dialogs: list = []                          # non-modal error boxes, kept alive until closed
        self.has_tray = QSystemTrayIcon.isSystemTrayAvailable()
        self.window = StatusWindow(self)
        self.tray = QSystemTrayIcon()
        self.menu = QMenu()
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self.on_activated)
        self.render()
        if self.has_tray:
            self.tray.show()
        else:                                            # no tray host (GNOME without the extension): window only
            self.window.show()
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.timer.start(TICK_MS)

    # ---------------------------------------------------------------- loop
    def tick(self) -> None:
        now = time.monotonic()
        if self.client.sock is None and now >= self.next_connect:
            self.client.connect()
            self.next_connect = now + RECONNECT_S
        self.client.poll()
        st = self.client.state
        if st is not None and st.get("seq") != self.seq:
            self.seq = st.get("seq")
            self.meter.feed(st)
        for tag in [t for t in self.pending if t in self.client.results]:
            cmd, task = self.pending.pop(tag)
            r = self.client.results.pop(tag)
            if r.get("ok"):
                self.last = f"last: {VERB[cmd]} {task}"
            else:
                self.last = f"last: FAILED to {cmd} {task}"
                self.error(f"Could not {cmd} “{task}”", r.get("error") or "unknown error")
        self.render()
        if self.args.press and not self.pressed:
            self.try_scripted_press()

    def rows(self, v: dict) -> list:
        raw = {(t.get("name"), t.get("cgroup_id")): t for t in (self.client.state or {}).get("tasks", [])}
        out = []
        for t in v["tasks"]:
            src = raw.get((t["name"], t["cgroup_id"]), {})
            psi = src.get("psi") or {}
            some, full = self.meter.fraction(t["name"], t["cgroup_id"])
            stall = "-" if some is None else f"{some * 100:.2f}%" + ("" if full is None else f" / {full * 100:.2f}%")
            mem = human_bytes(src.get("mem_bytes"))
            cap = (src.get("scope") or {}).get("memory_max")
            if cap:
                mem += f" / {human_bytes(cap)}"
            force = ", ".join(src.get("contained") or []) + "".join(f" {u}?" for u in src.get("unknown") or [])
            if (src.get("pressure") or {}).get("active"):
                force = (force + " PRESSURE").strip()
            if src.get("pids") == 0:
                force = (force + " (exited)").strip()
            out.append({"name": t["name"], "cgroup_id": t["cgroup_id"],
                        "can_sever": t["can_sever"], "can_cap": t["can_cap"],
                        "cells": [t["name"], mem, human_bytes(src.get("mem_delta_bytes"), True),
                                  pct(psi.get("some_avg10")), pct(psi.get("full_avg10")),
                                  pct(psi.get("some_avg60")), pct(psi.get("full_avg60")), stall, force or "-"],
                        "menu": f"{t['line']}  psi {pct(psi.get('some_avg10'))} / {pct(psi.get('full_avg10'))}"})
        return out

    def notes(self, v: dict) -> list:
        out = []
        if v.get("mode") == "dry-run":
            out.append("dry-run: the model's verdicts are not acted on; breakers still act")
        elif v.get("mode") == "detect-only":
            out.append("detect-only: no model; breakers still act")
        if self.last:
            out.append(self.last)
        return out

    def render(self) -> None:
        v = self.client.view()
        rows = self.rows(v)
        notes = self.notes(v)
        if v["colour"] != self.colour:
            self.colour = v["colour"]
            ic = icon_for(v["colour"])
            self.tray.setIcon(ic)
            self.window.setWindowIcon(ic)
        self.tray.setToolTip(f"{v['title']}\n{v['detail']}")
        spec = (v["title"], v["detail"], tuple(notes), v["status"],
                tuple((r["menu"], r["name"], r["cgroup_id"], r["can_sever"], r["can_cap"]) for r in rows))
        if spec != self.menu_spec and not self.menu.isVisible():   # never rebuild a menu under the pointer
            self.menu_spec = spec
            self.build_menu(v, rows, notes)
        self.window.render(v, rows, notes)

    def build_menu(self, v: dict, rows: list, notes: list) -> None:
        self.menu.clear()
        for text in [v["title"], v["detail"]] + notes:
            self.menu.addAction(text).setEnabled(False)
        self.menu.addSeparator()
        if v["status"] != "unreachable":
            if not rows:
                self.menu.addAction("no sandboxed tasks running").setEnabled(False)
            for r in rows:
                sub = self.menu.addMenu(r["menu"])
                for cmd, ok in (("sever", r["can_sever"]), ("cap", r["can_cap"])):
                    a = sub.addAction(BREAKER_LABEL[cmd])
                    a.setEnabled(ok)
                    a.triggered.connect(lambda _=False, c=cmd, n=r["name"], cid=r["cgroup_id"]: self.on_breaker(c, n, cid))
            self.menu.addSeparator()
        self.menu.addAction("Show status window…").triggered.connect(self.show_window)
        self.menu.addAction("Quit cora-tray").triggered.connect(QApplication.quit)

    def on_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            if self.window.isVisible():
                self.window.hide()
            else:
                self.show_window()

    def show_window(self) -> None:
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    # ---------------------------------------------------------------- breakers
    def on_breaker(self, cmd: str, task: str, cid) -> None:
        if not self.args.yes and not self.confirm(cmd, task):
            return
        tag = self.client.send(cmd, task, cid)
        if tag is None:
            self.error(f"Could not {cmd} “{task}”", self.client.error or "not connected to cora-sentinel")
            return
        self.pending[tag] = (cmd, task)
        self.last = f"last: {cmd} {task}: waiting for cora-sentinel…"
        self.render()

    def confirm(self, cmd: str, task: str) -> bool:
        head, body = confirm_text(cmd, task)
        box = QMessageBox(QMessageBox.Warning, "cora-sentinel", head, parent=self.window)
        box.setInformativeText(body)
        cancel = box.addButton(QMessageBox.Cancel)
        ok = box.addButton({"sever": "Sever network", "cap": "Cap memory"}[cmd], QMessageBox.DestructiveRole)
        box.setDefaultButton(cancel)                     # Enter must not sever by accident
        box.setEscapeButton(cancel)
        box.exec()
        return box.clickedButton() is ok

    def error(self, head: str, body: str) -> None:
        if self.args.dump_after is not None:             # headless test run: print, do not block
            print(f"ERROR: {head}: {body}", flush=True)
            return
        box = QMessageBox(QMessageBox.Critical, "cora-sentinel", head, QMessageBox.Close, self.window)
        box.setInformativeText(body)
        box.setAttribute(Qt.WA_DeleteOnClose)
        box.finished.connect(lambda _=0, b=box: self.dialogs.remove(b) if b in self.dialogs else None)
        self.dialogs.append(box)
        box.open()                                       # not exec(): the feed keeps updating behind it

    # ---------------------------------------------------------------- testing aids
    def try_scripted_press(self) -> None:
        cmd, _, task = self.args.press.partition(":")
        for t in self.client.view()["tasks"]:
            if t["name"] == task and t.get(f"can_{cmd}"):
                self.pressed = True
                self.on_breaker(cmd, task, t["cgroup_id"])
                return

    def dump(self) -> None:
        print(f"ICON cora-{self.colour}  (tray host: {'yes' if self.has_tray else 'no'})")
        for a in self.menu.actions():
            if a.isSeparator():
                print("  ----")
                continue
            print(f"  [{'x' if a.isEnabled() else ' '}] {a.text()}")
            for b in (a.menu().actions() if a.menu() else []):
                print(f"        [{'x' if b.isEnabled() else ' '}] {b.text()}")
        t = self.window.table
        if t.rowCount():
            print("TABLE  " + " | ".join(COLUMNS[:9]))
            for i in range(t.rowCount()):
                cells = [(t.item(i, c).text() if t.item(i, c) else "") for c in range(9)]
                btns = [f"[{'x' if t.cellWidget(i, c).isEnabled() else ' '}] {t.cellWidget(i, c).text()}"
                        for c in (9, 10)]
                print("       " + " | ".join(cells + btns))
        sys.stdout.flush()
        QApplication.quit()


def member_of(group: str = "cora") -> bool:
    """True for root, for a member of the group, and when the group does not exist (a custom --ui-group setup)."""
    if os.getuid() == 0:
        return True
    try:
        return grp.getgrnam(group).gr_gid in os.getgroups()
    except KeyError:
        return True


def main() -> int:
    ap = argparse.ArgumentParser(prog="cora-tray.py")
    ap.add_argument("--socket", default=DEFAULT_SOCKET)
    ap.add_argument("--autostart", action="store_true",
                    help="started by the session: exit quietly if you are not in group cora or PySide6 is missing")
    ap.add_argument("--dump-after", type=float, default=None, help=argparse.SUPPRESS)
    ap.add_argument("--press", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.autostart and not member_of():
        return 0
    if QT_ERROR is not None:
        if args.autostart:
            return 0
        sys.exit(f"cora-tray: PySide6 is missing ({QT_ERROR}).\n  pip install PySide6")
    app = QApplication(sys.argv[:1])
    app.setApplicationName("cora-tray")
    app.setQuitOnLastWindowClosed(False)                 # closing the status window leaves the tray running
    tray = Tray(app, args)
    if args.dump_after is not None:
        QTimer.singleShot(int(args.dump_after * 1000), tray.dump)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
