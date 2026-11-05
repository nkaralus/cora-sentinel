#!/usr/bin/env python3
"""
cora_sentinel.reload - re-read the blocklists on SIGHUP without touching anything else.

Only the lists change. The tap rules, NFLOG and sock_diag sockets, cgroup tracking, owner cache, firewall rules and
the model are not touched, so no flow is missed and no task is forgotten while a list is swapped.

Rules, each of which exists because the naive version ("build a new list and assign it") gets it wrong:

  * FAIL STATIC. If the new lists cannot be loaded (store failed verification, a file is unreadable) the current
    lists stay in force and the failure is logged. A reload can never leave the daemon with no list or half a list.
  * NEVER FAIL OPEN BY ACCIDENT. If the new lists are EMPTY and the current ones are not, the reload is refused
    (someone deleted the files, or a mount is missing). Restart the daemon if you really mean to have no lists.
  * NO DETECTION GAP. Resolved addresses (how a listed domain's CDN address is matched) live inside the list, and
    a fresh list starts without them. The resolver is rebound to the new list and primes it from its cache BEFORE
    it goes live; domains that are new are then resolved at once instead of at the next hourly cycle; domains that
    were removed stop matching immediately.
  * ONE ATOMIC SWAP. Readers see the old list or the new one, never a mixture (judge() reads it once per decision).
  * THE SIGNAL HANDLER ONLY SETS A FLAG. Printing or taking a lock inside a signal handler can deadlock against the
    code it interrupted; a worker thread does the work.

What reloads: --blocklist, --blocklist-store and --blocklist-allow, re-read from the same arguments. What does not:
every other option (policy, allow paths, thresholds): restart for those.
"""
from __future__ import annotations

import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from cora_sentinel.blocklist import Blocklist


class ListError(Exception):
    pass


def _note(msg: str) -> None:
    print(f"[cora-sentinel] {msg}", file=sys.stderr, flush=True)


def load_lists(blocklist_paths: Optional[Sequence[str]], store_dir: Optional[str],
               allow_paths: Optional[Sequence[str]]) -> Tuple[Blocklist, List[str]]:
    """Build a complete, independent set of lists. Raises ListError with a message fit to print."""
    bl = Blocklist()
    warnings: List[str] = []
    try:
        if store_dir:
            from cora_sentinel.blocklist_store import StoreError, load_verified
            try:
                warnings += load_verified(Path(store_dir), bl)
            except StoreError as e:
                raise ListError(str(e)) from None
        for p in blocklist_paths or []:
            bl.load(p)
        if allow_paths:
            bl.allow = Blocklist()
            for p in allow_paths:
                bl.allow.load(p)
    except (OSError, ValueError) as e:
        raise ListError(f"cannot load blocklist: {e}") from None
    return bl, warnings


def _count(bl: Optional[Blocklist]) -> Tuple[set, set]:
    return bl.entries() if bl is not None else (set(), set())


class Reloader:
    def __init__(self, sentinel, loader: Optional[Callable[[], Tuple[Blocklist, List[str]]]],
                 resolver=None, make_resolver: Optional[Callable[[Blocklist], object]] = None,
                 log: Callable[[str], None] = _note,
                 on_reload: Optional[Callable[[Blocklist], None]] = None):
        self.s, self.loader, self.resolver, self.make_resolver, self.log = sentinel, loader, resolver, make_resolver, log
        self.on_reload = on_reload             # called with the NEW list after it is live (the kernel floor follows it)
        self.stats: Counter = Counter()
        self._pending = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    # ---- the signal handler calls this, and ONLY this ----
    def request(self) -> None:
        self._pending = True

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="blocklist-reload", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.wait(0.2):
            if self._pending:
                self._pending = False              # a HUP during a reload asks for exactly one more
                try:
                    self.reload_now()
                except Exception as e:             # never let the worker die: the next HUP must still work
                    self.stats["reloads_failed"] += 1
                    self.log(f"reload FAILED unexpectedly, keeping the previous lists: {e!r}")

    # ---- the reload itself ----
    def reload_now(self) -> str:
        """Returns 'ok', 'failed', 'refused' or 'noop'. Whatever happens, the lists in force stay consistent."""
        with self._lock:
            if self.loader is None:
                self.log("SIGHUP: no blocklist is configured, nothing to reload")
                return "noop"
            old = self.s.conn.blocklist
            try:
                new, warnings = self.loader()
            except ListError as e:
                self.stats["reloads_failed"] += 1
                self.log(f"reload FAILED, keeping the previous lists: {e}")
                return "failed"
            od, on = _count(old)
            nd, nn = _count(new)
            if (od or on) and not (nd or nn):
                self.stats["reloads_refused"] += 1
                self.log(f"reload REFUSED: the new lists are empty but the current ones have {len(od)} domains "
                         f"and {len(on)} subnets/IPs. Keeping the current lists; restart the daemon if you "
                         f"really want none.")
                return "refused"
            for w in warnings:
                self.log(f"warning: {w}")
            if self.resolver is None and self.make_resolver is not None and new.domains:
                self.resolver = self.make_resolver(new)        # the first reload that brings domains in
                self.resolver.start()
            elif self.resolver is not None:
                self.resolver.rebind(new)                      # primes `new` from the cache BEFORE it is live
            self.s.set_blocklist(new)                          # the one atomic swap
            if self.resolver is not None:
                self.resolver.kick()                           # resolve the new domains now, not in an hour
            if self.on_reload is not None:
                try:
                    self.on_reload(new)
                except Exception as e:                         # the list swap already happened; never undo it for this
                    self.log(f"on_reload hook failed: {e!r}")
            self.stats["reloads_ok"] += 1
            self.log(f"reloaded blocklists: domains {len(od)} -> {len(nd)} (+{len(nd - od)}/-{len(od - nd)}), "
                     f"subnets/IPs {len(on)} -> {len(nn)} (+{len(nn - on)}/-{len(on - nn)}), "
                     f"{len(new._resolved)} resolved addresses carried over")
            return "ok"
