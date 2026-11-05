"""SIGHUP hot reload of the blocklists. Run: pytest -q tests/test_reload.py"""
import hashlib
import signal
import subprocess
import sys
import threading
import time

import pytest

from cora_sentinel.blocklist import Blocklist, DomainResolver
from cora_sentinel.blocklist_store import Store, accept, pull
from cora_sentinel.daemon import ConnDetector, NetPolicy, Sentinel
from cora_sentinel.reload import ListError, Reloader, load_lists

DNS = {"cdn.example.com": ["93.184.216.34"], "gone.example.com": ["93.184.216.50"],
       "new.example.com": ["93.184.216.99"]}


def bl_of(*lines, allow=None):
    b = Blocklist()
    for ln in lines:
        b.add_line(ln, "t")
    if allow:
        b.allow = Blocklist()
        for ln in allow:
            b.allow.add_line(ln, "allow")
    return b


def sentinel(bl):
    return Sentinel("X", ["/tmp"], 10**6, 5, emit=lambda e: None, net_allow=["0.0.0.0/0"], blocklist=bl, cooldown_s=0)


def hit(s, ip, qname=None):
    return s.conn.judge(ip, 443, 40000, qname=qname, proto="udp" if qname else "tcp", l7="dns" if qname else None)


def reloader(s, new, **kw):
    log = []
    r = Reloader(s, (lambda: (new() if callable(new) else new, [])) if new is not None else None, log=log.append, **kw)
    return r, log


def until(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


# ============================ what a reload does ============================
def test_a_reload_swaps_the_lists_in_force():
    s = sentinel(bl_of("198.51.100.0/24"))
    assert hit(s, "198.51.100.5") and not hit(s, "203.0.113.5")
    r, log = reloader(s, bl_of("203.0.113.0/24"))
    assert r.reload_now() == "ok"
    assert not hit(s, "198.51.100.5") and hit(s, "203.0.113.5")
    assert "domains 0 -> 0" in log[-1] and "subnets/IPs 1 -> 1 (+1/-1)" in log[-1]


def test_the_allowlist_changes_with_the_list():
    s = sentinel(bl_of("198.51.100.0/24"))
    assert hit(s, "198.51.100.5")
    r, _ = reloader(s, bl_of("198.51.100.0/24", allow=["198.51.100.5/32"]))
    r.reload_now()
    assert not hit(s, "198.51.100.5") and hit(s, "198.51.100.6")


def test_a_failed_load_keeps_the_previous_lists_and_says_so():
    s = sentinel(bl_of("198.51.100.0/24"))
    r, log = reloader(s, lambda: (_ for _ in ()).throw(ListError("store failed verification")))
    assert r.reload_now() == "failed"
    assert hit(s, "198.51.100.5")                                   # still enforcing
    assert r.stats["reloads_failed"] == 1 and "keeping the previous lists" in log[-1]


def test_a_reload_to_EMPTY_lists_is_refused_because_that_would_silently_disable_detection():
    s = sentinel(bl_of("198.51.100.0/24", "tracker.example.com"))
    r, log = reloader(s, Blocklist())
    assert r.reload_now() == "refused"
    assert hit(s, "198.51.100.5")
    assert r.stats["reloads_refused"] == 1 and "restart the daemon" in log[-1] and "1 domains" in log[-1]


def test_empty_to_empty_is_not_refused():
    s = sentinel(Blocklist())
    r, _ = reloader(s, Blocklist())
    assert r.reload_now() == "ok"


def test_with_no_lists_configured_a_reload_is_a_logged_no_op():
    s = sentinel(None)
    r, log = reloader(s, None)
    assert r.reload_now() == "noop" and "nothing to reload" in log[-1]


def test_the_worker_survives_an_unexpected_error_and_serves_the_next_signal():
    s = sentinel(bl_of("198.51.100.0/24"))
    state = {"boom": True}

    def loader():
        if state["boom"]:
            raise RuntimeError("disk on fire")
        return bl_of("203.0.113.0/24"), []
    log = []
    r = Reloader(s, loader, log=log.append)
    r.start()
    try:
        r.request()
        assert until(lambda: r.stats["reloads_failed"] == 1)
        assert hit(s, "198.51.100.5")
        state["boom"] = False
        r.request()
        assert until(lambda: r.stats["reloads_ok"] == 1) and hit(s, "203.0.113.5")
    finally:
        r.stop()


def test_load_lists_reads_the_same_arguments_the_daemon_started_with(tmp_path):
    (tmp_path / "bad.txt").write_text("tracker.example.com\n198.51.100.0/24\n")
    (tmp_path / "ok.txt").write_text("198.51.100.5/32\n")
    bl, warns = load_lists([str(tmp_path / "bad.txt")], None, [str(tmp_path / "ok.txt")])
    assert bl.match_name("a.tracker.example.com") and bl.match_ip("198.51.100.9") and bl.match_ip("198.51.100.5") is None
    with pytest.raises(ListError, match="cannot load blocklist"):
        load_lists([str(tmp_path / "missing.txt")], None, None)


# ============================ one atomic swap ============================
def test_judge_reads_the_reference_once_per_decision_so_a_swap_cannot_tear_it():
    reads, lists = [], [bl_of("198.51.100.0/24"), bl_of("203.0.113.0/24")]

    class Flip(ConnDetector):
        @property
        def blocklist(self):
            reads.append(1)
            return lists[len(reads) % 2]

        @blocklist.setter
        def blocklist(self, v):
            pass
    Flip(NetPolicy(["0.0.0.0/0"]), None).judge("198.51.100.5", 443, 1, qname="x.example.com", proto="udp", l7="dns")
    assert len(reads) == 1


def test_a_flow_listed_in_both_old_and_new_is_never_missed_while_lists_swap_under_load():
    """No window with an empty or half-built list, however the swap interleaves with decisions."""
    def make():
        return bl_of("198.51.100.0/24", f"extra{time.monotonic_ns()}.example.com")
    s = sentinel(make())
    r, _ = reloader(s, make)
    misses, stop = [], threading.Event()

    def swapper():
        while not stop.is_set():
            r.reload_now()
    t = threading.Thread(target=swapper, daemon=True)
    t.start()
    try:
        for i in range(30000):
            if not hit(s, "198.51.100.5"):
                misses.append(i)
    finally:
        stop.set()
        t.join(timeout=10)
    assert misses == [] and r.stats["reloads_ok"] > 20


# ============================ the detection gap ============================
def test_a_naive_swap_loses_resolved_addresses_and_the_reload_does_not():
    old = bl_of("cdn.example.com")
    res = DomainResolver(old, resolve=lambda n: DNS.get(n, []), max_per_cycle=10)
    res.cycle()
    s = sentinel(old)
    assert hit(s, "93.184.216.34")                                  # matched through its resolved address

    s.set_blocklist(bl_of("cdn.example.com"))                       # CONTROL: a plain assignment ...
    assert hit(s, "93.184.216.34") is None                          # ... opens the gap this design closes

    s.set_blocklist(old)
    r, _ = reloader(s, bl_of("cdn.example.com", "other.example.org"), resolver=res)
    assert r.reload_now() == "ok"
    assert hit(s, "93.184.216.34")                                  # still matched, immediately


def test_a_removed_domain_stops_matching_at_once():
    old = bl_of("cdn.example.com", "gone.example.com")
    res = DomainResolver(old, resolve=lambda n: DNS.get(n, []), max_per_cycle=10)
    res.cycle()
    s = sentinel(old)
    assert hit(s, "93.184.216.50")
    r, _ = reloader(s, bl_of("cdn.example.com"), resolver=res)
    r.reload_now()
    assert hit(s, "93.184.216.34") and hit(s, "93.184.216.50") is None


def test_a_new_domain_is_resolved_at_once_not_at_the_next_hourly_cycle():
    old = bl_of("cdn.example.com")
    res = DomainResolver(old, resolve=lambda n: DNS.get(n, []), max_per_cycle=10, interval_s=3600)
    res.start()
    s = sentinel(old)
    try:
        assert until(lambda: hit(s, "93.184.216.34"))
        r, _ = reloader(s, bl_of("cdn.example.com", "new.example.com"), resolver=res)
        r.reload_now()
        assert until(lambda: hit(s, "93.184.216.99"), 3), "the new domain waited for the hourly cycle"
    finally:
        res.stop()


def test_the_first_reload_that_brings_domains_in_starts_a_resolver():
    s = sentinel(bl_of("198.51.100.0/24"))                          # started with no domains: no resolver yet
    made = []

    def make(b):
        d = DomainResolver(b, resolve=lambda n: DNS.get(n, []), max_per_cycle=10, interval_s=3600)
        made.append(d)
        return d
    r, _ = reloader(s, bl_of("198.51.100.0/24", "new.example.com"), make_resolver=make)
    try:
        r.reload_now()
        assert len(made) == 1 and r.resolver is made[0]
        assert until(lambda: hit(s, "93.184.216.99"), 3)
    finally:
        r.resolver and r.resolver.stop()


def test_never_resolved_names_go_first_after_a_reload():
    asked = []
    res = DomainResolver(bl_of("a.example.com", "b.example.com"), resolve=lambda n: asked.append(n) or ["93.184.216.1"],
                         max_per_cycle=2)
    res.cycle()
    asked.clear()
    res.rebind(bl_of("a.example.com", "b.example.com", "c.example.com", "d.example.com"))
    res.cycle()
    assert sorted(asked) == ["c.example.com", "d.example.com"]


def test_names_whose_lookup_FAILS_cannot_starve_the_rotation():
    """A lookup that raises (NXDOMAIN, SERVFAIL) or times out records nothing; without marking the name as tried
    it would stay 'never resolved' and be retried first, every cycle, forever, ahead of everything else."""
    import socket
    names = ["a-dead.example.com", "b-dead.example.com", "c-dead.example.com",
             "d-good.example.com", "e-good.example.com", "f-good.example.com"]
    ok = {"d-good.example.com": ["93.184.216.4"], "e-good.example.com": ["93.184.216.5"],
          "f-good.example.com": ["93.184.216.6"]}

    def resolve(n):
        if n in ok:
            return ok[n]
        raise socket.gaierror("NXDOMAIN")
    b = bl_of(*names)
    res = DomainResolver(b, resolve=resolve, max_per_cycle=2)
    for _ in range(4):
        res.cycle()
    assert all(b.match_ip(ip) for ip in ("93.184.216.4", "93.184.216.5", "93.184.216.6"))


def test_a_lookup_that_finishes_after_the_reload_cannot_resurrect_a_removed_domain():
    """The race the publish filter exists for: a cycle is mid-flight when the list is reloaded; its answer for a
    domain that has just been REMOVED arrives afterwards and must not put that address back on the list."""
    release, started = threading.Event(), threading.Event()

    def slow(n):
        started.set()
        release.wait(10)
        return DNS.get(n, [])
    old = bl_of("cdn.example.com", "gone.example.com")
    res = DomainResolver(old, resolve=slow, max_per_cycle=10)
    t = threading.Thread(target=res.cycle, daemon=True)
    t.start()
    assert started.wait(5)
    new = bl_of("cdn.example.com")
    res.rebind(new)                                                  # reload lands while lookups are in flight
    release.set()
    t.join(timeout=10)
    assert new.match_ip("93.184.216.34") and new.match_ip("93.184.216.50") is None


# ============================ a real SIGHUP, to a real daemon ============================
class Daemon:
    def __init__(self, tmp_path, *args):
        self.p = subprocess.Popen([sys.executable, "-m", "cora_sentinel.daemon", "--interval", "0.2",
                                   "--out", str(tmp_path / "ev.jsonl"), *args],
                                  stderr=subprocess.PIPE, text=True, cwd=tmp_path)
        self.lines = []
        threading.Thread(target=lambda: [self.lines.append(ln) for ln in self.p.stderr], daemon=True).start()

    def count(self, text):
        return sum(text in ln for ln in self.lines)

    def wait_for(self, text, n=1, timeout=30):
        assert until(lambda: self.count(text) >= n, timeout), f"never saw {text!r} x{n}:\n" + "".join(self.lines)

    def alive(self):
        return self.p.poll() is None

    def finish(self):
        self.p.send_signal(signal.SIGTERM)
        return self.p.wait(timeout=30)


def publish(store, body, name="ads"):
    pull(store, {name: {"url": "https://example.invalid/x", "max_bytes": 100_000}}, fetch=lambda u, m, **kw: body.encode())
    accept(store, name, hashlib.sha256(body.encode()).hexdigest()[:12], allow_large_change=True)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "store")
    s.ensure()
    return s


def test_sighup_applies_an_accepted_update_to_a_running_daemon(tmp_path, store):
    publish(store, "a.example.com\n")
    d = Daemon(tmp_path, "--blocklist-store", str(store.root), "--no-resolve")
    try:
        d.wait_for("SIGHUP re-reads")
        d.wait_for("watching")
        publish(store, "a.example.com\nb.example.com\n")             # review + accept, as a person would
        d.p.send_signal(signal.SIGHUP)
        d.wait_for("reloaded blocklists: domains 1 -> 2 (+1/-0)")
        assert d.alive()
        publish(store, "a.example.com\nb.example.com\nc.example.com\n")
        d.p.send_signal(signal.SIGHUP)                                # and again: it keeps working
        d.wait_for("reloaded blocklists: domains 2 -> 3 (+1/-0)")
    finally:
        assert d.finish() == 0


def test_sighup_after_the_store_was_tampered_with_keeps_running_on_the_old_lists(tmp_path, store):
    publish(store, "a.example.com\n")
    d = Daemon(tmp_path, "--blocklist-store", str(store.root), "--no-resolve")
    try:
        d.wait_for("watching")
        store.path("active", "ads").write_text("")
        d.p.send_signal(signal.SIGHUP)
        d.wait_for("reload FAILED, keeping the previous lists")
        d.wait_for("does not match its pin")
        assert d.alive()
    finally:
        assert d.finish() == 0


def test_sighup_does_not_kill_a_daemon_that_has_no_lists(tmp_path):
    d = Daemon(tmp_path)
    try:
        d.wait_for("watching")
        d.p.send_signal(signal.SIGHUP)                               # the default action would be to terminate
        d.wait_for("nothing to reload")
        assert d.alive()
    finally:
        assert d.finish() == 0


def test_the_resolver_cache_does_not_keep_removed_domains(tmp_path):
    """A memory bound, not a safety property (the publish filter already guarantees correctness)."""
    res = DomainResolver(bl_of("cdn.example.com", "gone.example.com"), resolve=lambda n: DNS.get(n, []), max_per_cycle=10)
    res.cycle()
    res.rebind(bl_of("cdn.example.com"))
    assert set(res._dom_ips) == {"cdn.example.com"}
