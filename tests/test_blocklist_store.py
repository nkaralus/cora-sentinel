"""Pinned, reviewed blocklist updates. Run: pytest -q tests/test_blocklist_store.py"""
import hashlib
import json
import os
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cora_sentinel import blocklist_store as bs
from cora_sentinel.blocklist import Blocklist
from cora_sentinel.blocklist_store import (FetchError, Store, StoreError, accept, analyze, fetch_url,
                                           load_sources, load_verified, main, mutable_ref_warning, pull, review,
                                           validate_text, verify)

ROOT = Path(__file__).resolve().parents[1]
GOOD = "tracker.example.com\nads.example.net\n198.51.100.0/24\n"
URL = "https://example.invalid/ads.txt"


def sources(**extra):
    return {"ads": {"url": URL, "max_bytes": 100_000}, **extra}


def fetcher(body=GOOD):
    """A fake fetch whose content the test controls (and can change, like a compromised upstream)."""
    box = {"body": body}

    def fetch(url, max_bytes, **kw):
        b = box["body"]
        if isinstance(b, Exception):
            raise b
        return b.encode() if isinstance(b, str) else b
    fetch.box = box
    return fetch


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "store")
    s.ensure()
    return s


def approve(store, name="ads", body=GOOD, **kw):
    f = fetcher(body)
    pull(store, sources(), fetch=f)
    h = hashlib.sha256(body.encode()).hexdigest()
    accept(store, name, h[:12], **kw)
    return f, h


# ============================ sources.json ============================
def write(tmp, obj):
    p = tmp / "sources.json"
    p.write_text(json.dumps(obj))
    return p


def test_a_valid_sources_file_loads(tmp_path):
    out = load_sources(write(tmp_path, {"version": 1, "lists": {"ads": {"url": URL}}}))
    assert out == {"ads": {"url": URL, "max_bytes": bs.DEFAULT_MAX_BYTES}}


@pytest.mark.parametrize("obj,why", [
    ({"version": 2, "lists": {}}, "version"),
    ({"version": 1}, "lists"),
    ({"version": 1, "lists": {"Bad Name": {"url": URL}}}, "list name"),
    ({"version": 1, "lists": {"../x": {"url": URL}}}, "list name"),
    ({"version": 1, "lists": {"a": {"url": "http://example.com/x"}}}, "https"),
    ({"version": 1, "lists": {"a": {"url": "file:///etc/passwd"}}}, "https"),
    ({"version": 1, "lists": {"a": {"url": "https://x/<COMMIT-SHA>/y"}}}, "placeholder"),
    ({"version": 1, "lists": {"a": {"url": URL, "token": "x"}}}, "allowed keys"),
    ({"version": 1, "lists": {"a": {"url": URL, "max_bytes": 0}}}, "max_bytes"),
    ({"version": 1, "lists": {"a": {"url": URL, "max_bytes": 10**10}}}, "max_bytes"),
    ({"version": 1, "lists": {"a": {"url": URL, "max_bytes": True}}}, "max_bytes")])
def test_a_malformed_sources_file_is_refused_with_a_reason(tmp_path, obj, why):
    with pytest.raises(StoreError, match=why):
        load_sources(write(tmp_path, obj))


def test_the_shipped_example_cannot_be_used_until_its_placeholder_is_replaced():
    with pytest.raises(StoreError, match="placeholder"):
        load_sources(ROOT / "examples" / "sources.json")


@pytest.mark.parametrize("url,warns", [
    ("https://raw.githubusercontent.com/o/r/main/x.txt", True),
    ("https://raw.githubusercontent.com/o/r/" + "a" * 40 + "/x.txt", False),
    ("https://raw.githubusercontent.com/o/r/v1.2/x.txt", True),
    ("https://github.com/o/r/blob/main/x.txt", True),
    ("https://example.com/lists/ads.txt", False)])
def test_a_mutable_github_ref_is_warned_about_and_a_commit_is_not(url, warns):
    assert bool(mutable_ref_warning(url)) is warns


# ============================ content limits ============================
@pytest.mark.parametrize("data,why", [
    (b"a.example.com\0b", "NUL"), (b"\xff\xfe\xfa", "UTF-8"),
    (b"x\n" * (bs.MAX_LINES + 1), "lines"), (b"a" * (bs.MAX_LINE_CHARS + 1), "longer")])
def test_unacceptable_content_is_refused(data, why):
    with pytest.raises(StoreError, match=why):
        validate_text(data)


# ============================ the review flags ============================
def test_a_first_list_is_flagged_new_but_not_blocking():
    d = analyze(None, GOOD)
    assert d.flags == ["NEW LIST"] and d.blocking == [] and d.new_entries == 3


def test_documentation_ranges_are_not_mistaken_for_your_lan():
    assert "LAN" not in analyze(None, "198.51.100.0/24\n203.0.113.0/24\n192.0.2.0/24\n").flags


def test_a_small_ordinary_change_has_no_blocking_flags():
    old = "\n".join(f"d{i}.example.com" for i in range(20)) + "\n"
    assert analyze(old, old + "new.example.com\n").blocking == []


def test_a_large_rewrite_is_flagged():
    old = "\n".join(f"d{i}.example.com" for i in range(20)) + "\n"
    new = "\n".join(f"x{i}.example.com" for i in range(20)) + "\n"
    assert "LARGE CHANGE" in analyze(old, new).flags


@pytest.mark.parametrize("new,flag", [("", "EMPTIED"), ("# nothing here\n", "EMPTIED"),
                                      ("d0.example.com\n", "SHRINK")])
def test_a_list_that_is_emptied_or_gutted_is_flagged_because_that_silently_disables_detection(new, flag):
    old = "\n".join(f"d{i}.example.com" for i in range(20)) + "\n"
    assert flag in analyze(old, new).flags


def test_a_list_that_starts_blocking_your_own_network_is_flagged():
    for net in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16"):
        assert "LAN" in analyze(GOOD, GOOD + net + "\n").flags


def test_a_list_that_fills_up_with_malformed_or_overbroad_entries_is_flagged():
    junk = "\n".join(["0.0.0.0/0", "127.0.0.1", "not an entry"] * 8)
    assert "REJECTS UP" in analyze(GOOD, GOOD + junk + "\n").flags


# ============================ the core guarantee ============================
def test_a_first_pull_stages_and_never_activates(store):
    r = pull(store, sources(), fetch=fetcher())
    assert [(x.name, x.status) for x in r] == [("ads", "staged")]
    assert not store.path("active", "ads").exists() and store.lock()["lists"] == {}


def test_accept_needs_the_hash_of_exactly_what_was_reviewed(store):
    pull(store, sources(), fetch=fetcher())
    with pytest.raises(StoreError, match="does not match"):
        accept(store, "ads", "0" * 12)
    with pytest.raises(StoreError, match="does not match"):
        accept(store, "ads", hashlib.sha256(GOOD.encode()).hexdigest()[:11])        # too short to count
    assert not store.path("active", "ads").exists()


def test_accept_activates_pins_and_clears_staging(store):
    approve(store, today="2026-11-05")
    h = hashlib.sha256(GOOD.encode()).hexdigest()
    assert store.path("active", "ads").read_text() == GOOD
    assert store.lock()["lists"]["ads"] == {"url": URL, "sha256": h, "bytes": len(GOOD), "entries": 3,
                                            "approved": "2026-11-05"}
    assert not store.path("staging", "ads").exists() and verify(store) == []


def test_an_unchanged_upstream_is_a_no_op(store):
    f, h = approve(store)
    assert [r.status for r in pull(store, sources(), fetch=f)] == ["unchanged"]


def test_AN_UPSTREAM_CHANGE_NEVER_REACHES_THE_ACTIVE_LIST_WITHOUT_APPROVAL(store):
    """The property the whole design exists for: a compromised upstream changes nothing until you approve."""
    f, h = approve(store)
    before = store.path("active", "ads").read_bytes()
    f.box["body"] = GOOD + "evil.example.org\n"                 # upstream is now compromised
    assert [r.status for r in pull(store, sources(), fetch=f)] == ["staged"]
    assert store.path("active", "ads").read_bytes() == before   # active is untouched
    assert store.lock()["lists"]["ads"]["sha256"] == h          # and so is the pin
    assert "evil.example.org" in store.path("staging", "ads").read_text()


def test_a_tampered_active_file_is_restored_when_upstream_still_matches_the_pin(store):
    f, h = approve(store)
    store.path("active", "ads").write_text("")                  # someone emptied the active list
    assert verify(store) != []
    assert [r.status for r in pull(store, sources(), fetch=f)] == ["repaired"]
    assert store.path("active", "ads").read_text() == GOOD and verify(store) == []


def test_verify_names_every_kind_of_damage(store):
    approve(store)
    store.path("active", "ads").write_text(GOOD + "extra.example.com\n")
    (store.active / "stray.txt").write_text("x.example.com\n")
    msgs = " | ".join(verify(store))
    assert "does not match its pin" in msgs and "stray: an active file with no pin" in msgs
    store.path("active", "ads").unlink()
    assert "missing" in " | ".join(verify(store))


def test_flagged_updates_need_an_explicit_override(store):
    old = "\n".join(f"d{i}.example.com" for i in range(20)) + "\n"
    f, _ = approve(store, body=old)
    f.box["body"] = ""                                          # the list is emptied upstream
    pull(store, sources(), fetch=f)
    h = hashlib.sha256(b"").hexdigest()
    with pytest.raises(StoreError, match="EMPTIED"):
        accept(store, "ads", h[:12])
    assert store.path("active", "ads").read_text() == old       # still the approved list
    accept(store, "ads", h[:12], allow_large_change=True)
    assert store.path("active", "ads").read_text() == ""


def test_a_staged_file_edited_after_the_pull_is_caught(store):
    pull(store, sources(), fetch=fetcher())
    store.path("staging", "ads").write_text(GOOD + "sneaky.example.com\n")
    with pytest.raises(StoreError, match="recorded hash"):
        review(store, "ads")


def test_a_changed_url_needs_approval_even_when_the_content_is_identical(store):
    f, _ = approve(store)
    moved = {"ads": {"url": "https://elsewhere.invalid/ads.txt", "max_bytes": 100_000}}
    assert [r.status for r in pull(store, moved, fetch=f)] == ["staged"]
    d, _, h = review(store, "ads")
    assert "URL CHANGED" in d.flags
    with pytest.raises(StoreError, match="URL CHANGED"):
        accept(store, "ads", h[:12])


def test_one_failing_list_does_not_stop_or_damage_the_others(store):
    good, bad = fetcher(), fetcher(FetchError("boom"))
    srcs = {"ads": {"url": URL, "max_bytes": 1000}, "bad": {"url": URL + "2", "max_bytes": 1000}}

    def fetch(url, mb, **kw):
        return (good if url == URL else bad)(url, mb)
    r = {x.name: x for x in pull(store, srcs, fetch=fetch)}
    assert r["ads"].status == "staged" and r["bad"].status == "error" and "boom" in r["bad"].detail
    assert not store.path("staging", "bad").exists()


def test_a_failed_fetch_leaves_the_active_list_exactly_as_it_was(store):
    f, _ = approve(store)
    before = store.path("active", "ads").read_bytes()
    f.box["body"] = FetchError("network down")
    assert [r.status for r in pull(store, sources(), fetch=f)] == ["error"]
    assert store.path("active", "ads").read_bytes() == before and verify(store) == []


def test_a_crash_while_writing_leaves_no_half_written_file(tmp_path, monkeypatch):
    target = tmp_path / "list.txt"
    target.write_text("old\n")
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        bs.atomic_write(target, b"new content\n")
    assert target.read_text() == "old\n" and [p.name for p in tmp_path.iterdir()] == ["list.txt"]


# ============================ the store itself ============================
def test_a_world_writable_store_is_refused(tmp_path):
    s = Store(tmp_path / "s")
    s.ensure()
    os.chmod(s.root, 0o777)
    with pytest.raises(StoreError, match="world-writable"):
        s.check_perms()
    assert any("world-writable" in p for p in verify(s))


def test_a_symlinked_store_directory_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(StoreError, match="symlink"):
        Store(tmp_path / "link").check_perms()


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="root-only rule")
def test_as_root_a_group_writable_store_is_refused(tmp_path):
    s = Store(tmp_path / "s")
    s.ensure()
    os.chmod(s.root, 0o770)
    with pytest.raises(StoreError, match="group-writable"):
        s.check_perms()


def test_the_daemon_loader_returns_only_approved_lists_and_warns_when_they_are_stale(store):
    approve(store, today="2020-01-01")
    bl = Blocklist()
    warnings = load_verified(store.root, bl)
    assert bl.match_domain("x.tracker.example.com") and any("days ago" in w for w in warnings)


def test_the_daemon_loader_refuses_a_store_that_fails_verification(store):
    approve(store)
    store.path("active", "ads").write_text("")
    with pytest.raises(StoreError, match="refusing to run on lists nobody approved"):
        load_verified(store.root, Blocklist())


# ============================ the CLI ============================
def run_cli(tmp_path, monkeypatch, capsys, *args, body=GOOD):
    monkeypatch.setattr(bs, "fetch_url", fetcher(body))
    capsys.readouterr()
    rc = main(["--dir", str(tmp_path / "store"), *args])
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def test_the_cli_walks_the_whole_review_flow_with_the_documented_exit_codes(tmp_path, monkeypatch, capsys):
    (tmp_path / "store").mkdir(mode=0o700)
    write(tmp_path / "store", {"version": 1, "lists": {"ads": {"url": URL}}})
    rc, out, _ = run_cli(tmp_path, monkeypatch, capsys, "pull")
    assert rc == bs.EXIT_STAGED and "STAGED" in out
    rc, out, _ = run_cli(tmp_path, monkeypatch, capsys, "diff")
    assert rc == 0 and "NEW LIST" in out and "+ domain:tracker.example.com" in out
    h = hashlib.sha256(GOOD.encode()).hexdigest()
    rc, _, err = run_cli(tmp_path, monkeypatch, capsys, "accept", "ads", "--sha256", "deadbeefdead")
    assert rc == bs.EXIT_ERROR and "does not match" in err
    rc, out, _ = run_cli(tmp_path, monkeypatch, capsys, "accept", "ads", "--sha256", h[:12])
    assert rc == 0 and "accepted" in out
    rc, out, _ = run_cli(tmp_path, monkeypatch, capsys, "pull")
    assert rc == bs.EXIT_OK and "UNCHANGED" in out
    rc, out, _ = run_cli(tmp_path, monkeypatch, capsys, "verify")
    assert rc == 0 and out.startswith("OK")
    rc, out, _ = run_cli(tmp_path, monkeypatch, capsys, "status")
    assert rc == 0 and "pinned " + h[:12] in out
    rc, _, _ = run_cli(tmp_path, monkeypatch, capsys, "pull", body="x")        # unchanged is not an error ...
    assert rc == bs.EXIT_STAGED                                                # ... a changed upstream is staged


def test_a_cli_pull_error_exits_1_and_warns_about_mutable_refs(tmp_path, monkeypatch, capsys):
    (tmp_path / "store").mkdir(mode=0o700)
    write(tmp_path / "store", {"version": 1, "lists": {"ads": {"url": "https://raw.githubusercontent.com/o/r/main/a.txt"}}})
    rc, out, err = run_cli(tmp_path, monkeypatch, capsys, "pull", body=FetchError("down"))
    assert rc == bs.EXIT_ERROR and "ERROR" in out and "mutable ref 'main'" in err


def test_the_existing_check_command_still_works(tmp_path, capsys):
    from cora_sentinel.blocklist import main as bl_main
    f = tmp_path / "l.txt"
    f.write_text("tracker.example.com\n")
    assert bl_main(["check", str(f), "a.tracker.example.com"]) == 0
    assert "tracker_domain" in capsys.readouterr().out


# ============================ the daemon refuses an untrusted store ============================
def _daemon(tmp_path, store_dir):
    return subprocess.Popen([sys.executable, "-m", "cora_sentinel.daemon", "--blocklist-store", str(store_dir),
                             "--interval", "0.2", "--out", str(tmp_path / "ev.jsonl")],
                            stderr=subprocess.PIPE, text=True, cwd=tmp_path)


def test_the_daemon_refuses_to_start_on_a_tampered_store(tmp_path, store):
    approve(store)
    store.path("active", "ads").write_text("")
    p = _daemon(tmp_path, store.root)
    err = p.communicate(timeout=30)[1]
    assert p.returncode == 1 and "failed verification" in err and "does not match its pin" in err


def test_the_daemon_starts_on_a_verified_store_and_says_what_it_loaded(tmp_path, store):
    approve(store)
    p = _daemon(tmp_path, store.root)
    seen = []
    end = time.monotonic() + 30
    while time.monotonic() < end:
        line = p.stderr.readline()
        seen.append(line)
        if "watching" in line:
            break
    p.send_signal(signal.SIGINT)
    p.communicate(timeout=30)
    text = "".join(seen)
    assert "blocklist: 2 domains, 1 subnets/IPs" in text and "failed verification" not in text


# ============================ the fetcher, against a REAL local https server ============================
@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("needs the openssl CLI to make a test certificate")
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"),
                    "-out", str(d / "c.pem"), "-days", "2", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
    sent = {"big": 0}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _head(self, code, **hdr):
            self.send_response(code)
            for k, v in hdr.items():
                self.send_header(k.replace("_", "-"), str(v))
            self.end_headers()

        def do_GET(self):
            p = self.path
            if p == "/list.txt":
                body = GOOD.encode()
                self._head(200, Content_Length=len(body))
                self.wfile.write(body)
            elif p == "/missing":
                self._head(404, Content_Length=0)
            elif p == "/cl":
                self._head(200, Content_Length=10**9, Connection="close")
            elif p == "/big":
                self._head(200, Connection="close")
                try:
                    while sent["big"] < 200_000_000:
                        self.wfile.write(b"a.example.com\n" * 4000)
                        sent["big"] += 56000
                except OSError:
                    pass
            elif p == "/slow":
                self._head(200, Connection="close")
                try:
                    for _ in range(100):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.2)
                except OSError:
                    pass
            elif p == "/to-http":
                self._head(302, Location="http://localhost:1/x", Content_Length=0)
            elif p == "/to-https":
                self._head(302, Location="/list.txt", Content_Length=0)
            elif p == "/loop":
                self._head(302, Location="/loop", Content_Length=0)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    trust = ssl.create_default_context(cafile=str(d / "c.pem"))
    yield f"https://localhost:{srv.server_address[1]}", trust, sent
    srv.shutdown()


def test_a_trusted_https_fetch_returns_the_body(tls):
    base, trust, _ = tls
    assert fetch_url(f"{base}/list.txt", context=trust) == GOOD.encode()


def test_a_certificate_we_do_not_trust_is_rejected(tls):
    base, _, _ = tls
    with pytest.raises(FetchError, match="(?i)certificate"):
        fetch_url(f"{base}/list.txt")                       # default trust store: the test CA is not in it


def test_plain_http_is_refused_before_any_connection():
    with pytest.raises(FetchError, match="only https"):
        fetch_url("http://example.com/list.txt")


def test_a_404_is_an_error_not_an_empty_list(tls):
    base, trust, _ = tls
    with pytest.raises(FetchError, match="404"):
        fetch_url(f"{base}/missing", context=trust)


def test_a_redirect_to_plain_http_is_refused(tls):
    base, trust, _ = tls
    with pytest.raises(FetchError, match="non-https"):
        fetch_url(f"{base}/to-http", context=trust)


def test_a_redirect_that_stays_on_https_is_followed(tls):
    base, trust, _ = tls
    assert fetch_url(f"{base}/to-https", context=trust) == GOOD.encode()


def test_a_redirect_loop_is_cut_off(tls):
    base, trust, _ = tls
    with pytest.raises(FetchError):
        fetch_url(f"{base}/loop", context=trust)


def test_an_endless_response_is_aborted_at_the_limit_not_downloaded(tls):
    base, trust, sent = tls
    sent["big"] = 0
    with pytest.raises(FetchError, match="exceeds the 100000-byte limit"):
        fetch_url(f"{base}/big", max_bytes=100_000, context=trust)
    time.sleep(0.3)
    assert sent["big"] < 60_000_000                         # the server was cut off long before 200 MB


def test_a_lying_content_length_is_rejected_without_reading_the_body(tls):
    base, trust, _ = tls
    with pytest.raises(FetchError, match="Content-Length"):
        fetch_url(f"{base}/cl", max_bytes=100_000, context=trust)


def test_a_server_that_trickles_cannot_hold_the_fetch_open(tls):
    base, trust, _ = tls
    t = time.monotonic()
    with pytest.raises(FetchError, match="deadline"):
        fetch_url(f"{base}/slow", timeout=5, deadline_s=1.0, context=trust)
    assert time.monotonic() - t < 4


def test_pull_works_end_to_end_over_real_tls(tmp_path, tls):
    base, trust, _ = tls
    s = Store(tmp_path / "store")
    r = pull(s, {"ads": {"url": f"{base}/list.txt", "max_bytes": 100_000}}, context=trust)
    assert [(x.name, x.status) for x in r] == [("ads", "staged")]
    h = hashlib.sha256(GOOD.encode()).hexdigest()
    accept(s, "ads", h[:12])
    assert verify(s) == [] and s.path("active", "ads").read_text() == GOOD
