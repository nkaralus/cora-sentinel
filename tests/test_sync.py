"""cora-sync and the stdlib minisign verifier. Hermetic: a dict stands in for GitHub, a test-only
signer stands in for the owner's offline key, and real minisign 0.11 output anchors interop."""
import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from cora_sentinel import blocklist_store as bs
from cora_sentinel import minisign as ms
from cora_sentinel import sync
from cora_sentinel.blocklist import Blocklist

FIX = Path(__file__).parent / "fixtures" / "minisign"
REPO = "nkaralus/cora-security"
C1, C2, C3 = "a" * 40, "b" * 40, "c" * 40


# ---------------------------------------------------------------- test-only signer (RFC 8032 sign)

def _compress(P):
    zi = pow(P[2], ms._p - 2, ms._p)
    x, y = P[0] * zi % ms._p, P[1] * zi % ms._p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_sign(seed: bytes, msg: bytes):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _compress(ms._mul(a, ms._G))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % ms._L
    R = _compress(ms._mul(r, ms._G))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % ms._L
    return A, R + ((r + k * a) % ms._L).to_bytes(32, "little")


class Key:
    def __init__(self, seed=b"\x11" * 32, keyid=b"\x5b\xce\xbf\x45\x2d\xdf\x42\x92"):
        self.seed, self.keyid = seed, keyid
        self.pk, _ = ed25519_sign(seed, b"")

    @property
    def public(self):
        return ms.PublicKey(self.keyid, self.pk)

    def pub_text(self):
        return "untrusted comment: test key\n" + base64.b64encode(b"Ed" + self.keyid + self.pk).decode() + "\n"

    def sign(self, msg: bytes, ts: int, repo=REPO, comment=None):
        _, sig = ed25519_sign(self.seed, hashlib.blake2b(msg, digest_size=64).digest())
        tc = comment or f"cora-manifest repo:{repo} file:MANIFEST.json timestamp:{ts}"
        _, g = ed25519_sign(self.seed, sig + tc.encode())
        return (f"untrusted comment: signature from minisign secret key\n"
                f"{base64.b64encode(b'ED' + self.keyid + sig).decode()}\n"
                f"trusted comment: {tc}\n{base64.b64encode(g).decode()}\n").encode()


KEY = Key()


# ---------------------------------------------------------------- a fake GitHub

def render(name, entries):
    return ("\n".join([f"# {name}: compiled"] + list(entries)) + "\n").encode()


def manifest(lists, generated_from="2026-11-06T15:00:00Z"):
    return (json.dumps({"schema": sync.MANIFEST_SCHEMA, "generated_from": generated_from,
                        "accepted_reports": 1,
                        "lists": {f: {"sha256": hashlib.sha256(b).hexdigest(), "entries": 0, "sources": {}}
                                  for f, b in lists.items()}}, indent=2, sort_keys=True) + "\n").encode()


class GitHub:
    def __init__(self):
        self.files, self.head, self.calls, self.fail_after = {}, None, [], None

    def publish(self, commit, lists, ts, generated_from="2026-11-06T15:00:00Z", sign=True, key=KEY, **kw):
        base = f"https://raw.githubusercontent.com/{REPO}/{commit}/blocklists"
        m = manifest(lists, generated_from)
        self.files[f"{base}/MANIFEST.json"] = m
        if sign:
            self.files[f"{base}/MANIFEST.json.minisig"] = key.sign(m, ts, **kw)
        for f, b in lists.items():
            self.files[f"{base}/{f}"] = b
        self.head = commit
        return base

    def fetch(self, url, max_bytes, **kw):
        self.calls.append(url)
        if self.fail_after is not None and len(self.calls) > self.fail_after:
            raise bs.FetchError(f"{url}: [Errno 101] Network is unreachable")
        if url.endswith("/git/ref/heads/main"):
            return json.dumps({"object": {"sha": self.head}}).encode()
        if url not in self.files:
            raise bs.FetchError(f"{url}: HTTP 404 Not Found")
        data = self.files[url]
        if len(data) > max_bytes:
            raise bs.FetchError(f"{url}: exceeds the {max_bytes}-byte limit (aborted)")
        return data


@pytest.fixture
def gh():
    return GitHub()


@pytest.fixture
def store(tmp_path):
    s = bs.Store(tmp_path / "store")
    s.ensure()
    return s


def go(store, gh, **kw):
    logs = []
    rc = sync.run(store, REPO, "main", KEY.public, fetch=gh.fetch, log=logs.append, today="2026-11-06", **kw)
    return rc, "\n".join(logs)


def snapshot(store):
    return {p.relative_to(store.root).as_posix(): p.read_bytes()
            for p in sorted(store.root.rglob("*")) if p.is_file()}


def doms(n, prefix="t"):
    return [f"{prefix}{i}.tracker-test.net" for i in range(n)]


TRK = "community-trackers.txt"
NET = "community-subnets.txt"


# ---------------------------------------------------------------- the verifier itself

def test_rfc8032_vector_1():
    pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33ba"
                        "cc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ms.ed25519_verify(pk, b"", sig)
    assert not ms.ed25519_verify(pk, b"x", sig)


def test_test_signer_matches_rfc8032_vector_1():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk, sig = ed25519_sign(seed, b"")
    assert pk.hex().startswith("d75a9801") and sig.hex().startswith("e5564300")


@pytest.mark.parametrize("sigfile,prehashed", [("real-prehashed.minisig", True), ("real-legacy.minisig", False)])
def test_interop_with_real_minisign(sigfile, prehashed):
    pub = ms.load_public_key((FIX / "real.pub").read_text())
    v = ms.verify(pub, (FIX / "real.msg").read_bytes(), (FIX / sigfile).read_text())
    assert v.keyid_hex == "9242DF2D45BFCE5B" and v.prehashed is prehashed


def test_real_signature_rejects_altered_message_and_comment():
    pub = ms.load_public_key((FIX / "real.pub").read_text())
    sig = (FIX / "real-prehashed.minisig").read_text()
    with pytest.raises(ms.MinisignError, match="does not match"):
        ms.verify(pub, (FIX / "real.msg").read_bytes() + b" ", sig)
    with pytest.raises(ms.MinisignError, match="trusted comment"):
        ms.verify(pub, (FIX / "real.msg").read_bytes(), sig.replace("1762444800", "1999999999"))


def test_non_canonical_s_rejected():
    _, sig = ed25519_sign(KEY.seed, b"m")
    s = int.from_bytes(sig[32:], "little") + ms._L
    assert not ms.ed25519_verify(KEY.pk, b"m", sig[:32] + s.to_bytes(32, "little"))


# ---------------------------------------------------------------- happy path

def test_apply_pins_verifies_and_reloads(store, gh, tmp_path):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"]), NET: render("net", ["45.33.32.0/24"])}, ts=100)
    marker = tmp_path / "reloaded"
    rc, log = go(store, gh, reload_cmd=f"touch {marker}")
    assert rc == 0, log
    assert marker.exists()
    lock = store.lock()
    assert lock["lists"]["community-trackers"]["source"] == "cora-sync"
    assert lock["lists"]["community-trackers"]["url"].endswith(f"/{C1}/blocklists/{TRK}")
    assert lock["cora_sync"]["timestamp"] == 100 and lock["cora_sync"]["commit"] == C1
    assert bs.verify(store) == []
    bl = Blocklist()
    bs.load_verified(store.root, bl)                       # exactly what the daemon does at start and on HUP
    assert "criteo.com" in bl.entries()[0]
    assert not sync._journal(store).exists()


def test_every_url_is_pinned_to_one_commit(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    go(store, gh)
    raw = [u for u in gh.calls if "raw.githubusercontent" in u]
    assert raw and all(f"/{C1}/" in u for u in raw)


def test_second_run_is_a_noop(store, gh, tmp_path):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    go(store, gh)
    before = snapshot(store)
    marker = tmp_path / "r"
    rc, log = go(store, gh, reload_cmd=f"touch {marker}")
    assert rc == 0 and "unchanged" in log and not marker.exists()
    assert snapshot(store) == before


def test_pinned_ref_skips_the_api(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    rc = sync.run(store, REPO, C1, KEY.public, fetch=gh.fetch, log=lambda m: None)
    assert rc == 0 and not any("api.github.com" in u for u in gh.calls)


# ---------------------------------------------------------------- signatures

def test_flipped_signature_byte(store, gh):
    base = gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    lines = gh.files[f"{base}/MANIFEST.json.minisig"].decode().splitlines()
    raw = bytearray(base64.b64decode(lines[1]))
    raw[-1] ^= 1
    lines[1] = base64.b64encode(bytes(raw)).decode()
    gh.files[f"{base}/MANIFEST.json.minisig"] = ("\n".join(lines) + "\n").encode()
    before = snapshot(store)
    rc, _ = go(store, gh)
    assert rc == sync.EXIT_UNSIGNED and snapshot(store) == before


def test_signed_by_another_key(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100, key=Key(b"\x22" * 32, b"\x01" * 8))
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "not the pinned key" in log


def test_same_key_id_different_secret(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100, key=Key(b"\x33" * 32, KEY.keyid))
    rc, _ = go(store, gh)
    assert rc == sync.EXIT_UNSIGNED and "community-trackers" not in store.lock()["lists"]


def test_trusted_comment_swapped(store, gh):
    base = gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    p = f"{base}/MANIFEST.json.minisig"
    gh.files[p] = gh.files[p].replace(b"timestamp:100", b"timestamp:999")
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "altered" in log


def test_signature_for_another_repo(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100, repo="mallory/cora-security")
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "mallory" in log


def test_untagged_trusted_comment(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100, comment="timestamp:100 file:MANIFEST.json")
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "not a cora-manifest" in log


def test_no_signature_yet_waits(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100, sign=False)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_UNSIGNED and "no MANIFEST.json.minisig" in log


def test_compile_moved_manifest_old_signature_waits(store, gh):
    base = gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    stale_sig = gh.files[f"{base}/MANIFEST.json.minisig"]
    go(store, gh)
    base2 = gh.publish(C2, {TRK: render("trk", ["criteo.com", "taboola.com"])}, ts=0, sign=False)
    gh.files[f"{base2}/MANIFEST.json.minisig"] = stale_sig     # bot committed; owner has not re-signed
    rc, _ = go(store, gh)
    assert rc == sync.EXIT_UNSIGNED
    assert "taboola.com" not in store.path("active", "community-trackers").read_text()


def test_lists_not_fetched_before_signature_checks(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100, sign=False)
    go(store, gh)
    assert not any(u.endswith(TRK) for u in gh.calls)


def test_pubkey_permissions(tmp_path):
    p = tmp_path / "k.pub"
    p.write_text(KEY.pub_text())
    os.chmod(p, 0o644)
    assert sync.load_pubkey(p).keyid == KEY.keyid
    os.chmod(p, 0o666)
    with pytest.raises(sync.SyncError, match="writable"):
        sync.load_pubkey(p)


# ---------------------------------------------------------------- hashes and manifest

def test_list_hash_mismatch(store, gh):
    base = gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    gh.files[f"{base}/{TRK}"] = render("trk", ["criteo.com", "github.com"])
    before = snapshot(store)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "does not match the signed manifest" in log
    assert snapshot(store) == before


def test_mixed_snapshot_rejected(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    go(store, gh)
    base2 = gh.publish(C2, {TRK: render("trk", ["criteo.com", "taboola.com"])}, ts=200)
    gh.files[f"{base2}/{TRK}"] = gh.files[f"https://raw.githubusercontent.com/{REPO}/{C1}/blocklists/{TRK}"]
    rc, _ = go(store, gh)
    assert rc == sync.EXIT_ERROR and store.lock()["cora_sync"]["timestamp"] == 100


@pytest.mark.parametrize("fname", ["../lock.txt", "Community.txt", "x.json", "a/b.txt"])
def test_signed_manifest_with_hostile_file_name(store, gh, fname):
    gh.publish(C1, {fname: render("x", ["criteo.com"])}, ts=100)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "refusing list file name" in log


def test_name_collision_with_cora_blocklist_pin(store, gh):
    lock = store.lock()
    lock["lists"]["community-trackers"] = {"url": "https://x/y", "sha256": "0" * 64, "bytes": 1,
                                           "entries": 1, "approved": "2026-11-01"}
    store.save_lock(lock)
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "already pinned by `cora-blocklist`" in log


# ---------------------------------------------------------------- replay

def test_older_signature_replayed(store, gh):
    gh.publish(C2, {TRK: render("trk", ["criteo.com", "taboola.com"])}, ts=200)
    assert go(store, gh)[0] == 0
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "replay refused" in log
    assert "taboola.com" in store.path("active", "community-trackers").read_text()


def test_same_timestamp_different_manifest(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    go(store, gh)
    gh.publish(C2, {TRK: render("trk", ["taboola.com"])}, ts=100)
    assert go(store, gh)[0] == sync.EXIT_ERROR


def test_generated_from_going_backwards(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100, generated_from="2026-11-06T15:00:00Z")
    go(store, gh)
    gh.publish(C2, {TRK: render("trk", ["criteo.com", "x.net"])}, ts=200, generated_from="2026-01-01T00:00:00Z")
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "generated_from" in log


# ---------------------------------------------------------------- delta caps

def seed(store, gh, n=30):
    gh.publish(C1, {TRK: render("trk", doms(n))}, ts=100)
    assert go(store, gh)[0] == 0


def test_small_lists_grow_freely(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    go(store, gh)
    gh.publish(C2, {TRK: render("trk", ["criteo.com", "taboola.com"])}, ts=200)
    assert go(store, gh)[0] == 0                            # +100% on a 1-entry list is not "large"


@pytest.mark.parametrize("new,flag", [
    (doms(10), "SHRINK"),
    (doms(30) + doms(20, "n"), "LARGE CHANGE"),
    ([], "EMPTIED"),
])
def test_caps_hold(store, gh, new, flag):
    seed(store, gh)
    gh.publish(C2, {TRK: render("trk", new)}, ts=200)
    before = snapshot(store)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_HELD and flag in log
    assert snapshot(store) == before


def test_burst_cap(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    go(store, gh)
    gh.publish(C2, {TRK: render("trk", doms(sync.MAX_ADDED + 1))}, ts=200)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_HELD and "BURST" in log


def test_lan_entry_held_even_if_signed(store, gh):
    gh.publish(C1, {NET: render("net", ["45.33.32.0/24"])}, ts=100)
    go(store, gh)
    gh.publish(C2, {NET: render("net", ["45.33.32.0/24", "192.168.1.0/24"])}, ts=200)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_HELD and "LAN" in log


def test_dropped_list_held_then_removed_with_override(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"]), NET: render("net", ["45.33.32.0/24"])}, ts=100)
    go(store, gh)
    gh.publish(C2, {TRK: render("trk", ["criteo.com"])}, ts=200)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_HELD and "REMOVED" in log
    assert go(store, gh, allow_large_change=True)[0] == 0
    assert "community-subnets" not in store.lock()["lists"]
    assert not store.path("active", "community-subnets").exists()
    assert bs.verify(store) == []


def test_override_applies(store, gh):
    seed(store, gh)
    gh.publish(C2, {TRK: render("trk", doms(10))}, ts=200)
    assert go(store, gh, allow_large_change=True)[0] == 0
    assert store.lock()["cora_sync"]["timestamp"] == 200


def test_dry_run_writes_nothing(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    before = snapshot(store)
    rc, log = go(store, gh, dry_run=True)
    assert rc == 0 and "would apply" in log and snapshot(store) == before


# ---------------------------------------------------------------- network drops

@pytest.mark.parametrize("after", [0, 1, 2, 3])
def test_network_drop_mid_pull_changes_nothing(store, gh, after):
    seed(store, gh)
    gh.publish(C2, {TRK: render("trk", doms(31)), NET: render("net", ["45.33.32.0/24"])}, ts=200)
    gh.calls, gh.fail_after = [], after                    # die on the ref, manifest, signature, or first list
    before = snapshot(store)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "nothing changed" in log
    assert snapshot(store) == before
    gh.fail_after = None
    assert go(store, gh)[0] == 0                            # and the next run just works


def test_oversized_response(store, gh):
    base = gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    gh.files[f"{base}/MANIFEST.json.minisig"] += b"x" * sync.SIG_MAX
    assert go(store, gh)[0] == sync.EXIT_ERROR


# ---------------------------------------------------------------- crash, verify, rollback

def test_crash_before_commit_is_undone_next_run(store, gh, monkeypatch):
    seed(store, gh)
    good = store.path("active", "community-trackers").read_bytes()
    gh.publish(C2, {TRK: render("trk", doms(31))}, ts=200)

    real = bs.Store.save_lock
    def crash(self, lock):
        if lock.get("cora_sync", {}).get("timestamp") == 200:
            raise SystemExit("power cut")
        real(self, lock)
    monkeypatch.setattr(bs.Store, "save_lock", crash)
    with pytest.raises(SystemExit):
        go(store, gh)
    assert bs.verify(store)                                 # the daemon would refuse this state: fail closed
    monkeypatch.setattr(bs.Store, "save_lock", real)

    gh.calls, gh.fail_after = [], 0                         # and the network is still down on the next run
    rc, log = go(store, gh)
    assert "restoring last-good" in log and rc == sync.EXIT_ERROR
    assert bs.verify(store) == []                           # consistent again WITHOUT the retry succeeding
    assert store.path("active", "community-trackers").read_bytes() == good
    gh.fail_after = None
    rc, log = go(store, gh)
    assert rc == 0                                          # then the retry applies cleanly
    assert bs.verify(store) == [] and store.lock()["cora_sync"]["timestamp"] == 200
    assert store.path("active", "community-trackers").read_bytes() != good


def test_failed_post_apply_verify_restores_last_good(store, gh, monkeypatch):
    seed(store, gh)
    good = snapshot(store)["active/community-trackers.txt"]
    gh.publish(C2, {TRK: render("trk", doms(31))}, ts=200)
    real = bs.verify
    calls = {"n": 0}
    def flaky(s):
        calls["n"] += 1
        return ["simulated: active file does not match its pin"] if calls["n"] == 1 else real(s)
    monkeypatch.setattr(bs, "verify", flaky)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "restored last-good" in log
    assert store.path("active", "community-trackers").read_bytes() == good
    assert store.lock()["cora_sync"]["timestamp"] == 100


def test_rollback_refuses_that_signature_until_a_newer_one(store, gh):
    seed(store, gh)
    v1 = store.path("active", "community-trackers").read_bytes()
    gh.publish(C2, {TRK: render("trk", doms(31))}, ts=200)
    assert go(store, gh)[0] == 0
    assert sync.rollback(store, log=lambda m: None) == 0
    assert store.path("active", "community-trackers").read_bytes() == v1
    assert bs.verify(store) == []
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "rolled back by the operator" in log
    gh.publish(C3, {TRK: render("trk", doms(32))}, ts=300)
    assert go(store, gh)[0] == 0


def test_other_pins_survive_apply_and_rollback(store, gh):
    data = b"ads.example.org\n"
    bs.atomic_write(store.path("active", "mine"), data)
    lock = store.lock()
    lock["lists"]["mine"] = {"url": "https://x/mine", "sha256": bs.sha256(data), "bytes": len(data),
                             "entries": 1, "approved": "2026-11-01"}
    store.save_lock(lock)
    seed(store, gh)
    gh.publish(C2, {TRK: render("trk", doms(31))}, ts=200)
    go(store, gh)
    sync.rollback(store, log=lambda m: None)
    assert store.lock()["lists"]["mine"]["sha256"] == bs.sha256(data)
    assert bs.verify(store) == []


def test_reload_failure_is_not_fatal(store, gh):
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    rc, log = go(store, gh, reload_cmd="false")
    assert rc == 0 and "next start" in log and bs.verify(store) == []


def test_cli_end_to_end(tmp_path, gh, monkeypatch):
    pub = tmp_path / "k.pub"
    pub.write_text(KEY.pub_text())
    os.chmod(pub, 0o644)
    gh.publish(C1, {TRK: render("trk", ["criteo.com"])}, ts=100)
    monkeypatch.setattr(bs, "fetch_url", gh.fetch)
    d = str(tmp_path / "store")
    assert bs.main(["--dir", d, "sync", "--pubkey", str(pub), "--reload-cmd", ""]) == 0
    assert bs.main(["--dir", d, "verify"]) == 0
    assert bs.main(["--dir", d, "sync-rollback", "--reload-cmd", ""]) == 0
    assert bs.main(["--dir", d, "sync", "--pubkey", str(tmp_path / "missing.pub")]) == 1
