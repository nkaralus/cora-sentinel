"""sync v2: key rotation chain, role separation, future-skew, epoch reset, compromise taint. Hermetic."""
import json
import os

import pytest

from cora_sentinel import blocklist_store as bs
from cora_sentinel import sync
from test_sync import (C1, C2, C3, NET, REPO, TRK, GitHub, Key, doms, render, snapshot)

NOW = 1_800_000_000
K1 = Key(b"\x11" * 32, bytes.fromhex("5bcebf452ddf4292"))      # genesis active (Dimgeon)
K2 = Key(b"\x22" * 32, bytes.fromhex("0102030405060708"))      # genesis standby (USB)
K3 = Key(b"\x33" * 32, bytes.fromhex("1112131415161718"))
K4 = Key(b"\x44" * 32, bytes.fromhex("2122232425262728"))
EVIL = Key(b"\x66" * 32, bytes.fromhex("6666666666666666"))


class Repo(GitHub):
    """Rotation files persist across commits, as they do in a git repo."""

    def __init__(self):
        super().__init__()
        self.rot = {}

    def add_rotation(self, n, body: dict, signer: Key, *, epoch_in_comment=None, repo=REPO, ts=NOW - 60):
        raw = (json.dumps(body, indent=2, sort_keys=True) + "\n").encode()
        tc = f"cora-keyrotation repo:{repo} epoch:{epoch_in_comment or n} timestamp:{ts}"
        self.rot[n] = (raw, signer.sign(raw, 0, comment=tc))

    def publish(self, commit, lists, ts, **kw):
        base = super().publish(commit, lists, ts, **kw)
        for n, (raw, sig) in self.rot.items():
            k = base.rsplit("/blocklists", 1)[0] + f"/keys/rotation-{n}"
            self.files[f"{k}.json"], self.files[f"{k}.json.minisig"] = raw, sig
        return base


def rotation(n, active: Key, standby: Key, revokes, compromised_after=None):
    return {"schema": sync.ROTATION_SCHEMA, "epoch": n, "active": sync.pub_b64(active.public),
            "standby": sync.pub_b64(standby.public), "revokes": [k.public.keyid_hex for k in revokes],
            "compromised_after": compromised_after}


@pytest.fixture
def gh():
    return Repo()


@pytest.fixture
def store(tmp_path):
    s = bs.Store(tmp_path / "store")
    s.ensure()
    return s


def go(store, gh, standby=K2, active=K1, **kw):
    logs = []
    rc = sync.run(store, REPO, "main", active.public, fetch=gh.fetch, log=logs.append, today="2026-11-06",
                  standby=standby.public if standby else None, now=NOW, **kw)
    return rc, "\n".join(logs)


def keys(store):
    return store.lock().get("cora_keys")


def active_text(store, name="community-trackers"):
    p = store.path("active", name)
    return p.read_text() if p.exists() else None


# ---------------------------------------------------------------- compatibility

def test_no_rotation_behaves_like_v1(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K1)
    rc, log = go(store, gh)
    assert rc == 0 and keys(store) is None
    assert store.lock()["cora_sync"]["epoch"] == 0


def test_without_standby_still_syncs_but_warns(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K1)
    rc, log = go(store, gh, standby=None)
    assert rc == 0 and "no standby key pinned" in log


def test_without_standby_a_published_rotation_is_refused(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    rc, log = go(store, gh, standby=None)
    assert rc == sync.EXIT_ERROR and "no standby key is pinned" in log


def test_standby_equal_to_active_refused(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K1)
    assert go(store, gh, standby=K1)[0] == sync.EXIT_ERROR


# ---------------------------------------------------------------- role separation

def test_standby_never_signs_manifests(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "STANDBY key" in log


def test_active_key_cannot_rotate(store, gh):
    """The whole point: a thief with K1 cannot install their own key or lock the owner out."""
    gh.add_rotation(1, rotation(1, EVIL, K3, [K1]), K1)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=EVIL)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "signed by the ACTIVE key" in log and keys(store) is None


def test_rotation_by_unknown_key_refused(store, gh):
    gh.add_rotation(1, rotation(1, EVIL, K3, [K1]), EVIL)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=EVIL)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and keys(store) is None


# ---------------------------------------------------------------- planned rotation

def test_planned_rotation(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K1)
    assert go(store, gh)[0] == 0
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C2, {TRK: render("t", ["criteo.com", "taboola.com"])}, ts=200, key=K2)
    rc, log = go(store, gh)
    assert rc == 0, log
    k = keys(store)
    assert k["epoch"] == 1 and k["revoked"] == [K1.public.keyid_hex]
    assert k["active"] == sync.pub_b64(K2.public) and k["standby"] == sync.pub_b64(K3.public)
    assert store.lock()["cora_sync"]["epoch"] == 1 and "taboola.com" in active_text(store)
    assert bs.verify(store) == []


def test_after_rotation_the_old_key_is_dead(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    assert go(store, gh)[0] == 0
    gh.publish(C2, {TRK: render("t", ["criteo.com", "x.net"])}, ts=200, key=K1)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "REVOKED" in log


def test_rotation_is_kept_even_if_the_manifest_is_not_signed_yet(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K1)
    go(store, gh)
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C2, {TRK: render("t", ["criteo.com"])}, ts=200, sign=False)
    rc, _ = go(store, gh)
    assert rc == sync.EXIT_UNSIGNED and keys(store)["epoch"] == 1
    assert "criteo.com" in active_text(store)                      # planned: lists stay


def test_two_rotations_in_one_pull(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.add_rotation(2, rotation(2, K3, K4, [K2]), K3)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K3)
    rc, log = go(store, gh)
    assert rc == 0, log
    k = keys(store)
    assert k["epoch"] == 2 and set(k["revoked"]) == {K1.public.keyid_hex, K2.public.keyid_hex}


def test_chain_must_start_from_the_etc_pins(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    go(store, gh)
    rc, log = go(store, gh, active=K3, standby=K4)               # someone swapped /etc
    assert rc == sync.EXIT_ERROR and "does not start from the keys pinned" in log


def test_rollback_does_not_roll_back_keys(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K1)
    go(store, gh)
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C2, {TRK: render("t", ["criteo.com", "x.net"])}, ts=200, key=K2)
    go(store, gh)
    assert sync.rollback(store, log=lambda m: None) == 0
    assert keys(store)["epoch"] == 1 and "x.net" not in active_text(store)


# ---------------------------------------------------------------- malformed rotations

@pytest.mark.parametrize("mutate,why", [
    (lambda b: b.update(epoch=2), "shape or epoch"),
    (lambda b: b.update(revokes=[]), "must revoke the outgoing active key"),
    (lambda b: b.update(active=sync.pub_b64(K1.public)), "is revoked"),
    (lambda b: b.update(standby=b["active"]), "same key"),
    (lambda b: b.update(compromised_after="yesterday"), "compromised_after"),
    (lambda b: b.update(schema="x"), "shape"),
    (lambda b: b.update(active="not a key"), "rotation-1 active"),
])
def test_malformed_rotation(store, gh, mutate, why):
    body = rotation(1, K2, K3, [K1])
    mutate(body)
    gh.add_rotation(1, body, K2)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and why in log and keys(store) is None


def test_rotation_comment_bound_to_epoch_and_repo(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2, epoch_in_comment=7)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    assert go(store, gh)[0] == sync.EXIT_ERROR
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2, repo="mallory/cora-security")
    gh.publish(C2, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    assert go(store, gh)[0] == sync.EXIT_ERROR


def test_rotation_without_signature_refused(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    base = gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    del gh.files[base.rsplit("/blocklists", 1)[0] + "/keys/rotation-1.json.minisig"]
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "no signature" in log


def test_rotation_file_tampered(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    base = gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    p = base.rsplit("/blocklists", 1)[0] + "/keys/rotation-1.json"
    gh.files[p] = gh.files[p].replace(sync.pub_b64(K3.public).encode(), sync.pub_b64(EVIL.public).encode())
    assert go(store, gh)[0] == sync.EXIT_ERROR and keys(store) is None


# ---------------------------------------------------------------- skew and epoch reset

def test_manifest_from_the_future_refused(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=NOW + sync.MAX_FUTURE_SKEW_S + 1, key=K1)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "in the future" in log


def test_manifest_just_inside_skew_ok(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=NOW + sync.MAX_FUTURE_SKEW_S - 1, key=K1)
    assert go(store, gh)[0] == 0


def test_rotation_from_the_future_refused(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2, ts=NOW + 2 * 86400)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_ERROR and "future" in log


def test_rotation_clears_a_poisoned_counter(store, gh):
    """A K1 thief signs ~24 h ahead to make every real update look like a replay; one rotation ends it."""
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=NOW + 86000, key=K1)
    assert go(store, gh)[0] == 0
    gh.publish(C2, {TRK: render("t", ["criteo.com", "x.net"])}, ts=NOW, key=K1)
    assert "replay refused" in go(store, gh)[1]
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C3, {TRK: render("t", ["criteo.com", "x.net"])}, ts=NOW, key=K2)
    rc, log = go(store, gh)
    assert rc == 0, log and "x.net" in active_text(store)


# ---------------------------------------------------------------- compromise

def seed30(store, gh, ts=100):
    gh.publish(C1, {TRK: render("t", doms(30))}, ts=ts, key=K1)
    assert go(store, gh)[0] == 0


def test_compromise_purges_tainted_lists_and_overrides_caps(store, gh):
    seed30(store, gh, ts=100)                                      # honest
    gh.publish(C2, {TRK: render("t", doms(30) + ["github.com"])}, ts=200, key=K1)   # the thief
    assert go(store, gh)[0] == 0
    gh.add_rotation(1, rotation(1, K2, K3, [K1], compromised_after=100), K2)
    gh.publish(C3, {TRK: render("t", doms(10))}, ts=50, key=K2)   # clean set: SHRINK would hold it
    rc, log = go(store, gh)
    assert rc == 0, log
    assert "TAINTED" in log                                        # purged, so nothing old to SHRINK against
    assert "github.com" not in active_text(store) and len(active_text(store).splitlines()) == 11
    assert "override_caps" not in keys(store)                      # spent
    assert bs.verify(store) == []


def test_compromise_with_clean_manifest_not_yet_signed(store, gh):
    seed30(store, gh, ts=100)
    gh.publish(C2, {TRK: render("t", doms(30) + ["github.com"])}, ts=200, key=K1)
    go(store, gh)
    gh.add_rotation(1, rotation(1, K2, K3, [K1], compromised_after=100), K2)
    gh.publish(C3, {TRK: render("t", doms(10))}, ts=0, sign=False)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_UNSIGNED
    assert active_text(store) is None and "community-trackers" not in store.lock()["lists"]
    assert not (store.root / "last-good").exists()                # it held tainted lists too
    assert bs.verify(store) == []                                  # the daemon still starts, on its own lists
    gh.publish(C3, {TRK: render("t", doms(10) + ["192.168.0.0/16"])}, ts=300, key=K2)
    rc, log = go(store, gh)                                        # next run: override survived the gap
    assert rc == 0, log
    assert "overrides the caps" in log and "LAN" in log           # policy (a): the K2-signed set wins
    assert "override_caps" not in keys(store)


def test_without_override_that_lan_entry_would_be_held(store, gh):
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K1)
    go(store, gh)
    gh.publish(C2, {TRK: render("t", ["criteo.com", "192.168.0.0/16"])}, ts=200, key=K1)
    assert go(store, gh)[0] == sync.EXIT_HELD                     # control for the test above


def test_compromise_declared_but_applied_set_predates_it(store, gh):
    seed30(store, gh, ts=100)
    gh.add_rotation(1, rotation(1, K2, K3, [K1], compromised_after=150), K2)
    gh.publish(C2, {TRK: render("t", doms(10))}, ts=50, key=K2)
    rc, log = go(store, gh)
    assert rc == sync.EXIT_HELD and "TAINTED" not in log          # not tainted: the caps still apply
    assert len(active_text(store).splitlines()) == 31


def test_dry_run_persists_no_rotation(store, gh):
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2)
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    before = snapshot(store)
    rc, log = go(store, gh, dry_run=True)
    assert rc == 0 and "key rotation" in log and snapshot(store) == before


def test_cli_standby_flag(tmp_path, gh, monkeypatch):
    for k, n in ((K1, "a.pub"), (K2, "s.pub")):
        (tmp_path / n).write_text(k.pub_text())
        os.chmod(tmp_path / n, 0o644)
    import time
    gh.add_rotation(1, rotation(1, K2, K3, [K1]), K2, ts=int(time.time()) - 60)   # the CLI uses the real clock
    gh.publish(C1, {TRK: render("t", ["criteo.com"])}, ts=100, key=K2)
    monkeypatch.setattr(bs, "fetch_url", gh.fetch)
    d = str(tmp_path / "store")
    argv = ["--dir", d, "sync", "--pubkey", str(tmp_path / "a.pub"), "--reload-cmd", ""]
    assert bs.main(argv + ["--standby-pubkey", str(tmp_path / "missing.pub")]) == 1   # rotation, no standby
    assert bs.main(argv + ["--standby-pubkey", str(tmp_path / "s.pub")]) == 0


def test_dispatcher_routes_sync_rollback_without_dir(tmp_path, monkeypatch, capsys):
    """The form typed in an emergency: no --dir, so the dispatcher's word list is what routes it."""
    from cora_sentinel import blocklist
    monkeypatch.setenv("CORA_BLOCKLIST_DIR", str(tmp_path / "s"))
    assert blocklist.main(["sync-rollback", "--reload-cmd", ""]) == 1     # routed; "no last-good" (2 = usage)
    assert "no last-good" in capsys.readouterr().out
