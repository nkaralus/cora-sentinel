"""Ephemeral launch scopes (cora_sentinel.scope). A temp directory stands in for the task tree; the last test uses the
real kernel where a writable cgroup v2 tree exists (root on a real machine)."""
import json
import os
import pathlib
import stat
import subprocess
import sys
import time

import pytest

from cora_sentinel import scope as sc
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.scope import ScopeError, Scopes, parse_size

GiB = 1 << 30


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "cora"
    root.mkdir()
    return CgroupRoot(str(root))


@pytest.fixture
def clock():
    return Clock()


def tokens(*vals):
    it = iter(vals)
    return lambda n: next(it)


def make(tree, clock, **kw):
    return Scopes(tree, state_path=str(tree.root.parent / "scopes.json"), clock=clock, **kw)


def events(tree, name, populated):
    (tree.root / name / "cgroup.events").write_text(f"populated {int(populated)}\nfrozen 0\n")


# ---------------------------------------------------------------- create

def test_name_is_app_plus_six_hex_and_limits_are_written(tree, clock):
    s = make(tree, clock, token=tokens("a1b2c3"))
    name = s.create_scope("steam-570", uid=1000, memory_max="8G", memory_high="7G")
    assert name == "steam-570-a1b2c3"
    d = tree.root / name
    assert (d / "memory.max").read_text() == str(8 * GiB) and (d / "memory.high").read_text() == str(7 * GiB)
    assert s.describe(name)["uid"] == 1000 and s.describe(name)["entered"] is False


def test_never_adopts_an_existing_directory(tree, clock):
    (tree.root / "game-aaaaaa").mkdir()
    s = make(tree, clock, token=tokens("aaaaaa", "bbbbbb"))
    assert s.create_scope("game", uid=1000) == "game-bbbbbb"


def test_no_limits_is_allowed_and_writes_nothing(tree, clock):
    name = make(tree, clock).create_scope("tool", uid=1000)
    assert not (tree.root / name / "memory.max").exists()


@pytest.mark.parametrize("app", ["", "Steam", "../x", "-x", "a" * 33, "a b", "a.b", 7, None])
def test_bad_app_names_refused(tree, clock, app):
    with pytest.raises(ScopeError):
        make(tree, clock).create_scope(app, uid=1000)
    assert list(tree.root.iterdir()) == []


@pytest.mark.parametrize("uid", [-1, True, "1000", None])
def test_uid_must_be_a_real_number(tree, clock, uid):
    with pytest.raises(ScopeError):
        make(tree, clock).create_scope("game", uid=uid)


def test_high_above_max_refused(tree, clock):
    with pytest.raises(ScopeError, match="must not exceed"):
        make(tree, clock).create_scope("game", uid=1000, memory_max="4G", memory_high="6G")
    assert list(tree.root.iterdir()) == []


@pytest.mark.parametrize("v,n", [("512M", 512 << 20), ("8G", 8 * GiB), ("1t", 1 << 40), (128 << 20, 128 << 20),
                                 (" 2G ", 2 * GiB), (None, None)])
def test_parse_size(v, n):
    assert parse_size(v) == n


@pytest.mark.parametrize("v", ["8 GB", "lots", "-1G", "1.5G", True, "1M"])
def test_parse_size_refuses(v):
    with pytest.raises(ScopeError):
        parse_size(v)


def test_a_limit_the_kernel_refuses_removes_the_scope(tree, clock, monkeypatch):
    """No scope exists without its limits: a game must never start silently uncapped."""
    real = pathlib.Path.write_text

    def refuse(self, data, *a, **kw):
        if self.name == "memory.max":
            raise PermissionError(13, "Permission denied")        # e.g. memory controller not enabled
        return real(self, data, *a, **kw)
    monkeypatch.setattr(pathlib.Path, "write_text", refuse)
    s = make(tree, clock)
    with pytest.raises(ScopeError, match="nothing started without its ceiling"):
        s.create_scope("game", uid=1000, memory_max="8G")
    assert list(tree.root.iterdir()) == [] and s.owned == {}


def test_a_limit_that_reads_back_wrong_removes_the_scope(tree, clock, monkeypatch):
    real = pathlib.Path.read_text
    monkeypatch.setattr(pathlib.Path, "read_text",
                        lambda self, *a, **kw: "max" if self.name == "memory.max" else real(self, *a, **kw))
    # on cgroupfs, rmdir succeeds with interface files present; in a temp dir the written memory.max is a real file
    import shutil
    monkeypatch.setattr(pathlib.Path, "rmdir", lambda self: shutil.rmtree(self))
    s = make(tree, clock)
    with pytest.raises(ScopeError, match="reads back"):
        s.create_scope("game", uid=1000, memory_max="8G")
    assert list(tree.root.iterdir()) == [] and s.owned == {}


def test_the_scope_cap(tree, clock, monkeypatch):
    monkeypatch.setattr(sc, "MAX_SCOPES", 2)
    s = make(tree, clock)
    s.create_scope("a", uid=1000)
    s.create_scope("b", uid=1000)
    with pytest.raises(ScopeError, match="already exist"):
        s.create_scope("c", uid=1000)


# ---------------------------------------------------------------- enter

def test_enter_moves_the_pid(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s.enter(name, pid=4242, uid=1000)
    assert (tree.root / name / "cgroup.procs").read_text() == "4242" and s.describe(name)["entered"]


def test_enter_only_a_scope_this_daemon_made(tree, clock):
    (tree.root / "game-abcdef").mkdir()
    with pytest.raises(ScopeError, match="not a scope this daemon created"):
        make(tree, clock).enter("game-abcdef", pid=4242, uid=1000)


def test_enter_only_by_its_creator(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    with pytest.raises(ScopeError, match="another user"):
        s.enter(name, pid=4242, uid=1001)
    assert not (tree.root / name / "cgroup.procs").exists()


def test_enter_is_one_shot(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s.enter(name, pid=4242, uid=1000)
    with pytest.raises(ScopeError, match="already entered"):
        s.enter(name, pid=4343, uid=1000)
    assert (tree.root / name / "cgroup.procs").read_text() == "4242"


def test_enter_after_the_ttl_refused(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    clock.t += sc.ENTER_TTL_S + 1
    with pytest.raises(ScopeError, match="expired"):
        s.enter(name, pid=4242, uid=1000)


@pytest.mark.parametrize("pid", [0, 1, -5, True, "4242", None])
def test_enter_refuses_a_pid_that_is_not_a_real_peer(tree, clock, pid):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    with pytest.raises(ScopeError, match="SO_PEERCRED"):
        s.enter(name, pid=pid, uid=1000)


# ---------------------------------------------------------------- reap

def test_rmtree_removes_children_first(tmp_path):
    """On cgroupfs only directories block rmdir (interface files do not), so the fake is directories only."""
    top = tmp_path / "game-abcdef"
    (top / "workers" / "gpu").mkdir(parents=True)
    (top / "workers" / "audio").mkdir()
    (top / "helper").mkdir()
    Scopes._rmtree_cgroup(top)
    assert not top.exists()


def test_rmtree_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    (outside / "precious").mkdir(parents=True)
    top = tmp_path / "game-abcdef"
    top.mkdir()
    (top / "link").symlink_to(outside)
    with pytest.raises(OSError):
        Scopes._rmtree_cgroup(top)                                 # the symlink blocks rmdir of top: fine, next tick
    assert (outside / "precious").is_dir()                         # nothing on the far side of a link is touched


def test_reap_removes_an_empty_entered_scope(tree, clock, monkeypatch):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s.enter(name, pid=4242, uid=1000)
    events(tree, name, False)
    removed = []
    monkeypatch.setattr(Scopes, "_rmtree_cgroup", staticmethod(lambda d: removed.append(d.name)))
    assert s.reap() == [name] and removed == [name] and name not in s.owned
    assert name not in json.loads((tree.root.parent / "scopes.json").read_text())


def test_reap_keeps_a_populated_scope(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s.enter(name, pid=4242, uid=1000)
    events(tree, name, True)
    assert s.reap() == [] and (tree.root / name).is_dir()


def test_reap_keeps_a_scope_whose_state_is_unknown(tree, clock, monkeypatch):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s.enter(name, pid=4242, uid=1000)                              # no cgroup.events in the fake: unknown
    tried = []
    monkeypatch.setattr(Scopes, "_rmtree_cgroup", staticmethod(lambda d: tried.append(d)))
    assert s.reap() == [] and tried == []                          # not even attempted


def test_reap_waits_for_the_launcher_then_cleans_up_a_crashed_one(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s._populated = staticmethod(lambda d: False)
    assert s.reap() == []                                          # created, not entered yet: give it its TTL
    clock.t += sc.ENTER_TTL_S + 1
    assert s.reap() == [name] and not (tree.root / name).exists()


def test_reap_never_touches_what_it_did_not_make(tree, clock):
    for n in ("game-abcdef", "build", "traytest"):
        (tree.root / n).mkdir()
    s = make(tree, clock)
    s._populated = staticmethod(lambda d: False)
    clock.t += 10_000
    assert s.reap() == []
    assert sorted(p.name for p in tree.root.iterdir()) == ["build", "game-abcdef", "traytest"]


def test_reap_forgets_a_scope_someone_else_removed(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    (tree.root / name).rmdir()
    assert s.reap() == [name] and s.owned == {}


def test_a_busy_rmdir_is_retried_next_tick(tree, clock, monkeypatch):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s.enter(name, pid=4242, uid=1000)
    s._populated = staticmethod(lambda d: False)
    monkeypatch.setattr(Scopes, "_rmtree_cgroup", staticmethod(lambda d: (_ for _ in ()).throw(OSError(16, "busy"))))
    assert s.reap() == [] and name in s.owned


# ---------------------------------------------------------------- the registry survives a restart

def test_a_restarted_daemon_still_reaps_its_own_scopes(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    s.enter(name, pid=4242, uid=1000)
    (tree.root / name / "cgroup.procs").unlink()
    s2 = make(tree, clock)                                         # the daemon restarted
    assert name in s2.owned
    s2._populated = staticmethod(lambda d: False)
    assert s2.reap() == [name]


def test_the_registry_is_private(tree, clock):
    make(tree, clock).create_scope("game", uid=1000)
    st = (tree.root.parent / "scopes.json").stat()
    assert stat.S_IMODE(st.st_mode) == 0o600


@pytest.mark.parametrize("content", ["not json", "[1,2]", '{"../etc": {"uid": 0}}', '{"game-xyz": 5}'])
def test_a_bad_registry_is_ignored_not_trusted(tree, clock, content):
    (tree.root.parent / "scopes.json").write_text(content)
    s = make(tree, clock)
    assert s.owned == {}


# ---------------------------------------------------------------- the real kernel

def _real_root():
    mount = "/sys/fs/cgroup"
    if os.geteuid() != 0 or not os.path.isfile(f"{mount}/cgroup.controllers"):
        return None
    probe = f"{mount}/cora-scope-probe-{os.getpid()}"
    try:
        os.mkdir(probe)
        os.rmdir(probe)
        return mount
    except OSError:
        return None


@pytest.mark.skipif(_real_root() is None, reason="needs root and a writable cgroup v2 tree")
def test_real_kernel_scope_lifecycle():
    mount = _real_root()
    root = CgroupRoot(f"{mount}/cora-scopetest-{os.getpid()}", mount)
    enabled = root.ensure(("memory",))
    if "memory" not in enabled:
        os.rmdir(root.root)
        pytest.skip("the memory controller cannot be enabled here")
    s = Scopes(root)
    try:
        name = s.create_scope("realtest", uid=os.getuid(), memory_max="256M", memory_high="192M")
        assert (root.root / name / "memory.max").read_text().strip() == str(256 << 20)
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        s.enter(name, pid=p.pid, uid=os.getuid())
        assert f"/{root.root.name}/{name}" in open(f"/proc/{p.pid}/cgroup").read()
        assert s.reap() == []                                      # populated: kept
        p.kill(); p.wait()
        for _ in range(50):
            if s._populated(root.root / name) is False:
                break
            time.sleep(0.05)
        assert s.reap() == [name] and not (root.root / name).exists()
    finally:
        for d in sorted(root.root.glob("*"), reverse=True):
            if d.is_dir():
                try:
                    os.rmdir(d)
                except OSError:
                    pass
        try:
            os.rmdir(root.root)
        except OSError:
            pass


# ---------------------------------------------------------------- scopes.json: missing is clean, corrupt fails closed

from cora_sentinel.scope import ScopeRegistryError  # noqa: E402

CORRUPT = {
    "truncated": b'{"game-abcdef": {"app": "game", "uid": 1000, "created": 1.0, "ent',
    "bad json": b"not json at all",
    "a list": b'[{"game-abcdef": {}}]',
    "a string": b'"scopes"',
    "not utf-8": b"\xff\xfe\x00junk",
    "empty": b"",
}


def reg_path(tree):
    return tree.root.parent / "scopes.json"


def test_a_missing_registry_is_a_clean_start(tree, clock):
    s = make(tree, clock)
    assert (s.owned, s.registry_error, s.check()) == ({}, None, None)


@pytest.mark.parametrize("kind", sorted(CORRUPT))
def test_a_corrupt_registry_is_an_error_and_the_file_is_never_touched(tree, clock, kind):
    p = reg_path(tree)
    p.write_bytes(CORRUPT[kind])
    s = make(tree, clock)
    assert s.registry_error and str(p) in s.registry_error and s.check() == s.registry_error
    with pytest.raises(ScopeRegistryError, match="scope registry unreadable"):
        s.create_scope("game", uid=1000)
    assert s.reap() == [] and s.describe("game-abcdef") is None
    assert p.read_bytes() == CORRUPT[kind]                                 # never overwritten, never deleted
    assert [x.name for x in p.parent.iterdir() if x.name.startswith(".scopes.json")] == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads files whatever their mode")
def test_a_registry_that_cannot_be_read_is_an_error(tree, clock):
    p = reg_path(tree)
    p.write_text("{}")
    p.chmod(0)
    try:
        s = make(tree, clock)
        assert "Permission denied" in s.registry_error
    finally:
        p.chmod(0o600)


def test_a_directory_in_its_place_is_an_error(tree, clock):
    reg_path(tree).mkdir()
    assert "is a directory" in make(tree, clock).registry_error


def test_it_heals_in_process_once_the_file_reads_cleanly(tree, clock, monkeypatch):
    p = reg_path(tree)
    p.write_bytes(CORRUPT["truncated"])
    s = make(tree, clock)
    assert s.registry_error
    (tree.root / "game-abcdef").mkdir()
    events(tree, "game-abcdef", True)                                     # a live scope: create_scope's reap keeps it
    p.write_text(json.dumps({"game-abcdef": {"app": "game", "uid": 1000, "created": clock.t, "entered": True,
                                             "memory_max": None, "memory_high": None, "psi_memory": None}}))
    assert s.check() is None and s.registry_error is None and list(s.owned) == ["game-abcdef"]
    assert s.describe("game-abcdef")["app"] == "game"
    name = s.create_scope("other", uid=1000)                              # writes work again
    assert set(json.loads(p.read_text())) == {"game-abcdef", name}


def test_the_reaper_is_suspended_while_unreadable_and_resumes_after(tree, clock, monkeypatch):
    s = make(tree, clock)
    monkeypatch.setattr(s, "token", tokens("aaaaaa"))
    name = s.create_scope("game", uid=1000)
    s.owned[name]["entered"] = True
    s._save()
    events(tree, name, populated=False)
    good = reg_path(tree).read_bytes()
    removed = []
    monkeypatch.setattr(Scopes, "_rmtree_cgroup", staticmethod(lambda d: removed.append(d.name)))
    reg_path(tree).write_bytes(CORRUPT["bad json"])
    assert s.reap() == [] and removed == []                               # an empty scope, but nobody reaps blind
    reg_path(tree).write_bytes(good)
    assert s.reap() == [name] and removed == [name]


def test_corruption_mid_run_keeps_the_last_good_registry_in_memory(tree, clock):
    s = make(tree, clock)
    name = s.create_scope("game", uid=1000)
    reg_path(tree).write_bytes(CORRUPT["a list"])
    assert s.check() and s.profile(name) == "app"                         # profiles stay right: not judged as agent
    assert s.describe(name) is None                                       # but the hub is told nothing it cannot verify


def test_a_save_never_replaces_a_file_corrupted_since_it_was_read(tree, clock):
    s = make(tree, clock)
    s.create_scope("game", uid=1000)
    reg_path(tree).write_bytes(CORRUPT["truncated"])
    with pytest.raises(ScopeRegistryError):
        s._save()
    assert reg_path(tree).read_bytes() == CORRUPT["truncated"]


def test_one_immediate_re_read_rides_out_a_replace(tree, clock, monkeypatch):
    reg_path(tree).write_text("{}")
    real, calls = Scopes._read_once, []

    def flaky(self):
        calls.append(1)
        if len(calls) == 1:
            raise ScopeRegistryError("caught mid-replace")
        return real(self)
    monkeypatch.setattr(Scopes, "_read_once", flaky)
    s = make(tree, clock)
    assert (s.registry_error, len(calls)) == (None, 2)


def test_the_writer_is_atomic_private_and_leaves_no_temp_files(tree, clock, monkeypatch):
    s = make(tree, clock)
    synced = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd))[1])
    s.create_scope("game", uid=1000)
    p = reg_path(tree)
    assert oct(p.stat().st_mode & 0o777) == "0o600" and len(synced) >= 2   # the file and its directory
    assert [x.name for x in p.parent.iterdir() if x.name.startswith(".scopes.json")] == []
