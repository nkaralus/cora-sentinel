"""A task may keep its workers in sub-cgroups (a browser, a flatpak: <root>/<task>/sub/worker). cgroup v2's cgroup.procs lists only the
processes DIRECTLY in a cgroup, so such a task used to look empty: the tap flagged its connections, the owner lookup found nobody
("cgroup.procs empty") and dropped the event, and tick() never monitored the workers. This file pins the fix: cgroup_of() resolves the top-level
task name by string parsing, pids()/discover() look below the task directory with a bounded walk, and a task with more processes than the
VIP pool holds no longer stops the watch.

Unit tests need no kernel; the last three run on a real cgroup and nft table and skip themselves without root.
Run: pytest -q tests/test_cgroup_nested.py"""
import inspect
import os
import sys
import time

import pytest

from cora_sentinel import daemon
from cora_sentinel.cgroup import CgroupError, CgroupRoot
from cora_sentinel.daemon import Sentinel
from test_nflog import LOCAL, drain, env, listener, monitor, real, task   # noqa: F401  (env: a real cgroup root + nft table)


# ---------------------------------------------------------------------------------------------- cgroup_of: pure string parsing
def at(path):
    r = CgroupRoot("/sys/fs/cgroup/cora", "/sys/fs/cgroup")
    r._read_proc_cgroup = lambda pid: path
    return r.cgroup_of(1234)


@pytest.mark.parametrize("path,want", [
    ("/cora/task-a", "task-a"),
    ("/cora/task-a/sub", "task-a"),
    ("/cora/task-a/sub/worker", "task-a"),                    # the case that was None
    ("/cora/task-a/a/b/c/d/e/f/g/h/i/j", "task-a"),
    ("/cora/task-a/sub (deleted)", "task-a"),
    ("/cora/t_1-x/w", "t_1-x"),
])
def test_a_pid_anywhere_below_a_task_belongs_to_that_task(path, want):
    assert at(path) == want


@pytest.mark.parametrize("path", [
    None,                                                      # the process is gone
    "/cora", "/cora/",                                         # the root itself is not a task
    "/coraX/task-a", "/cor/task-a", "/other/task-a", "/", "/user.slice/x",     # outside the root, including a sibling that shares the prefix
    "/cora/Task-A/x", "/cora/.hidden/x", "/cora//x", "/cora/../x", "/cora/task a/x",    # first component is not a valid task name
    "/cora/task-a (deleted)",                                  # the task directory itself was removed
    "/cora/" + "a" * 41 + "/x",                                # longer than a task name may be
])
def test_anything_that_is_not_below_a_valid_task_is_none(path):
    assert at(path) is None


def test_cgroup_of_does_no_directory_walk(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("cgroup_of must be string parsing only")
    monkeypatch.setattr(os, "scandir", boom)
    monkeypatch.setattr(os, "walk", boom)
    monkeypatch.setattr(os, "listdir", boom)
    monkeypatch.setattr(os.path, "isdir", boom)
    assert at("/cora/task-a/sub/worker") == "task-a"


# ---------------------------------------------------------------------------------------------- pids() / discover(): a bounded walk
def tree(tmp_path, spec):
    root = tmp_path / "cora"
    for rel, content in spec.items():
        d = root / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / "cgroup.procs").write_text(content)
    return CgroupRoot(str(root), str(tmp_path))


def test_pids_lists_the_tasks_own_processes_first_then_those_in_its_sub_cgroups(tmp_path):
    r = tree(tmp_path, {"task-a": "10\n11\n", "task-a/sub": "20\n", "task-a/sub/worker": "30\n31\n", "task-a/other": "40\n"})
    assert sorted(r.pids("task-a")) == [10, 11, 20, 30, 31, 40]
    assert r.pids("task-a")[:2] == [10, 11], "the directly-owned processes come first (the owner lookup prefers them)"
    assert r.pids("task-a", nested=False) == [10, 11]


def test_a_task_whose_every_process_is_nested_is_not_empty(tmp_path):
    r = tree(tmp_path, {"nest": "", "nest/sub/worker": "99\n"})
    assert r.pids("nest", nested=False) == [], "this is exactly what the old code saw"
    assert r.pids("nest") == [99]


def test_discover_maps_nested_processes_to_the_top_level_task_and_keeps_tasks_apart(tmp_path):
    r = tree(tmp_path, {"task-a": "1\n", "task-a/sub/w": "2\n", "task-b": "3\n", "task-b/x": "4\n"})
    assert r.discover() == {1: "task-a", 2: "task-a", 3: "task-b", 4: "task-b"}


def test_the_walk_is_bounded_in_depth(tmp_path):
    spec = {"deep": "1\n"}
    path = "deep"
    for i in range(CgroupRoot.MAX_NEST_DEPTH + 4):
        path += f"/d{i}"
        spec[path] = f"{100 + i}\n"
    got = tree(tmp_path, spec).pids("deep")
    assert 1 in got and 100 in got, "shallow levels are seen"
    assert 100 + CgroupRoot.MAX_NEST_DEPTH + 3 not in got, "the deepest level is beyond the cap"
    assert len(got) <= CgroupRoot.MAX_NEST_DEPTH + 1


def test_the_walk_is_bounded_in_the_number_of_sub_cgroups(tmp_path):
    cap = CgroupRoot.MAX_SUBCGROUPS
    got = tree(tmp_path, {"wide": "1\n", **{f"wide/c{i:05d}": f"{1000 + i}\n" for i in range(cap + 60)}}).pids("wide")
    assert 1 in got and len(got) == cap + 1, "a runaway tree cannot make a tick expensive"


def test_the_walk_stops_scanning_directories_once_the_cap_is_reached(tmp_path, monkeypatch):
    cap = CgroupRoot.MAX_SUBCGROUPS
    r = tree(tmp_path, {"wide": "1\n", **{f"wide/c{i:05d}": f"{1000 + i}\n" for i in range(cap + 60)}})
    calls, real = [], os.scandir

    def counting(path):
        calls.append(str(path))
        return real(path)
    monkeypatch.setattr(os, "scandir", counting)
    r.pids("wide")
    assert len(calls) <= 2, f"past the cap the walk must stop, not scan {len(calls)} more directories it can no longer use"


def test_the_walk_never_follows_a_symlink_out_of_the_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "cgroup.procs").write_text("666\n")
    r = tree(tmp_path, {"task-a": "1\n", "task-a/real": "2\n"})
    (tmp_path / "cora" / "task-a" / "link").symlink_to(outside, target_is_directory=True)
    assert sorted(r.pids("task-a")) == [1, 2], "a symlink is not a sub-cgroup"


def test_garbage_missing_and_unreadable_pieces_are_skipped_not_fatal(tmp_path):
    r = tree(tmp_path, {"t": "5\nabc\n-1\n7\n", "t/nofile": "9\n"})
    (tmp_path / "cora" / "t" / "empty").mkdir()                   # a sub-cgroup with no cgroup.procs at all
    (tmp_path / "cora" / "t" / "nofile" / "cgroup.procs").unlink()
    assert r.pids("t") == [5, 7]
    assert r.pids("not-there") == []
    with pytest.raises(CgroupError):
        r.pids("../escape")                                       # an invalid name is still refused, as before


# ---------------------------------------------------------------------------------------------- a task bigger than the VIP pool
def sentinel_with(pids):
    s = Sentinel("CORA_TASK", ["/tmp"], 150, 10.0, lambda p: None)
    s._targets = lambda: {pid: "cmd" for pid in pids}
    return s


def test_a_task_with_more_processes_than_the_pool_holds_does_not_stop_the_watch(capsys):
    s = sentinel_with(range(900000, 900300))
    s.tick()                                                      # used to raise RegistryError: SUBNET_EXHAUSTED, and end the daemon
    assert len(s.net.by_pid) == 245 and s.vip_skipped == 55
    err = capsys.readouterr().err
    assert 1 <= err.count("no virtual IP for pid") <= 3, "logged, but rate-limited"


def test_the_pids_that_were_skipped_are_picked_up_when_room_frees_up():
    s = sentinel_with(range(900000, 900300))
    s.tick()
    assert 900299 not in s.net.by_pid
    s._targets = lambda: {pid: "cmd" for pid in range(900050, 900300)}        # 50 of the monitored ones exit
    s.tick()                                                                  # (tick() releases the exited ones at its END...)
    s.tick()                                                                  # ...so the skipped ones get their VIP on the next
    assert 900245 in s.net.by_pid and 900294 in s.net.by_pid, "the ones that had been skipped are monitored now"
    assert 900000 not in s.net.by_pid and len(s.net.by_pid) == 245
    assert 900299 not in s.net.by_pid, "250 targets cannot fit 245 VIPs: the last five stay skipped, and the watch goes on"


def test_one_bad_tick_is_logged_and_the_watch_goes_on(capsys):
    s = Sentinel("CORA_TASK", ["/tmp"], 150, 10.0, lambda p: None)
    calls = []

    def bad():
        calls.append(1)
        raise OSError("transient")
    s.tick = bad
    for _ in range(5):
        s.guarded_tick()                                          # none of these may raise
    assert len(calls) == 5 and s.tick_errors == 5
    assert capsys.readouterr().err.count("tick failed") == 3, "the first three are logged, then it goes quiet"


def test_the_main_loop_uses_the_guarded_tick():
    src = inspect.getsource(daemon.main)
    assert "s.guarded_tick()" in src and "        s.tick()\n        n += 1" not in src


# ---------------------------------------------------------------------------------------------- the real kernel (root only)
def nested_worker(root, port=None, n=3, hold=1.5, sleep_only=False):
    """What a browser does: the task makes a sub-cgroup, moves itself into it, and only then talks to the network."""
    body = ("for _ in range(%d):\n    socket.create_connection((%r, %d)).close()\n" % (n, LOCAL, port)) if not sleep_only else ""
    return ("import os, socket, time\nsub = os.path.join(%r, 'nest', 'sub', 'worker')\nos.makedirs(sub, exist_ok=True)\n"
            "open(os.path.join(sub, 'cgroup.procs'), 'w').write(str(os.getpid()))\n%stime.sleep(%r)\n" % (str(root), body, hold))


@pytest.fixture
def nested_env(env):
    """env, plus removal of the sub-cgroups a test made: the shared fixture can only rmdir a task's own directory.
    (It depends on env, so it is torn down BEFORE env: the root still exists.)"""
    yield env
    root = env[0].root
    for rel in ("nest/sub/worker", "nest/sub"):
        for _ in range(50):
            try:
                (root / rel).rmdir()
                break
            except FileNotFoundError:
                break
            except OSError:
                time.sleep(0.1)                                   # the worker is still exiting


@real
def test_a_connection_from_a_nested_worker_becomes_an_event_instead_of_being_dropped(nested_env):
    cgroups, fw, made = nested_env
    events = []
    lis, port = listener()
    stop = drain(lis)
    s, nm = monitor(cgroups, fw, made, events, interval=0.2)
    p = task(cgroups, fw, "nest", nested_worker(cgroups.root, port))
    time.sleep(3.0)
    p.wait(30)
    stop.set()
    lis.close()
    st = nm.stats
    assert st["syn_hits"] >= 1, "the tap flagged it (it always did)"
    assert st["owner_gone"] == 0, "and the owner is found now: it was 'cgroup.procs empty'"
    got = [e for e in events if e["anomaly"]["kind"] == "unauthorized_connection"]
    assert got and all(e["subject"]["cgroup"] == "nest" for e in got)
    assert all(e["subject"]["cgroup_id"] == cgroups.cgroup_id("nest") for e in got)
    assert all(e["detection"] == {"proto": "tcp", "via": "syn_tap"} for e in got), "a real tap event records how it was seen"


@real
def test_cgroup_of_and_pids_agree_with_the_kernel_for_a_nested_process(nested_env):
    cgroups, fw, made = nested_env
    p = task(cgroups, fw, "nest", nested_worker(cgroups.root, hold=4, sleep_only=True))
    try:
        end = time.monotonic() + 10
        while not (cgroups._read_proc_cgroup(p.pid) or "").endswith("/nest/sub/worker") and time.monotonic() < end:
            time.sleep(0.02)                                      # wait for the MOVE: before it, the pid is directly in the task
        assert (cgroups._read_proc_cgroup(p.pid) or "").endswith("/nest/sub/worker"), "the worker never moved into its sub-cgroup"
        assert cgroups.cgroup_of(p.pid) == "nest", "the kernel says .../nest/sub/worker; the answer is the task"
        assert p.pid in cgroups.pids("nest") and p.pid not in cgroups.pids("nest", nested=False)
        assert cgroups.discover().get(p.pid) == "nest"
    finally:
        p.kill()
        p.wait()
