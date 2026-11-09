"""cora-run --app: the unprivileged launcher. A real Hub with real Scopes over a temp tree answers on a real socket;
only the final kernel check (/proc/self/cgroup) is stubbed, because a temp tree cannot really move a process."""
import grp
import json
import os
import socket
import threading

import pytest

from cora_sentinel import run, uihub
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.scope import Scopes
from cora_sentinel.uihub import Hub, cgroup_tasks

GROUP = grp.getgrgid(os.getgid()).gr_name


@pytest.fixture(autouse=True)
def guarded(monkeypatch):
    """Never exec for real, never change this process's identity."""
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    monkeypatch.delenv("SteamAppId", raising=False)
    monkeypatch.delenv("SteamGameId", raising=False)
    for fn in ("setuid", "setgid", "setgroups"):
        monkeypatch.setattr(run.os, fn, lambda *a, _fn=fn: pytest.fail(f"os.{_fn} in app mode"))
    started = []
    monkeypatch.setattr(run.os, "execvp", lambda f, a: started.append(a))
    return started


@pytest.fixture
def daemon(tmp_path, monkeypatch):
    monkeypatch.setattr(uihub, "HEARTBEAT_S", 0.3)
    root = tmp_path / "cora"
    root.mkdir()
    cg = CgroupRoot(str(root))
    scopes = Scopes(cg)
    rd = tmp_path / "run"
    rd.mkdir(mode=0o755)
    h = Hub(str(rd / "ui.sock"), group=GROUP, tasks=cgroup_tasks(cg, None), scopes=scopes, log=lambda m: None)
    h.start()
    yield h, cg, scopes
    h.stop()


def go(argv, monkeypatch, moved=True):
    monkeypatch.setattr(run, "in_scope", lambda scope: moved and bool(scope))
    monkeypatch.setattr("sys.argv", ["cora-run", *argv])
    return run.main()


# ---------------------------------------------------------------- the path that works

def test_launch_then_exec(daemon, guarded, monkeypatch, capsys):
    hub, cg, scopes = daemon
    rc = go(["--app", "dota", "--memory-max", "8G", "--socket", str(hub.path), "--", "game", "-x"], monkeypatch)
    assert rc is None and guarded == [["game", "-x"]]
    (name,) = scopes.owned
    assert name.startswith("dota-") and scopes.owned[name]["memory_max"] == 8 << 30
    assert (cg.root / name / "cgroup.procs").read_text() == str(os.getpid())       # this process, by SO_PEERCRED
    assert f"runs in scope {name}" in capsys.readouterr().err


def test_equals_form_and_env_socket(daemon, guarded, monkeypatch):
    hub, _, scopes = daemon
    monkeypatch.setenv("CORA_UI_SOCKET", str(hub.path))
    assert go(["--app=tool", "--memory-high=2G", "true"], monkeypatch) is None
    (name,) = scopes.owned
    assert name.startswith("tool-") and scopes.owned[name]["memory_high"] == 2 << 30


def test_steam_launch_options(daemon, guarded, monkeypatch):
    """Steam: launch options  cora-run --app steam %command%"""
    hub, _, scopes = daemon
    monkeypatch.setenv("SteamAppId", "570")
    assert go(["--app", "steam", "--socket", str(hub.path), "/home/u/.steam/proton", "waitforexitandrun", "x.exe"],
              monkeypatch) is None
    (name,) = scopes.owned
    assert name.startswith("steam-570-") and guarded[0][0].endswith("proton")


# ---------------------------------------------------------------- CMD never starts unconfined

def test_if_the_kernel_does_not_show_the_move_nothing_starts(daemon, guarded, monkeypatch, capsys):
    hub, _, _ = daemon
    assert go(["--app", "dota", "--socket", str(hub.path), "game"], monkeypatch, moved=False) == run.EXIT_LAUNCH
    assert guarded == [] and "not in it (/proc/self/cgroup)" in capsys.readouterr().err


def test_a_refusal_starts_nothing_and_says_why(daemon, guarded, monkeypatch, capsys):
    hub, cg, _ = daemon
    assert go(["--app", "dota", "--memory-max", "1M", "--socket", str(hub.path), "game"], monkeypatch) == run.EXIT_LAUNCH
    assert guarded == [] and "floor" in capsys.readouterr().err and list(cg.root.iterdir()) == []


def test_a_non_member_starts_nothing(daemon, guarded, monkeypatch, capsys):
    hub, _, _ = daemon
    monkeypatch.setattr(uihub, "peer_uid", lambda conn: 65534)
    assert go(["--app", "dota", "--socket", str(hub.path), "game"], monkeypatch) == run.EXIT_LAUNCH
    assert guarded == [] and "--ui-group" in capsys.readouterr().err


def test_no_daemon_starts_nothing(tmp_path, guarded, monkeypatch, capsys):
    assert go(["--app", "dota", "--socket", str(tmp_path / "nope.sock"), "game"], monkeypatch) == run.EXIT_LAUNCH
    err = capsys.readouterr().err
    assert guarded == [] and "--ui-socket" in err and "not starting game" in err


@pytest.mark.parametrize("when, says", [
    ("before_request", "Broken pipe"),            # gone before we send: EPIPE (CI run #44, 3.12)
    ("unread_request", "reset by peer"),          # gone with our request unread in its buffer: ECONNRESET
    ("after_request", "closed the connection"),   # read the request, then hung up without answering: EOF
])
def test_a_daemon_that_hangs_up_starts_nothing(tmp_path, guarded, monkeypatch, capsys, when, says):
    """Each moment a daemon can hang up is forced, not raced: the old single test accepted two of these three
    outcomes and failed on a runner that scheduled the third."""
    import select
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(tmp_path / "s.sock"))
    srv.listen(1)
    closed = threading.Event()

    def daemon():
        conn = srv.accept()[0]
        if when == "unread_request":
            select.select([conn], [], [], 5)      # the request has arrived; close without reading it
        elif when == "after_request":
            conn.recv(65536)
        conn.close()
        closed.set()
    t = threading.Thread(target=daemon, daemon=True)
    t.start()
    if when == "before_request":
        real = socket.socket.sendall

        def sendall(self, data, *a):              # send only once the daemon has really hung up
            closed.wait(5)
            return real(self, data, *a)
        monkeypatch.setattr(socket.socket, "sendall", sendall)
    assert go(["--app", "dota", "--socket", str(tmp_path / "s.sock"), "game"], monkeypatch) == run.EXIT_LAUNCH
    err = capsys.readouterr().err
    assert guarded == [] and says in err and "not starting game" in err, err
    t.join(5)
    srv.close()


def test_a_lying_daemon_cannot_start_the_game_unconfined(tmp_path, guarded, monkeypatch):
    """Anything that answers ok without moving us: the kernel check refuses (in_scope is the REAL one here)."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(tmp_path / "s.sock"))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.makefile("rb").readline()
        c.sendall(json.dumps({"type": "result", "id": "cora-run", "ok": True, "scope": "dota-abcdef"}).encode() + b"\n")
        c.close()
    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr("sys.argv", ["cora-run", "--app", "dota", "--socket", str(tmp_path / "s.sock"), "game"])
    assert run.main() == run.EXIT_LAUNCH and guarded == []
    srv.close()


# ---------------------------------------------------------------- arguments and names

@pytest.mark.parametrize("raw,env,name", [
    ("Dota 2", {}, "dota-2"),
    ("steam", {"SteamAppId": "570"}, "steam-570"),
    ("steam", {"SteamGameId": "1091500"}, "steam-1091500"),
    ("steam", {}, "steam"),
    ("steam", {"SteamAppId": "../x"}, "steam"),
    ("My_Game!!", {}, "my_game"),
    ("x" * 40, {}, "x" * 32),
])
def test_app_names(raw, env, name):
    assert run.app_name(raw, env) == name


@pytest.mark.parametrize("raw", ["", "!!!", "  "])
def test_unusable_app_names(raw):
    with pytest.raises(ValueError):
        run.app_name(raw, {})


@pytest.mark.parametrize("argv,why", [
    (["--app", "x"], "no command"),
    (["--app"], "needs a value"),
    (["--app", "x", "--bogus", "y", "cmd"], "unknown option"),
    (["--app", "x", "--memory-max"], "needs a value"),
])
def test_bad_arguments(argv, why, guarded, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cora-run", *argv])
    assert run.main() == 2 and guarded == [] and why in capsys.readouterr().err


def test_options_stop_at_the_command(monkeypatch):
    opts, cmd = run.parse_app_args(["--app", "x", "game", "--memory-max", "1G"])
    assert cmd == ["game", "--memory-max", "1G"] and opts["memory_max"] is None


def test_the_socket_is_not_inherited_by_the_game(daemon, monkeypatch):
    """What keeps the daemon's connection out of the game is close-on-exec (Python's default for sockets), checked
    here on the socket request_scope really creates; the explicit close() is tidiness, not the guarantee."""
    hub, _, _ = daemon
    import socket as sk
    made = []
    real = sk.socket

    class Spy(real):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            made.append(self.get_inheritable())
    monkeypatch.setattr(sk, "socket", Spy)
    assert run.request_scope(str(hub.path), "dota")["ok"]
    assert made and not any(made)                                 # ours, and the hub's accepted end


@pytest.mark.parametrize("answer", ["", None, "/", "dota", "dota-zzzzzz", "../x-abcdef", 7])
def test_in_scope_never_accepts_a_malformed_answer(answer):
    """Found by these tests: in the root cgroup ("0::/") an EMPTY scope name matched, so an ok reply without a
    scope would have let the game start unconfined."""
    assert run.in_scope(answer) is False


def test_in_scope_matches_the_kernels_line(tmp_path, monkeypatch):
    import builtins
    real = builtins.open
    monkeypatch.setattr(builtins, "open", lambda p, *a, **kw: real(tmp_path / "cg", *a, **kw)
                        if p == "/proc/self/cgroup" else real(p, *a, **kw))
    (tmp_path / "cg").write_text("0::/cora/dota-1a2b3c\n")
    assert run.in_scope("dota-1a2b3c") and not run.in_scope("dota-1a2b3d")
    (tmp_path / "cg").write_text("0::/\n")
    assert not run.in_scope("dota-1a2b3c")


def test_an_ok_reply_without_a_scope_starts_nothing(tmp_path, guarded, monkeypatch):
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(tmp_path / "s.sock"))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.makefile("rb").readline()
        c.sendall(json.dumps({"type": "result", "id": "cora-run", "ok": True}).encode() + b"\n")
        c.close()
    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr("sys.argv", ["cora-run", "--app", "dota", "--socket", str(tmp_path / "s.sock"), "game"])
    assert run.main() == run.EXIT_LAUNCH and guarded == []
    srv.close()


def test_legacy_name_mode_is_unchanged(tmp_path, guarded, monkeypatch):
    root = tmp_path / "cora"
    root.mkdir()
    monkeypatch.setenv("CORA_CGROUP_ROOT", str(root))
    monkeypatch.setattr(run, "_firewall", lambda c: None)
    monkeypatch.setattr(run, "_preinstall_tap", lambda *a: None)
    monkeypatch.setattr("sys.argv", ["cora-run", "build", "make"])
    run.main()
    assert guarded == [["make"]] and (root / "build" / "cgroup.procs").read_text() == "0"
