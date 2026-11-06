"""cora-sentinel's start-up: it says what arguments it was started with, and refuses arguments that look like shell syntax nobody
expanded (the usual sign of a mangled systemd EnvironmentFile). No kernel, no root. Run: pytest -q tests/test_args.py"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from cora_sentinel import daemon

ROOT = Path(__file__).resolve().parents[1]
FLAGGED = ["$CORA_ARGS", "${HOME}/events.jsonl", "--out=$HOME/e.jsonl", "$(date)", "`id`", "$1", "'/var/log/x", '"/var/log/x"',
           "/var/log/x'", '--model="/m.gguf"', "a$b"]
FINE = ["--cgroup-root", "/sys/fs/cgroup/cora", "10.0.0.0/8", "~/.config/cora/salt", "120", "--net-allow=192.168.68.0/24", "a-b_c.d",
        "/path/with#hash", "100%", "price$", "$", "--floor-confirm", "/var/log/cora-sentinel/events.jsonl", "", "it's"[:0] or "x"]


@pytest.mark.parametrize("tok", FLAGGED)
def test_each_shape_of_unexpanded_shell_syntax_is_flagged(tok):
    assert [t for t, _ in daemon.shell_tokens(["--x", tok, "--y"])] == [tok]


@pytest.mark.parametrize("tok", FINE)
def test_ordinary_arguments_are_not(tok):
    assert daemon.shell_tokens([tok]) == []


def run_main(monkeypatch, capsys, tmp_path, *argv):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["cora-sentinel", *argv])
    try:
        rc = daemon.main()
    except SystemExit as e:                                   # argparse's own usage errors
        rc = e.code
    return rc, capsys.readouterr().err


def test_a_start_with_an_unexpanded_variable_is_refused_with_status_2_and_names_it(monkeypatch, capsys, tmp_path):
    rc, err = run_main(monkeypatch, capsys, tmp_path, "--cgroup-root", "/x", "--out", "$HOME/e.jsonl")
    assert rc == 2
    assert "refusing to start" in err and "'$HOME/e.jsonl'" in err and "EnvironmentFile" in err and "--allow-shell-chars" in err
    assert list(tmp_path.iterdir()) == [], "it must refuse BEFORE creating any file (a file literally named $HOME/... would be the bug)"


def test_the_arguments_are_echoed_first_so_the_journal_shows_what_it_really_runs_with(monkeypatch, capsys, tmp_path):
    rc, err = run_main(monkeypatch, capsys, tmp_path, "--out", "$HOME/e.jsonl")
    lines = err.splitlines()
    assert re.match(r"\[cora-sentinel\] \d+\.\d+\.\d+ starting with: --out '\$HOME/e\.jsonl'$", lines[0])
    assert "refusing to start" in lines[1]


def test_the_echo_quotes_a_token_so_a_value_split_at_a_space_is_visible(monkeypatch, capsys, tmp_path):
    rc, err = run_main(monkeypatch, capsys, tmp_path, "--floor", "--match", "a b")            # --floor without --nft: refused later, with 1
    assert rc == 1 and "starting with: --floor --match 'a b'" in err
    assert "refusing to start: the argument" not in err


def test_a_stray_quote_from_systemd_not_stripping_it_is_refused(monkeypatch, capsys, tmp_path):
    rc, err = run_main(monkeypatch, capsys, tmp_path, "--model", '"/m.gguf"')
    assert rc == 2 and "quote mark stuck to it" in err and "'\"/m.gguf\"'" in err


def test_a_bare_unexpanded_variable_is_still_an_argparse_error_with_status_2(monkeypatch, capsys, tmp_path):
    rc, err = run_main(monkeypatch, capsys, tmp_path, "$CORA_ARGS")
    assert rc == 2 and "unrecognized arguments: $CORA_ARGS" in err


def test_the_escape_hatch_lets_a_literal_dollar_through(monkeypatch, capsys, tmp_path):
    rc, err = run_main(monkeypatch, capsys, tmp_path, "--allow-shell-chars", "--out", "/tmp/a$b.jsonl", "--floor")
    assert rc == 1 and "refusing to start: the argument" not in err and "--floor needs --nft" in err       # past the check, stopped by a later one


def test_selftest_is_not_echoed_and_help_still_works(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(daemon, "selftest", lambda: 0)
    rc, err = run_main(monkeypatch, capsys, tmp_path, "--selftest")
    assert rc == 0 and "starting with" not in err
    rc, err = run_main(monkeypatch, capsys, tmp_path, "--help")
    assert rc == 0 and "starting with" not in err


def test_a_real_process_exits_2_and_says_why(tmp_path):
    r = subprocess.run([sys.executable, "-m", "cora_sentinel.daemon", "--out", "${HOME}/e.jsonl"], capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 2 and "'${HOME}/e.jsonl'" in r.stderr and "starting with" in r.stderr
    assert list(tmp_path.iterdir()) == []


def test_the_shipped_config_can_never_trip_its_own_check():
    conf = (ROOT / "deploy" / "cora-sentinel.conf").read_text()
    args = re.search(r"^CORA_ARGS=(.*)$", conf, re.M).group(1).split()          # systemd splits on whitespace and nothing else
    assert args and daemon.shell_tokens(args) == []


def test_the_unit_does_not_restart_a_usage_error():
    unit = (ROOT / "deploy" / "cora-sentinel.service").read_text()
    assert "RestartPreventExitStatus=2" in unit and "Restart=on-failure" in unit


def test_the_docs_say_where_to_look(monkeypatch):
    doc = (ROOT / "docs" / "service.md").read_text()
    assert "starting with:" in doc and "--allow-shell-chars" in doc and "/proc" in doc
