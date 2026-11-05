"""The systemd packaging in deploy/: the unit says what the lifecycle promises, the shipped config only uses flags the
daemon has, and the installer renders, keeps your edits and uninstalls. Runs anywhere (no systemd needed; the
`systemd-analyze verify` test runs when it is installed). Run: pytest -q tests/test_service.py"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
UNIT = (DEPLOY / "cora-sentinel.service").read_text()
CONF = (DEPLOY / "cora-sentinel.conf").read_text()
INSTALL = DEPLOY / "install-service.sh"


def section(name):
    m = re.search(rf"^\[{name}\]\n(.*?)(?=^\[|\Z)", UNIT, re.M | re.S)
    return m.group(1) if m else ""


def keys(sec, key):
    return [l.split("=", 1)[1].strip() for l in section(sec).splitlines() if l.startswith(key + "=")]


def test_the_unit_restarts_on_failure_but_is_capped():
    assert keys("Service", "Restart") == ["on-failure"]
    assert keys("Unit", "StartLimitBurst") and keys("Unit", "StartLimitIntervalSec")
    assert keys("Service", "RestartSec")


def test_stopping_removes_an_unconfirmed_floor_and_only_that():
    post = keys("Service", "ExecStopPost")
    assert len(post) == 1 and post[0].startswith("-") and post[0].endswith("/cora-floor rollback")   # "-": failure ignored
    assert "remove" not in post[0].split("cora-floor")[1].replace("rollback", "")                      # never a blanket remove


def test_the_unit_takes_its_arguments_from_the_config_file_and_can_hot_reload():
    assert keys("Service", "EnvironmentFile") == ["-/etc/cora-sentinel/cora-sentinel.conf"]
    assert keys("Service", "ExecStart") == ["@BINDIR@/cora-sentinel $CORA_ARGS"]
    assert keys("Service", "ExecReload") == ["/bin/kill -HUP $MAINPID"]


def test_state_logs_and_ordering_are_declared():
    assert keys("Service", "StateDirectory") == ["cora-sentinel"] and keys("Service", "LogsDirectory") == ["cora-sentinel"]
    assert keys("Service", "WorkingDirectory") == ["/var/lib/cora-sentinel"]
    after = keys("Unit", "After")[0].split()
    assert "network-online.target" in after and "nftables.service" in after     # nftables.conf must not flush us at boot
    assert keys("Install", "WantedBy") == ["multi-user.target"]


def test_the_state_directory_matches_what_the_daemon_and_cli_default_to():
    from cora_sentinel.floorguard import DEFAULT_STATE_DIR
    assert DEFAULT_STATE_DIR == "/var/lib/cora-sentinel" == keys("Service", "WorkingDirectory")[0]


def conf_args():
    m = re.search(r"^CORA_ARGS=(.*)$", CONF, re.M)
    assert m, "the shipped config has no CORA_ARGS line"
    return m.group(1).split()


def test_every_flag_in_the_shipped_config_exists_in_the_daemon():
    help_text = subprocess.run([sys.executable, "-m", "cora_sentinel.daemon", "--help"], capture_output=True, text=True).stdout
    flags = [a for a in conf_args() if a.startswith("--")]
    assert flags and [f for f in flags if f not in help_text] == []
    for line in CONF.splitlines():                       # the commented suggestions must be real flags too
        for f in re.findall(r"(--[a-z][a-z-]+)", line) if line.startswith("#") else []:
            if f in ("--help",):
                continue
            assert f in help_text, f"the config suggests {f}, which the daemon does not have"


def test_the_shipped_config_asks_for_the_dead_man_and_uses_absolute_paths():
    a = conf_args()
    assert "--floor" in a and "--floor-confirm" in a and int(a[a.index("--floor-confirm") + 1]) >= 60
    for flag in ("--out", "--decisions", "--report-dir", "--cgroup-root"):
        assert a[a.index(flag) + 1].startswith("/"), flag                       # systemd starts in /: relative paths break


@pytest.fixture
def stubbin(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    for n in ("cora-sentinel", "cora-floor"):
        (b / n).write_text("#!/bin/sh\nexit 0\n")
        (b / n).chmod(0o755)
    return b


def run_install(root, *args):
    return subprocess.run(["bash", str(INSTALL), *args], capture_output=True, text=True, env=dict(os.environ, CORA_ROOT=str(root)))


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_install_renders_the_unit_keeps_your_config_and_uninstall_removes_only_the_unit(tmp_path, stubbin):
    root = tmp_path / "root"
    r = run_install(root, "--bindir", str(stubbin))
    assert r.returncode == 0, r.stderr
    unit = (root / "etc/systemd/system/cora-sentinel.service").read_text()
    assert "@BINDIR@" not in unit and f"ExecStart={stubbin}/cora-sentinel $CORA_ARGS" in unit
    assert f"ExecStopPost=-{stubbin}/cora-floor rollback" in unit
    assert (root / "etc/logrotate.d/cora-sentinel").exists()
    conf = root / "etc/cora-sentinel/cora-sentinel.conf"
    assert conf.exists()
    conf.write_text("CORA_ARGS=--my-edit\n")
    assert run_install(root, "--bindir", str(stubbin)).returncode == 0
    assert conf.read_text() == "CORA_ARGS=--my-edit\n"                          # a reinstall does not clobber your edits
    u = run_install(root, "--uninstall")
    assert u.returncode == 0 and not (root / "etc/systemd/system/cora-sentinel.service").exists() and conf.exists()
    assert not (root / "etc/logrotate.d/cora-sentinel").exists()
    assert "cora-floor remove" in u.stdout                                       # tells you the floor is still there


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_install_refuses_when_the_binaries_are_missing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    r = run_install(tmp_path / "root", "--bindir", str(empty))
    assert r.returncode == 1 and "not found" in r.stderr


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="needs systemd-analyze")
def test_systemd_accepts_the_rendered_unit(tmp_path, stubbin):
    root = tmp_path / "root"
    assert run_install(root, "--bindir", str(stubbin)).returncode == 0
    r = subprocess.run(["systemd-analyze", "verify", "--man=no", str(root / "etc/systemd/system/cora-sentinel.service")],
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stderr.strip() == "", r.stderr


LOGROTATE = DEPLOY / "cora-sentinel.logrotate"


def test_the_logrotate_config_truncates_in_place_because_the_daemon_never_reopens_its_logs():
    t = LOGROTATE.read_text()
    assert "copytruncate" in t and "/var/log/cora-sentinel/*.jsonl" in t
    assert "size " in t and "weekly" not in t and "daily" not in t             # never cut a week of shadow data at a clock tick
    assert "compress" in t and "delaycompress" in t                            # the newest rotated file stays readable as-is


@pytest.mark.skipif(not shutil.which("logrotate"), reason="needs logrotate")
def test_logrotate_accepts_the_config(tmp_path):
    conf = tmp_path / "cora.conf"
    conf.write_text(Path(LOGROTATE).read_text())
    conf.chmod(0o644)
    r = subprocess.run(["logrotate", "-d", "-s", str(tmp_path / "state"), str(conf)], capture_output=True, text=True)
    assert r.returncode == 0 and "error" not in (r.stdout + r.stderr).lower(), r.stdout + r.stderr


def test_the_logs_the_unit_declares_are_the_ones_rotated():
    assert keys("Service", "LogsDirectory") == ["cora-sentinel"]
    for flag in ("--out", "--decisions"):
        assert re.search(rf"{flag} /var/log/cora-sentinel/[\w-]+\.jsonl", CONF), flag
