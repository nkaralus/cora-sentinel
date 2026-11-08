"""The stale-import guard in tests/conftest.py, exercised the way it fails in real life: an older cora_sentinel earlier
on sys.path than this checkout's."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_pytest(tmp_path, extra_env):
    fake = tmp_path / "old_tree" / "cora_sentinel"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text('__version__ = "0.0.0-stale"\n')
    env = dict(os.environ, PYTHONPATH=str(fake.parent), **extra_env)
    env.pop("CORA_TEST_INSTALLED", None) if "CORA_TEST_INSTALLED" not in extra_env else None
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--co",
                           str(ROOT / "tests" / "test_scope.py")], cwd=ROOT, env=env, capture_output=True, text=True), fake


def test_a_stale_copy_stops_the_run_before_any_test(tmp_path):
    r, fake = run_pytest(tmp_path, {})
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "stale import" in out and str(fake.resolve()) in out and str(ROOT) in out
    assert "collected" not in out                                   # nothing ran against the wrong code


def test_testing_an_installed_copy_on_purpose_is_allowed_and_announced(tmp_path):
    r, fake = run_pytest(tmp_path, {"CORA_TEST_INSTALLED": "1"})
    out = r.stdout + r.stderr
    # the guard let it through (the empty fake copy then fails to collect, which is the point: it was allowed)
    assert f"testing the installed cora_sentinel at {fake.resolve()}" in r.stderr and "stale import" not in out


def test_this_run_is_testing_this_checkout():
    import cora_sentinel
    Path(cora_sentinel.__file__).resolve().relative_to(ROOT)       # raises if not
