"""The vendored raw-text validator (cora_sentinel/_vendor/mule): exactly what its VENDOR.lock says, pinned to the
upstream commit that fixed load_spec() for vendored copies, read from here whatever other mule is installed, and
re-vendored only by tools/vendor_bus.py --lib mule.
Run: pytest -q tests/test_vendor_mule.py   (CORA_TEST_NETWORK=1 compares the lock with GitHub;
CORA_MULE_SRC=/path/to/mule-protocol compares it with a local clone)"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cora_sentinel import _vendor

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "vendor_bus.py"
PINNED = "99791550303b5484fcebbbdbd2b09842085b9ef1"      # mule-protocol: load_spec() resolves from its own package
FILES = {"__init__.py", "constrain.py", "prompt.py", "runners.py", "selftest.py", "validator.py", "spec/mule_spec.json",
         "LICENSE", "NOTICE"}
git_needed = pytest.mark.skipif(not shutil.which("git"), reason="needs git")


def run_tool(*args):
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)


def sh(*cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


# ================= the shipped copy =================
def test_the_vendored_mule_is_exactly_what_its_lock_says():
    assert _vendor.verify(_vendor.MULE) == []
    assert _vendor.describe(_vendor.MULE).startswith("vendored mule 0.2.0 @ 9979155 ")
    assert _vendor.describe(_vendor.MULE).endswith("verified")


def test_the_lock_pins_the_fixed_commit_and_covers_every_file():
    lock = _vendor.read_lock(_vendor.MULE)
    assert lock["commit"] == PINNED, "re-vendoring to another commit must be a deliberate change to this test too"
    assert (lock["schema"], lock["name"], lock["distribution"]) == (1, "mule", "mule-protocol")
    assert lock["upstream"] == "https://github.com/nkaralus/mule-protocol" and lock["version"] == "0.2.0"
    assert set(lock["files"]) == FILES
    on_disk = {p.relative_to(_vendor.MULE).as_posix() for p in _vendor.MULE.rglob("*")
               if p.is_file() and "__pycache__" not in p.parts} - {_vendor.LOCK_NAME}
    assert on_disk == FILES
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in lock["files"].values())


def test_no_bytecode_was_vendored():
    lock = _vendor.read_lock(_vendor.MULE)
    assert not [f for f in lock["files"] if f.endswith(".pyc") or "__pycache__" in f]


def test_load_spec_reads_the_vendored_spec():
    from cora_sentinel._vendor.mule import load_spec
    want = json.loads((_vendor.MULE / "spec" / "mule_spec.json").read_text())
    assert load_spec() == want and want["schema_version"] == "1.1.0"


def test_another_mule_on_the_path_is_ignored(tmp_path):
    decoy = tmp_path / "decoy" / "mule"
    (decoy / "spec").mkdir(parents=True)
    (decoy / "__init__.py").write_text("class MuleValidator: FAKE = True\ndef load_spec(): return {'title': 'DECOY'}\n")
    (decoy / "spec" / "mule_spec.json").write_text('{"title": "DECOY"}')
    code = ("from cora_sentinel._vendor.mule import MuleValidator, load_spec; import sys; "
            "print(load_spec()['title'], MuleValidator.__module__, 'mule' in sys.modules)")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(tmp_path / "decoy")] + [p for p in sys.path if p]))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["MuleTaskBlockSpec", "cora_sentinel._vendor.mule.validator", "False"]


def test_verify_notices_a_loosened_spec(tmp_path):
    d = tmp_path / "mule"
    shutil.copytree(_vendor.MULE, d, ignore=shutil.ignore_patterns("__pycache__"))
    assert _vendor.verify(d) == []
    spec = d / "spec" / "mule_spec.json"
    spec.write_text(spec.read_text().replace('"maxLength": 18', '"maxLength": 99'))
    (d / "spec" / "extra.json").write_text("{}")
    assert _vendor.verify(d) == ["modified: spec/mule_spec.json", "unexpected file: spec/extra.json"]


def test_the_wheel_config_ships_the_spec_and_the_notices():
    text = (ROOT / "pyproject.toml").read_text()
    assert '"cora_sentinel._vendor.mule" = ["LICENSE", "NOTICE", "VENDOR.lock", "spec/*.json"]' in text
    assert "*.json" in (ROOT / "MANIFEST.in").read_text()


# ================= tools/vendor_bus.py --lib mule =================
@pytest.fixture
def upstream(tmp_path):
    """A stand-in for the mule repo: mule/ with a nested spec/, committed bytecode, an examples/ dir, LICENSE, NOTICE."""
    repo = tmp_path / "upstream"
    for d in ("mule/spec", "mule/__pycache__", "mule/examples", "tests"):
        (repo / d).mkdir(parents=True)
    (repo / "mule" / "__init__.py").write_text('__version__ = "7.0.0"\n')
    (repo / "mule" / "validator.py").write_text("OK = True\n")
    (repo / "mule" / "spec" / "mule_spec.json").write_text('{"schema_version": "7"}\n')
    (repo / "mule" / "__pycache__" / "validator.cpython-314.pyc").write_bytes(b"\0stale")
    (repo / "mule" / "examples" / "demo.py").write_text("print('demo')\n")
    (repo / "LICENSE").write_text("MIT License\n")
    (repo / "NOTICE").write_text("mule-protocol\n")
    (repo / "tests" / "test_ok.py").write_text("from mule.validator import OK\n\ndef test_ok():\n    assert OK\n")
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-f", ".", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "one", cwd=repo)
    return repo


@git_needed
def test_update_lib_mule_takes_the_package_its_spec_and_notices_and_nothing_else(upstream, tmp_path):
    vend = tmp_path / "vend"
    sha = sh("git", "rev-parse", "HEAD", cwd=upstream)
    r = run_tool("--lib", "mule", "--root", str(vend), "update", "--commit", sha, "--src", str(upstream), "--run-upstream-tests")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "upstream tests: 1 passed" in r.stdout
    lock = json.loads((vend / "VENDOR.lock").read_text())
    assert (lock["name"], lock["distribution"], lock["version"], lock["commit"]) == ("mule", "mule-protocol", "7.0.0", sha)
    assert sorted(lock["files"]) == ["LICENSE", "NOTICE", "__init__.py", "spec/mule_spec.json", "validator.py"]
    assert not (vend / "__pycache__").exists() and not (vend / "examples").exists()
    assert run_tool("--lib", "mule", "--root", str(vend), "check").returncode == 0
    assert run_tool("--lib", "mule", "--root", str(vend), "check-upstream", "--src", str(upstream)).returncode == 0
    (vend / "spec" / "mule_spec.json").write_text('{"schema_version": "8"}\n')
    r = run_tool("--lib", "mule", "--root", str(vend), "check")
    assert r.returncode == 1 and "modified: spec/mule_spec.json" in r.stdout


@git_needed
def test_without_lib_the_tool_still_means_subnetbus():
    r = run_tool("check")
    assert r.returncode == 0 and "engine-telemetry-bus" in r.stdout


# ================= against the real upstream =================
@git_needed
@pytest.mark.skipif(not os.environ.get("CORA_MULE_SRC"), reason="set CORA_MULE_SRC to a mule-protocol clone to compare")
def test_the_lock_matches_a_local_upstream_clone():
    r = run_tool("--lib", "mule", "check-upstream", "--src", os.environ["CORA_MULE_SRC"])
    assert r.returncode == 0, r.stdout + r.stderr


@git_needed
@pytest.mark.skipif(not os.environ.get("CORA_TEST_NETWORK"), reason="set CORA_TEST_NETWORK=1 to compare with GitHub")
def test_the_lock_matches_the_real_upstream_commit():
    r = run_tool("--lib", "mule", "check-upstream")
    assert r.returncode == 0, r.stdout + r.stderr
