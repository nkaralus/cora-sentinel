"""The vendored safety gate (cora_sentinel/_vendor/subnetbus): it is exactly what VENDOR.lock says, nothing can swap it
quietly, the importers always use it, and tools/vendor_bus.py is the only way to change it.
Run: pytest -q tests/test_vendor.py   (CORA_TEST_NETWORK=1 also compares the lock with GitHub)"""
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from cora_sentinel import _vendor

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "vendor_bus.py"
PINNED = "ac3f126946056b3b24eea9dbc15015b5a5639706"      # the commit that was confirmed and that the suite was run against
git_needed = pytest.mark.skipif(not shutil.which("git"), reason="needs git")


# ================= the shipped copy =================
def test_the_vendored_copy_is_exactly_what_the_lock_says():
    assert _vendor.verify() == []
    assert _vendor.describe().endswith("verified")


def test_the_lock_pins_the_confirmed_commit_and_covers_every_file():
    lock = _vendor.read_lock()
    assert lock["commit"] == PINNED, "re-vendoring to another commit must be a deliberate change to this test too"
    assert re.fullmatch(r"[0-9a-f]{40}", lock["commit"])
    assert (lock["schema"], lock["name"], lock["distribution"], lock["license"]) == (1, "subnetbus", "engine-telemetry-bus", "MIT")
    assert lock["upstream"] == "https://github.com/nkaralus/engine-telemetry-bus" and lock["version"] == "0.1.0"
    on_disk = {p.name for p in _vendor.HERE.iterdir() if p.is_file()} - {_vendor.LOCK_NAME}
    assert set(lock["files"]) == on_disk and "LICENSE" in on_disk and "gates.py" in on_disk
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in lock["files"].values())


def test_the_bus_license_notice_is_present():
    text = (_vendor.HERE / "LICENSE").read_text()
    assert "MIT License" in text and "Copyright" in text


def test_the_api_the_daemon_relies_on_is_there():
    from cora_sentinel._vendor import subnetbus as bus
    for name in ("AABB", "Registry", "Action", "check_all", "GateResult", "Verdict", "PathGuard"):
        assert hasattr(bus, name), name
    assert callable(bus.check_all)


# ================= verify() notices tampering =================
@pytest.fixture
def copy(tmp_path):
    d = tmp_path / "subnetbus"
    shutil.copytree(_vendor.HERE, d, ignore=shutil.ignore_patterns("__pycache__"))
    return d


def test_verify_detects_a_modified_a_missing_and_an_unexpected_file(copy):
    assert _vendor.verify(copy) == []
    (copy / "gates.py").write_text((copy / "gates.py").read_text() + "\n# loosened\n")
    (copy / "geometry.py").unlink()
    (copy / "sneaky.py").write_text("x = 1\n")
    problems = _vendor.verify(copy)
    assert "modified: gates.py" in problems and "missing: geometry.py" in problems and "unexpected file: sneaky.py" in problems
    assert _vendor.describe(copy).split("MODIFIED")[0].endswith("@ ac3f126 ") and "MODIFIED" in _vendor.describe(copy)


def test_bytecode_caches_are_not_drift_but_a_broken_lock_is(copy):
    (copy / "__pycache__").mkdir()
    (copy / "__pycache__" / "gates.cpython-312.pyc").write_bytes(b"\0")
    assert _vendor.verify(copy) == []
    (copy / _vendor.LOCK_NAME).write_text("{not json")
    assert _vendor.verify(copy)[0].startswith("VENDOR.lock unreadable")
    (copy / _vendor.LOCK_NAME).unlink()
    assert _vendor.verify(copy)[0].startswith("VENDOR.lock unreadable") and "NO LOCK FILE" in _vendor.describe(copy)


def test_selfcheck_fails_loudly_when_the_gate_is_modified(monkeypatch, capsys):
    from cora_sentinel import selfcheck
    monkeypatch.setattr(_vendor, "verify", lambda root=None: ["modified: gates.py"])
    rc = selfcheck.main()
    out = capsys.readouterr().out
    assert rc != 0 and "was modified" in out and "gates.py" in out


# ================= the importers use the vendored copy, whatever else is installed =================
def test_a_different_subnetbus_on_the_path_is_ignored(tmp_path):
    fake = tmp_path / "fake" / "subnetbus"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("class Registry: FAKE = True\nclass AABB: FAKE = True\nclass Action: FAKE = True\n"
                                      "def check_all(*a, **k): raise SystemExit('the fake gate was used')\n")
    code = ("import sys; from cora_sentinel import daemon, verdict; "
            "print(daemon.Registry.__module__, verdict.check_all.__module__, 'subnetbus' in sys.modules)")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(tmp_path / "fake")] + [p for p in sys.path if p]))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    reg, gate, shadow = r.stdout.split()
    assert reg.startswith("cora_sentinel._vendor.subnetbus") and gate.startswith("cora_sentinel._vendor.subnetbus") and shadow == "False"


def test_nothing_imports_the_bus_by_its_old_name():
    bad = re.compile(r"^\s*(from|import) subnetbus\b", re.M)
    src = ROOT / "src" / "cora_sentinel"
    offenders = [str(p.relative_to(ROOT)) for p in src.rglob("*.py") if "_vendor" not in p.parts and bad.search(p.read_text())]
    assert offenders == []


# ================= tools/vendor_bus.py =================
def run_tool(*args):
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)


def sh(*cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def upstream(tmp_path):
    """A tiny stand-in for the bus repo: the same layout (subnetbus/, tests/, LICENSE), two commits."""
    repo = tmp_path / "upstream"
    (repo / "subnetbus").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "subnetbus" / "__init__.py").write_text('__version__ = "9.9.9"\nfrom .core import VALUE\n')
    (repo / "subnetbus" / "core.py").write_text("VALUE = 1\n")
    (repo / "LICENSE").write_text("MIT License\n\nCopyright (c) 2026 Somebody\n")
    (repo / "tests" / "test_core.py").write_text("from subnetbus import VALUE\n\ndef test_value():\n    assert VALUE == 1\n")
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", ".", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "one", cwd=repo)
    (tmp_path / "first.sha").write_text(sh("git", "rev-parse", "HEAD", cwd=repo))
    return repo


def first_sha(upstream):
    return (upstream.parent / "first.sha").read_text()


@git_needed
def test_update_vendors_exactly_a_commit_and_writes_a_complete_lock(upstream, tmp_path):
    vend = tmp_path / "vend"
    r = run_tool("--root", str(vend), "update", "--commit", first_sha(upstream), "--src", str(upstream), "--run-upstream-tests")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "upstream tests: 1 passed" in r.stdout
    lock = json.loads((vend / "VENDOR.lock").read_text())
    assert lock["commit"] == first_sha(upstream) and lock["version"] == "9.9.9" and lock["distribution"] == "engine-telemetry-bus"
    assert sorted(lock["files"]) == ["LICENSE", "__init__.py", "core.py"]
    assert not (vend / "tests").exists() and (vend / "LICENSE").read_text().startswith("MIT License")
    assert run_tool("--root", str(vend), "check").returncode == 0
    assert run_tool("--root", str(vend), "check-upstream", "--src", str(upstream)).returncode == 0


@git_needed
def test_check_fails_on_drift_and_says_how_to_fix_it(upstream, tmp_path):
    vend = tmp_path / "vend"
    run_tool("--root", str(vend), "update", "--commit", first_sha(upstream), "--src", str(upstream))
    (vend / "core.py").write_text("VALUE = 2\n")
    r = run_tool("--root", str(vend), "check")
    assert r.returncode == 1 and "modified: core.py" in r.stdout and "git checkout" in r.stdout


@git_needed
def test_a_dirty_working_tree_cannot_leak_into_the_vendored_copy(upstream, tmp_path):
    (upstream / "subnetbus" / "core.py").write_text("VALUE = 1  # uncommitted\nBACKDOOR = True\n")
    (upstream / "subnetbus" / "untracked.py").write_text("x = 1\n")
    vend = tmp_path / "vend"
    assert run_tool("--root", str(vend), "update", "--commit", first_sha(upstream), "--src", str(upstream)).returncode == 0
    assert (vend / "core.py").read_text() == "VALUE = 1\n" and not (vend / "untracked.py").exists()


@git_needed
@pytest.mark.parametrize("ref", ["main", "HEAD", "v1.0", "abc", "zzzzzzz", "deadbeefdeadbeef"])
def test_only_a_real_hex_commit_is_accepted(upstream, tmp_path, ref):
    vend = tmp_path / "vend"
    r = run_tool("--root", str(vend), "update", "--commit", ref, "--src", str(upstream))
    assert r.returncode == 2 and not vend.exists()


@git_needed
def test_failing_upstream_tests_stop_the_update_and_leave_the_old_copy_alone(upstream, tmp_path):
    vend = tmp_path / "vend"
    run_tool("--root", str(vend), "update", "--commit", first_sha(upstream), "--src", str(upstream))
    before = {p.name: p.read_bytes() for p in vend.iterdir()}
    (upstream / "subnetbus" / "core.py").write_text("VALUE = 2\n")                 # breaks the upstream test (VALUE == 1)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "break", cwd=upstream)
    second = sh("git", "rev-parse", "HEAD", cwd=upstream)
    r = run_tool("--root", str(vend), "update", "--commit", second, "--src", str(upstream), "--run-upstream-tests")
    assert r.returncode == 2 and "own tests fail" in r.stderr
    assert {p.name: p.read_bytes() for p in vend.iterdir()} == before


@git_needed
def test_update_replaces_the_tree_and_drops_files_upstream_removed(upstream, tmp_path):
    vend = tmp_path / "vend"
    run_tool("--root", str(vend), "update", "--commit", first_sha(upstream), "--src", str(upstream))
    (upstream / "subnetbus" / "core.py").unlink()
    (upstream / "subnetbus" / "__init__.py").write_text('__version__ = "10.0.0"\n')
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=upstream)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "two", cwd=upstream)
    second = sh("git", "rev-parse", "HEAD", cwd=upstream)
    assert run_tool("--root", str(vend), "update", "--commit", second, "--src", str(upstream)).returncode == 0
    assert sorted(p.name for p in vend.iterdir()) == ["LICENSE", "VENDOR.lock", "__init__.py"]
    assert json.loads((vend / "VENDOR.lock").read_text())["version"] == "10.0.0"


@git_needed
def test_check_upstream_catches_a_lock_that_disagrees_with_upstream(upstream, tmp_path):
    vend = tmp_path / "vend"
    run_tool("--root", str(vend), "update", "--commit", first_sha(upstream), "--src", str(upstream))
    lock = json.loads((vend / "VENDOR.lock").read_text())
    lock["files"]["core.py"] = "0" * 64
    (vend / "VENDOR.lock").write_text(json.dumps(lock))
    r = run_tool("--root", str(vend), "check-upstream", "--src", str(upstream))
    assert r.returncode == 1 and "core.py: differs from upstream" in r.stdout


@git_needed
@pytest.mark.skipif(not os.environ.get("CORA_TEST_NETWORK"), reason="set CORA_TEST_NETWORK=1 to compare with GitHub")
def test_the_lock_matches_the_real_upstream_commit():
    r = run_tool("check-upstream")
    assert r.returncode == 0, r.stdout + r.stderr
