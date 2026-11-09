"""The CI workflows keep their promises: every supported Python is in the matrix, the test job is unprivileged, permissions are
read-only, actions are pinned, and the destructive lifecycle workflow can only be started by hand.
Skips when there is no .github directory (an sdist, an installed copy). Run: pytest -q tests/test_ci.py"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows"
pytestmark = pytest.mark.skipif(not WF.is_dir(), reason="no .github/workflows in this tree")


def text(name):
    return (WF / name).read_text()


def job(name):
    """The text of one job in ci.yml (2-space-indented key under jobs:)."""
    t = text("ci.yml").split("\njobs:\n", 1)[1]
    m = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \w[\w-]*:\n|\Z)", t, re.M | re.S)
    assert m, f"no job {name!r} in ci.yml"
    return m.group(1)


def version_key(v):
    return tuple(int(p) for p in v.split("."))


def test_the_matrix_covers_every_supported_python_from_the_declared_floor():
    m = re.search(r"python:\s*\[([^\]]+)\]", job("unprivileged"))
    versions = [v.strip().strip("\"'") for v in m.group(1).split(",")]
    floor = re.search(r'requires-python\s*=\s*">=(\d+\.\d+)"', (ROOT / "pyproject.toml").read_text()).group(1)
    assert versions == sorted(versions, key=version_key)
    assert versions[0] == floor, "the oldest tested Python must be the one pyproject.toml promises"
    assert {"3.10", "3.11", "3.12", "3.13"} <= set(versions)
    assert "fail-fast: false" in text("ci.yml")                      # one failing version must not hide the others


def test_the_unprivileged_and_package_jobs_never_use_sudo_for_python_pytest_or_pip():
    for name in ("unprivileged", "package"):
        for line in job(name).splitlines():
            assert not re.search(r"sudo\s+.*(pytest|python|pip)\b", line), f"{name} must run unprivileged: {line.strip()}"
    assert "python -m pytest -q -ra" in job("unprivileged")


def test_the_original_job_names_are_kept_and_the_experimental_root_job_cannot_block_a_merge():
    for name in ("unprivileged", "package", "privileged"):             # the names the repository's CI has always had
        job(name)
    priv = job("privileged")
    assert "continue-on-error: true" in priv
    assert "sudo bash -c 'ulimit -n 65536 && exec ./venv/bin/python -m pytest -q'" in priv


def test_the_root_job_raises_the_fd_limit_inside_sudo_not_before_it():
    """sudo's PAM session resets RLIMIT_NOFILE: a `ulimit` before sudo never reaches the tests (run #49, [Errno 24])."""
    runs = [l.strip() for l in job("privileged").splitlines() if l.strip().startswith("- run:") and "pytest" in l]
    assert len(runs) == 1 and runs[0].index("sudo") < runs[0].index("ulimit -n")


def test_the_unprivileged_job_runs_the_hud_qt_tests_instead_of_skipping_them():
    j = job("unprivileged")
    assert '".[dev,hud]"' in j and 'CORA_REQUIRE_QT: "1"' in j and "QT_QPA_PLATFORM: offscreen" in j


def test_the_package_job_installs_the_wheel_clean_and_runs_selfcheck_strictly():
    runs = "\n".join(l for l in job("package").splitlines() if not l.lstrip().startswith("#"))      # what runs, not what is said
    assert "/tmp/clean/bin/cora-selfcheck" in runs and "|| true" not in runs      # the old `|| true` hid a damaged install


@pytest.mark.parametrize("name", ["ci.yml", "lifecycle.yml"])
def test_permissions_are_read_only_and_nothing_dangerous_is_used(name):
    t = text(name)
    assert re.search(r"^permissions:\n  contents: read\n", t, re.M)
    assert "pull_request_target" not in t and "secrets." not in t and "GITHUB_TOKEN" not in t


@pytest.mark.parametrize("name", ["ci.yml", "lifecycle.yml"])
def test_actions_are_pinned_to_a_major_version(name):
    uses = re.findall(r"uses:\s*(\S+)", text(name))
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@v\d+", u) for u in uses), uses


def test_the_lifecycle_workflow_can_only_be_started_by_hand_and_names_the_token():
    t = text("lifecycle.yml")
    on = t.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert on.strip() == "workflow_dispatch:", "the workflow that stops a service and removes a floor must be manual only"
    assert "CORA_LIFECYCLE_TEST=disposable-machine" in t and "packaging/lifecycle_test.sh" in t
    assert "lifecycle_test" not in text("ci.yml").replace("lifecycle.yml", "")        # and the unattended CI never runs it


def test_the_build_job_checks_the_gate_the_checksums_reproducibility_and_lintian():
    t = text("ci.yml")
    for needle in ("CORA_TEST_NETWORK=1 python -m pytest -q tests/test_vendor.py", "packaging/build_release.sh",
                   "sha256sum -c SHA256SUMS", "cmp ", "lintian --fail-on error"):
        assert needle in job("package"), needle
    assert "python tools/vendor_bus.py check" in job("unprivileged")


def test_the_package_job_can_import_the_project_wherever_it_runs_pytest():
    """The package job installs build tools, not the project. A pytest line there must say where the code is (PYTHONPATH=src), or the
    first run on a real runner fails with ModuleNotFoundError (it did, and a local run could not show it: there the project was installed)."""
    runs = [l for l in job("package").splitlines() if "pytest" in l and not l.lstrip().startswith(("#", "python -m pip install"))
            and "pip install" not in l]
    installs_project = re.search(r"pip install (-e )?[\"']?\.", job("package")) is not None
    assert runs, "the package job runs no tests?"
    for l in runs:
        assert installs_project or "PYTHONPATH=src" in l, f"pytest cannot import cora_sentinel here: {l.strip()}"


def test_every_script_the_workflows_call_exists_and_is_executable():
    for rel in ("packaging/build_release.sh", "packaging/lifecycle_test.sh", "tools/vendor_bus.py"):
        p = ROOT / rel
        assert p.is_file(), rel
        assert (p.stat().st_mode & 0o111), f"{rel} must be executable in git (git update-index --chmod=+x)"
