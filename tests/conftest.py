"""Suite-wide guards."""
import os
import sys
from pathlib import Path

import pytest

CHECKOUT = Path(__file__).resolve().parents[1]


def _tested_copy() -> Path:
    import cora_sentinel
    return Path(cora_sentinel.__file__).resolve().parent


def pytest_configure(config):
    """Stop before collecting anything if the cora_sentinel being imported is NOT this checkout's. A stale editable
    install, or an old copy earlier on sys.path, makes every test exercise other code while reporting on this one:
    it happened twice during 0.10 development ("71 passed" against an old tree, then a signature error from it).
    CORA_TEST_INSTALLED=1 tests an installed copy on purpose (the report header still says which)."""
    copy = _tested_copy()
    if os.environ.get("CORA_TEST_INSTALLED") == "1":
        # stderr, not the report header: -q (which CI uses) hides the header, and this is the run that must say it
        sys.stderr.write(f"CORA_TEST_INSTALLED=1: testing the installed cora_sentinel at {copy}\n")
        return
    try:
        copy.relative_to(CHECKOUT)
    except ValueError:
        raise pytest.UsageError(
            f"stale import: these tests are in {CHECKOUT}, but `import cora_sentinel` loads {copy}. Every test would "
            f"run other code. Fix: pip install -e {CHECKOUT}  (or PYTHONPATH={CHECKOUT / 'src'}); to test an "
            f"installed copy on purpose, set CORA_TEST_INSTALLED=1.") from None


def pytest_report_header(config):
    return f"cora_sentinel under test: {_tested_copy()}"


@pytest.fixture(autouse=True)
def the_test_process_keeps_its_identity(request):
    """A test must never change the identity of the pytest process itself. 0.10.0's pre-flight tests called
    cora-run's main() in-process; under the privileged CI (`sudo pytest` sets SUDO_UID) it dropped the WHOLE run to the
    unprivileged user, every later test ran as that user, and pytest's cleanup of /tmp/pytest-of-root died with
    PermissionError. This names the test that did it, at the test that did it."""
    before = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    yield
    after = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if after != before:
        msg = (f"{request.node.nodeid} changed the pytest process's uid/euid/gid/egid from {before} to {after}; "
               f"every later test runs with the wrong identity and pytest's tmp cleanup will fail")
        # printed NOW, outside pytest's capture: a process that left root cannot get back, and the cleanup crash that
        # follows kills the run before pytest prints its error summary
        capman = request.config.pluginmanager.getplugin("capturemanager")
        with capman.global_and_fixture_disabled():
            sys.stderr.write(f"\n\n*** {msg}\n\n")
            sys.stderr.flush()
        pytest.fail(msg)
