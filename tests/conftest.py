"""Suite-wide guards."""
import os
import sys

import pytest


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
