# Continuous integration

Two workflows in `.github/workflows/`.

## `ci.yml`: unprivileged, on every push to `main` and every pull request

| Job | What it does |
|---|---|
| `unprivileged` (Python 3.10, 3.11, 3.12, 3.13) | `pip install -e ".[dev]"` (there are no runtime dependencies), `python tools/vendor_bus.py check`, `pytest -q -ra`. No root and no sudo: the kernel tests (cgroups, nftables, NFLOG, network namespaces) see they are not root and **skip themselves** |
| `package` | the vendored copy against GitHub at the pinned commit (`CORA_TEST_NETWORK=1`), `packaging/build_release.sh`, `sha256sum -c`, a second build that must be byte-identical, the wheel installed into a clean venv with `cora-selfcheck` run **strictly**, `lintian --fail-on error`, and the artifacts uploaded for 14 days |
| `privileged` | **unchanged from the repository's original CI, kept deliberately**: an experiment that runs the whole suite as root on the hosted runner (`sudo ... pytest`) to find out whether it exposes cgroup v2, `nfnetlink_log` and `NETLINK_SOCK_DIAG`. `continue-on-error: true`, so it can never block a merge. (Only a 30-minute timeout was added.) |

The job names are the ones the repository's CI has always had, so any required-status settings keep matching.
`cora-selfcheck` exits 1 only for a REQUIRED problem (a damaged install, a modified vendored gate); the machine capabilities a
runner lacks are reported, not failed. The previous version of this step ended in `|| true`, which hid both.
`fail-fast` is off, so one failing Python does not hide the others. The oldest Python in the matrix is checked against
`requires-python` by a test (`tests/test_ci.py`), as are read-only permissions, major-version-pinned actions, the absence of
`sudo` around Python in the two unprivileged jobs, that the experimental job stays non-blocking, and that the destructive
workflow below is manual only.

### What CI does not cover

The real-kernel tests: they need root, cgroup v2, nftables and a real network address, and run on the author's bare metal
(`sudo -E pytest -q`). So CI says nothing about the tap, the floor, the dead-man or the dynamic policy against a real kernel;
it covers everything else, on every Python. Also not covered: loading a model.

### How it was checked before it was published

The `unprivileged` job's exact steps (fresh venv, install, vendor check, `pytest -ra`) were run as an **unprivileged user** on real
CPython 3.10.20, 3.11.15, 3.12.3 and 3.13.14: each gave `619 passed, 107 skipped` (the skips are the kernel tests). The hardened
tap tests were also run as root, under ambient noise, on 3.10 and 3.13. The `package` job's commands were run as written. The
workflow files are linted with `actionlint`. **They have not run on GitHub yet:** the first push is the real test. Things that
can differ on a hosted runner are the preinstalled tools (the tests for `systemd-analyze`, `logrotate` and `dpkg-deb` skip when
absent) and the `apt-get install lintian` step.

Suggested branch protection: require the four `unprivileged` checks and `package` (not `privileged`).

## `lifecycle.yml`: the real systemd lifecycle, manual only

`packaging/lifecycle_test.sh` does a real `dpkg -i`, upgrade, `-r` and `-P`. It **stops the cora-sentinel service and removes a
kernel floor**, so it must never run on the live host. This workflow runs it on a disposable GitHub-hosted runner (a throwaway
VM with a real systemd), started by hand from the Actions tab (Run workflow). It is the check for the one part the unit tests
stub: `stop`/`disable` ordering with `ExecStopPost`, the restart on upgrade, and removing a real floor. If the runner's kernel
cannot do nftables the install step says so; that is a limit of the runner, not of the package. It has not been run yet.

## Noise on purpose: `CORA_TEST_AMBIENT=1`

The tap tests blocklist the machine's own LAN address, and the sock_diag destroy stream is host-wide, so anything else on the
host talking to that address while a test runs is counted as a slip (this was a rare flake on a busy workstation). The tests
now assert on their own listener's port, which noise cannot share. Setting `CORA_TEST_AMBIENT=1` makes a non-task process
connect to the blocklisted address continuously during those tests, so the scoping is exercised on demand and a regression to a
global assertion fails at once:

```bash
sudo -E CORA_TEST_AMBIENT=1 python -m pytest -q tests/test_sockdiag.py tests/test_nflog.py
```

`tests/_ambient.py` explains which counters are host-wide (slips) and which are not (per-task `syn`/`udp` counters and live
hits).
