# Packaging and releases

Three artifacts, all built from one tree with no network after the first fetch of the build tools:

| Artifact | For | Runtime dependencies |
|---|---|---|
| `cora_sentinel-X-py3-none-any.whl` | `pip install` into a venv (the model path, development) | none |
| `cora_sentinel-X.tar.gz` (sdist) | rebuilding from source | none |
| `cora-sentinel_X-1_all.deb` | a clean install on Ubuntu/Debian with systemd | `python3 (>= 3.10)`, `nftables` |

```bash
pip install build                       # once
packaging/build_release.sh              # checks the vendored gate, then builds all three + dist/SHA256SUMS
sudo dpkg -i dist/cora-sentinel_*_all.deb
```

`CORA_BUILD_NO_ISOLATION=1` builds offline with the installed setuptools. `SOURCE_DATE_EPOCH` defaults to the last
commit's time, and on one toolchain the same tree gives the same wheel, the same sdist (rewritten deterministically by
`packaging/normalize_sdist.py`) and the same `.deb`, so `SHA256SUMS` is reproducible: building twice gave identical files.
The epoch is the commit time, so a new commit changes the bytes; pass `SOURCE_DATE_EPOCH` to pin it. Across setuptools
versions the wheel's bytes can differ (its contents do not).

## The vendored safety gate

The one thing cora-sentinel used to install from GitHub is [`engine-telemetry-bus`](https://github.com/nkaralus/engine-telemetry-bus)
(the `subnetbus` module: the GI_1-GI_3 gates and the registry). It is the check the verdict code asks before it acts, and
without it the daemon refuses to act at all. It is now **vendored**: a verbatim copy at one pinned commit lives in
`src/cora_sentinel/_vendor/subnetbus/`, so the code that ships is the code the tests ran against, a wheel installs
offline, and no `git+https` requirement is left (PyPI refuses those).

- **`VENDOR.lock`** (beside the code, shipped with it) records the upstream URL, the full commit
  (`ac3f126946056b3b24eea9dbc15015b5a5639706`, bus version 0.1.0) and the sha256 of every file, license included.
- **The vendored copy always wins.** Another `subnetbus` on the path is ignored (tested).
- **Drift is visible.** `cora-selfcheck` fails if a vendored file was modified, added or removed; the daemon prints
  `vendored subnetbus 0.1.0 @ ac3f126 verified` (or `MODIFIED (...)`) at start; `pytest tests/test_vendor.py` and
  `python tools/vendor_bus.py check` verify it offline. It warns rather than refuses at start, so a hotfix on a live box is
  possible but loud.
- **The license is bundled.** The bus's MIT notice ships as package data in the wheel and sdist, in the `.deb`'s
  `copyright` file, and beside the code.

Changing it is deliberate and has one entry point:

```bash
python tools/vendor_bus.py check                                   # offline: the files match the lock
python tools/vendor_bus.py check-upstream                          # online: the lock matches GitHub at the pinned commit
python tools/vendor_bus.py update --commit <40-char sha> --run-upstream-tests [--src ~/engine-telemetry-bus]
```

`update` exports exactly that commit with `git archive` (a dirty working tree cannot leak in), refuses a branch, a tag or
a short unknown ref, runs the bus's own test-suite first and aborts if it fails, then replaces the tree and the lock. After
it: run the whole suite, update `PINNED` in `tests/test_vendor.py`, and say why in the CHANGELOG. The upstream repo has no
tags, so the commit is the only stable name; tagging `ac3f126` there as `v0.1.0` would make the lock easier to read.

## The .deb

Installing does **not** start or enable anything: the kernel floor the daemon can install is host-wide, so the first
start is yours (the install prints the three steps). The package is `Architecture: all`, installs the code to
`/usr/lib/python3/dist-packages`, the nine commands to `/usr/bin`, the unit to `/usr/lib/systemd/system`, and:

| | |
|---|---|
| `/etc/cora-sentinel/cora-sentinel.conf` | conffile: the daemon's arguments (`CORA_ARGS`). dpkg keeps your edits across upgrades |
| `/etc/logrotate.d/cora-sentinel` | conffile: size-based, `copytruncate` |
| `/usr/share/doc/cora-sentinel/` | README, these docs, `changelog.gz`, `copyright` (both licenses) |

The unit is in `/usr/lib/systemd/system`, not `/etc`, so it is not a conffile: files under `/usr` never are, and putting it
in `/etc/systemd/system` would make it silently override the package's updates. Customize it with `systemctl edit
cora-sentinel` (a drop-in). The venv installer (`deploy/install-service.sh`) is unchanged and uses the same unit template.

### What each dpkg action does

| Action | Service | Kernel floor | Config | `/var/lib/cora-sentinel` | `/var/log/cora-sentinel` |
|---|---|---|---|---|---|
| install | **not** started or enabled | untouched | installed | - | - |
| upgrade | restarted **only if it was running** | **kept** (a confirmed floor survives; an unchanged allow set asks no new confirmation) | your edits kept | kept | kept |
| remove | stopped and disabled (an unconfirmed floor goes with it) | **removed** | kept | kept | kept |
| purge | (as remove) | (as remove) | removed | **removed** | **kept** (the audit trail) |

On removal the package takes the floor out because it also removes `cora-floor`: a confirmed floor left in the kernel
would have nothing left to remove it. **Per-task isolation rules are not touched** (they contain tasks the daemon
isolated; releasing them is a person's decision). If any exist, removal says so and tells you to run
`cora-firewall purge` first, while the tool is still installed. An empty `inet cora` table is tidied away.
Files dpkg does not own (anything you put in `/etc/cora-sentinel`, the side-install below) are left alone.

### The model

The `.deb` is the core: the sentinel, the floor, the dynamic policy, the replay tool. Running the local model needs
`llama-cpp-python`, which is not in the Ubuntu archive, and Ubuntu 24.04 refuses `pip install` into the system Python
(PEP 668, `externally-managed-environment`; verified). A side-install into its own directory works:

```bash
sudo mkdir -p /opt/cora-sentinel/pylibs
sudo python3 -m pip install --target /opt/cora-sentinel/pylibs --only-binary=:all: \
    --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu llama-cpp-python
echo 'PYTHONPATH=/opt/cora-sentinel/pylibs' | sudo tee -a /etc/cora-sentinel/cora-sentinel.conf
```

then add `--model /path/to/model.gguf` to `CORA_ARGS` and restart. What was **verified**: PyPI has no prebuilt
`llama-cpp-python` wheel (a plain `pip install` compiles it and needs a compiler and cmake); the project's CPU wheel index
has one (`py3-none-manylinux`, no compiler); `--target` is accepted under PEP 668; system Python imports it through
`PYTHONPATH`; and this repo's `VERDICT_GBNF` parses in the real llama.cpp grammar engine. What was **not**: loading a model
and running inference through the unit, and GPU builds (that index is the CPU one; for CUDA use the matching index or
compile). `PYTHONPATH` is set in the config, not the unit, so the side-install is opt-in and visible. The venv install
(`pip install 'cora-sentinel[model]'`) is unaffected.

## Testing it

- `pytest tests/test_vendor.py tests/test_packaging_deb.py`: the drift check, wheel/sdist/.deb contents, reproducibility,
  and every maintainer script run against **stubbed** `systemctl`/`nft`/`cora-floor` in a temp dir. Non-destructive.
- `packaging/lifecycle_test.sh`: the real `dpkg -i`, reinstall (upgrade), `-r` and `-P`, with assertions (the floor survives
  the upgrade, the edited config survives, removal takes the floor out, purge cleans state and keeps the logs). It
  **stops the service and removes a floor**, so it refuses to run unless `CORA_LIFECYCLE_TEST=disposable-machine` is set
  and the machine shows no sign of running cora-sentinel (package, service, `inet cora` table, config or state). Use a
  throwaway VM or container, never the live host.

## Compatibility and caveats

- Built and tested on Ubuntu 24.04 with Python 3.12. The package declares `python3 (>= 3.10)` and `requires-python >=3.10`;
  22.04 (3.10) and Debian 12 (3.11) are **not tested**.
- `pyproject.toml` asks for `setuptools>=68` and uses the table form of the license, so Ubuntu 24.04's own setuptools (68.1.2)
  can build it. Newer setuptools prints a deprecation warning for that form (it announces 2027-02-18 as the date to move to
  PEP 639); when the oldest distro you target ships setuptools 77 or later, switch to `license = "MIT"` and
  `license-files`.
- The `.deb` is built with `dpkg-deb` alone, so it is not a Debian *source* package (no `debian/` tree for a PPA or the
  archive). `Maintainer:` defaults to a GitHub no-reply address; set `DEB_MAINTAINER` to change it.
- `lintian` (run on the final package): **0 errors**, 14 warnings, all known and left alone. `maintainer-script-calls-systemctl`
  (4): the scripts call `systemctl` directly, guarded by `/run/systemd/system`, instead of debhelper's generated
  `deb-systemd-invoke` snippets. `no-manual-page` (9): the commands have `--help` but no man pages yet.
  `initial-upload-closes-no-bugs`: only relevant to an upload to the Debian archive.
- Not signed. To publish, put the files in an apt repository (`reprepro`, `aptly`) and sign that.
