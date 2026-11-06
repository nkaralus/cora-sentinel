# Changelog

## 0.8.2

### Added
- **Man pages for all nine commands** (`cora-sentinel`, `cora-run`, `cora-cgroup`, `cora-firewall`, `cora-floor`, `cora-blocklist`,
  `cora-report`, `cora-demo`, `cora-selfcheck`), installed by the `.deb` to `/usr/share/man/man1/*.1.gz`.
  `tools/gen_man.py` builds them at build time; nothing generated is checked in. The OPTIONS and COMMANDS sections come from the
  real argparse parsers (including `cora-floor`'s subcommands and `dyn-replay`'s options), so they cannot drift; the descriptions,
  signals, files, environment, exit status and examples are in the generator. The page date is the build epoch, so the `.deb` stays
  byte-reproducible.
- `tests/test_man.py` (19): every console script has a page; every page is clean roff (`groff -ww`) and has the standard sections
  and an EXIT STATUS; no option or command is listed without a description; every option and subcommand the parsers accept is in
  the page; every subcommand in the hand-parsed tools' usage text is in theirs; every `CORA_*` environment variable a tool reads is
  documented; `SEE ALSO` points only at pages that exist; reproducible output; roff escaping. Mutation-checked (a new undocumented
  environment variable, subcommand and option each fail it). The `.deb` test checks the nine `.1.gz` files, their date and version,
  and that they pass `groff -ww`.
- `tests/test_ci.py` (+1): a `pytest` line in the CI `package` job must set `PYTHONPATH=src` or the job must install the project. The
  first real GitHub run failed there with `ModuleNotFoundError` (fixed upstream in `de26085`); a local emulation could not show it,
  because the project was installed on the machine that ran it. The test fails on the original workflow and passes on the fix.
- `packaging/lifecycle_test.sh` checks the installed man pages (and `man -w`) and that purge removes them, and skips that on an image
  that excludes `/usr/share/man`.

### Fixed
- Twenty-three options had no description in the code, so they were blank in `--help` as well as in the new pages. They now say what
  they do (`--spike-mb`, `--window`, `--interval`, `--out`, `--decisions`, `--min-conf`, `--selftest`, `--threads`, `--cgroup-mount`,
  `--report-salt`, `cora-floor --table`, and `dyn-replay`'s tuning and output options).
- `CORA_NFT_NATIVE` (read by `cora-firewall` and the daemon, default 1; 0 reads the ruleset with `nft -j list` instead of netlink)
  was undocumented. The man page test found it.

### Changed
- `lintian` on the package: 14 warnings down to 5 (the nine `no-manual-page` warnings are gone; nothing new appeared).

## 0.8.1

### Fixed
- **A rare flake in the tap tests on a busy host.** The sock_diag destroy-event stream audits every TCP socket on the machine
  and carries no cgroup id, and these tests blocklist the machine's own LAN address, so any other process talking to that
  address while a test ran was counted as a slip and broke `slips == 0` and `live + slips == N`. Only slips are host-wide
  (`live_hits` needs a task's cgroup id; the tap's `syn`/`udp` counters match on the task's cgroup). The five affected
  assertions (`test_sockdiag.py` x3 tests incl. the 3-way lifetime parametrization, `test_nflog.py` x2) now read a per-port tally
  of the test's own listener (`tests/_ambient.py: watch_slips`), which noise cannot share.
  - **Proved red then green:** with `CORA_TEST_AMBIENT=1` the unchanged assertions failed 7 of 8 tests; scoped, 8 of 8 pass with
    noise on and off. The scoped tests still fail when slip accounting breaks (3 of 5 slip-dependent tests under a mutation).
  - `CORA_TEST_AMBIENT=1` (new): a non-task process connects to the blocklisted address continuously during those tests.
  - `tests/test_ambient.py` (6, no kernel): the helper, and a guard that no tap test asserts on the host-wide counter alone.
  - `test_ambient_host_traffic_is_audited_host_wide_and_never_lands_on_a_tests_own_port` (real kernel): the noise IS audited, and
    none of it is attributable to the test's port. This pins the semantics so nobody "fixes" the monitor to be per-task.

### Added
- **CI** (`.github/workflows/ci.yml`, which already existed from 0.1.2; its three job names are kept so required-status settings
  still match). `unprivileged`: the suite on Python **3.10, 3.11, 3.12, 3.13** (was 3.10 and 3.12) plus the vendored-gate check.
  `package`: vendored copy vs GitHub, `build_release.sh`, `sha256sum -c`, a second build that must be byte-identical, the wheel
  installed into a clean venv with `cora-selfcheck` run strictly (the old step ended in `|| true`, which hid a damaged install),
  `lintian --fail-on error`, artifacts uploaded. `privileged`: the original experimental root job, kept as it was (it still
  cannot block a merge). Read-only permissions, actions pinned to major versions, no sudo around Python in the unprivileged jobs.
- **`lifecycle.yml`** (manual only): the real systemd lifecycle on a disposable GitHub runner, so the one stubbed part (stop/disable
  order, restart on upgrade, removing a real floor) can be exercised without touching the live host. Not run yet.
- `tests/test_ci.py` (9): the matrix floor equals `requires-python` and includes 3.10-3.13, tests never run under sudo, permissions
  and pinning, and the destructive workflow is manual only (mutation-checked).
- docs/ci.md.

### Verified
- The `test` job's steps, as an unprivileged user, on real CPython 3.10.20, 3.11.15, 3.12.3, 3.13.14: **619 passed, 107 skipped on
  each** (the skips are the kernel tests), with no source change needed. The hardened tap tests also pass as root under noise on
  3.10 and 3.13. This lifts the "tested on 3.12 only" caveat for everything that runs unprivileged; the kernel tests are still
  only run on 3.12 on bare metal.

### Not done
- The workflows have not run on GitHub (they are linted with `actionlint` and their commands were run locally); the first push is the
  test. `lifecycle.yml` in particular depends on what the hosted runner's kernel allows.

## 0.8.0

### Added
- **The safety gate is vendored.** `engine-telemetry-bus` (module `subnetbus`: the GI_1-GI_3 gates and the registry) is
  copied verbatim, pinned to commit `ac3f126946056b3b24eea9dbc15015b5a5639706` (bus version 0.1.0), into
  `src/cora_sentinel/_vendor/subnetbus`. cora-sentinel now has **no runtime dependencies**: a wheel installs offline, and the
  code that ships is the code the tests ran against (the full suite is unchanged: 657 passed in a clean venv with no
  `subnetbus` installed).
  - `_vendor/subnetbus/VENDOR.lock`: upstream URL, full commit, sha256 of every file (license included).
  - The vendored copy always wins over any `subnetbus` on the path (tested). `cora-selfcheck` FAILS if a vendored file was
    modified, added or removed; the daemon prints `vendored subnetbus 0.1.0 @ ac3f126 verified` (or `MODIFIED`) at start.
  - `tools/vendor_bus.py check | update --commit SHA [--run-upstream-tests] | check-upstream`: the only way to change it. It
    exports the commit with `git archive` (a dirty working tree cannot leak in), refuses a branch, tag or short unknown ref,
    runs the bus's own tests first, and leaves the old copy alone if they fail. Re-vendoring reproduces the committed tree
    byte for byte.
  - `tests/test_vendor.py` (22): the copy matches the lock, the lock pins the confirmed commit, tampering is detected, a
    shadowing `subnetbus` is ignored, nothing imports the old name, and the update tool against a fixture upstream repo.
- **Build and packaging.** `pyproject.toml` asks for `setuptools>=68` with the table-form license, so Ubuntu 24.04's own
  setuptools (68.1.2) can build it (the previous `setuptools>=77` and `license = "MIT"` did not). The vendored license and lock
  ship as package data. `MANIFEST.in` makes the sdist an allow-list (the repository root also holds old patches and zips) and
  complete enough to rebuild the wheel.
- **A native `.deb`** (`packaging/build_deb.sh`, `dpkg-deb` only; `packaging/build_release.sh` builds sdist + wheel + `.deb` +
  `SHA256SUMS`; the sdist is normalized so the set is reproducible). `Architecture: all`, `Depends: python3 (>= 3.10), nftables`, `Recommends: logrotate`. Installs the code to
  `/usr/lib/python3/dist-packages`, the nine commands to `/usr/bin`, the unit to `/usr/lib/systemd/system` (with
  `ExecStart=/usr/bin/cora-sentinel`), `/etc/cora-sentinel/cora-sentinel.conf` and `/etc/logrotate.d/cora-sentinel` as
  conffiles, docs and a DEP-5 `copyright` crediting both licenses, plus `md5sums` so `dpkg -V` works. Byte-for-byte
  reproducible from a given wheel and `SOURCE_DATE_EPOCH`.
- **Lifecycle.** Install never starts or enables the service. Upgrade restarts it only if it was running and keeps a confirmed
  floor and your edited config. **Removal** stops and disables the service and **removes the kernel floor** (the package takes
  `cora-floor` away, which would strand a confirmed floor), tidies an empty `inet cora` table, and leaves per-task isolation
  rules alone, saying so. **Purge** removes config and `/var/lib/cora-sentinel` and **keeps `/var/log/cora-sentinel`**.
- `packaging/lifecycle_test.sh`: the real install, upgrade, remove and purge with assertions. It stops the service and
  removes a floor, so it refuses unless `CORA_LIFECYCLE_TEST=disposable-machine` is set and the machine shows no sign of
  running cora-sentinel.
- `tests/test_packaging_deb.py` (33): wheel and sdist contents (no runtime dependencies, vendored license and lock present,
  the sdist rebuilds the same wheel), `.deb` contents, ownership and modes, md5sums, reproducibility, and every maintainer
  script run against stubbed `systemctl`/`nft`/`cora-floor` (never a real service or floor).
- docs/packaging.md. The model for `.deb` users is a documented side-install of `llama-cpp-python` (verified: PyPI has no
  prebuilt wheel; the project's CPU index does; `pip install --target` is accepted under PEP 668; system Python imports it
  through `PYTHONPATH`; this repo's grammar parses in the real engine. Not verified: loading a model through the unit).

### Changed
- `cora-selfcheck`, `cora-demo` and the daemon look for the vendored gate, not a top-level `subnetbus`.

### Not done
- Tested on Ubuntu 24.04 / Python 3.12 only. 22.04 (3.10) and Debian 12 (3.11) are untested.
- Newer setuptools warns that the table-form license is deprecated (by 2027-02-18); switch to PEP 639 when the oldest target
  distro ships setuptools 77 or later.
- `lintian` on the final package: 0 errors, 14 warnings (4 direct `systemctl` calls in the maintainer scripts, 9 commands without
  man pages, and the Debian-archive-only `initial-upload-closes-no-bugs`). The first run found two real problems, both fixed: a
  Markdown changelog where Debian requires its own format (now `changelog.Debian.gz`, with upstream's as `changelog.gz`), and an
  absolute path to `cora-floor` in `prerm`.
- Not a Debian source package (no `debian/` tree for a PPA or the archive), and not signed.
- Reproducible on one toolchain (`packaging/build_release.sh` run twice gives identical wheel, sdist and `.deb`, and so identical
  `SHA256SUMS`); across setuptools versions the wheel's bytes can differ. The sdist is rewritten deterministically
  (`packaging/normalize_sdist.py`) because setuptools stamps build time into it.

## 0.7.0

### Added
- **Replay harness (`cora-floor dyn-replay`, `tools/dyn_replay.py`, `cora_sentinel.dynreplay`).** Feeds recorded ISOLATE
  decisions back through the real `DynPolicy` with a clock that follows the recorded timestamps, to rehearse policy
  tweaks against shadow data without waiting a week and without touching the live system. It needs BOTH logs: a decision has
  no destination or task, so it is joined with `events.jsonl` on `event_id` (rotated, `.gz`, several files, `-` for stdin;
  `--since/--until`).
- **Worlds.** *Rehearse* (default): the adjudicator is assumed enforcing (a dry-run ISOLATE counts as done) and a task's later
  events are dropped once it is isolated, because an isolated task has no egress. `--as-recorded`: no assumptions.
  `--check`: replay as recorded and verify every decision against the live `dyn` record (exit 1 on a mismatch); in these two
  modes the policy flags state the LIVE daemon's settings.
- **Report:** results, skip reasons, the three limits (write budget with peak per minute and denials, live elements, per-task
  cap), the web-port section (blocks, refreshes, targets, promotions, which must be 0), the longest-blocked targets with
  exact blocked time, `--timeline`, and for tweaks (`--min-conf --write-budget --max-live --task-cap --promote-tasks
  --flow-ttl --ip-ttl --allow --protect`) a B-vs-A diff of every changed decision. `--json` / `--outcomes`.
- **Kernel mode** (auto when root, nft and `unshare` exist; `--kernel off|on`): every write is mirrored into a private
  network namespace and a throwaway table, elements are removed at their SIMULATED expiry, and the real nft state is
  cross-checked against the ledger. Reports write count, p50/p99 and expiries removed.
- **Self-checks (exit 2):** a web port promoted to a whole address (classified by port inside the replay, not from the
  policy's own flag, so it cannot hide the bug it looks for), or the sets disagreeing with the ledger.
- Tests: `test_dynreplay.py` (26) and `test_dynreplay_kernel.py` (4); the two daemon end-to-end tests replay the real
  daemon's logs with `--check`.

### Not done
- It does not re-run the model, so a different model or prompt cannot be rehearsed; `--min-conf` filters recorded
  confidences only.
- The live allow list at the time is not recoverable (exemptions come from the recorded skip reasons plus `--allow` /
  `--protect`); releases and manual unblocks are not in the log and are not replayed; time has one-second resolution.

## 0.6.2

### Fixed
- Test fixtures (recorded here after the fact): `test_daemon_dyn.py` writes each task's result to `/tmp` because `cora-run`
  drops root when started under `sudo` and the task could not write into the root-owned pytest directory; the logrotate
  test stages a root-owned copy of the config, which logrotate insists on.

## 0.6.1

### Fixed
- `tests/test_floor_confirm.py`: the four daemon tests failed on a host with cgroup v2 at `/sys/fs/cgroup` with
  `cannot prepare cgroup root`. They launched the daemon with `ip netns exec`, which gives the command a fresh sysfs and
  hides every cgroup mount, while the test's probe (run outside the namespace) saw a perfectly good one. They now use
  `nsenter --net=`, which joins the namespace and leaves the mounts alone (as the real service sees them). Reproduced
  and verified in a hybrid layout (cgroup2 under `/sys/fs/cgroup/unified`).

### Added
- `tests/test_daemon_dyn.py`: the dynamic policy through the REAL daemon (stub model, real `cora-run` tasks, real nft). Shadow
  records `would_block` and leaves the kernel alone; in enforce, task B, which has done nothing wrong, cannot get its
  first packet to the address task A was isolated for. Mutation-checked (dropping the Adjudicator's `dyn=` or the
  kernel handle fails them).
- `deploy/cora-sentinel.logrotate` (size-based, `copytruncate`: the daemon never reopens its logs; a week of shadow data
  must not be cut at a clock tick), installed and removed by `install-service.sh`.
- docs/dyn-policy.md: shadow's prerequisites (ISOLATE needs a cgroup and nft, so shadow needs `--nft --cgroup-root`; it does
  not need `--enforce`) and a "Deploying in shadow" recipe.

## 0.6.0

### Added
- **Dynamic policy (`--dyn-policy off|shadow|enforce`, default `shadow`; `cora_sentinel.dynpolicy`).** A model ISOLATE
  can now also drop the destination in the kernel (`dyn*` sets, timeouts expire them), so the next task's first packet to
  that address does not escape. In **shadow** it computes everything, budgets and escalation included, and writes
  `dyn: {result: would_block|would_refresh|would_promote|skipped, ...}` into each decision; the kernel is untouched.
  `enforce` needs `--model`, `--enforce` and `--floor`, and stays in shadow for decisions the adjudicator only dry-ran.
- **Policy:** only a final ISOLATE the MODEL chose, at confidence >= 0.9, whose gate passed and whose action ran;
  ESCALATE never writes; never non-public addresses, allowed or protected ones (gateway, SSH peers, resolvers), or DNS/NTP
  ports. **Web ports (80/443, tcp and udp) are flow-only** (address, proto, port), 10 min, x4 per repeat offense up to
  24 h, **never promoted** to a whole-address block. **Other ports:** flow first; whole address (30 min, x4, up to 24 h)
  once two distinct tasks have hit non-web ports of it within an hour.
- **Limits:** 20 kernel writes/min (token bucket), 512 live elements, 8 distinct targets per task per hour
  (`--dyn-write-budget`, `--dyn-max-live`, `--dyn-task-cap`, `--dyn-min-conf`).
- **A persistent ledger** per mode in `--state-dir` (flock-guarded: `cora-firewall release` is another process).
  Offense memory lasts 7 days; the daemon reconciles it against the kernel at start and hourly, so an element removed by
  hand is not remembered as blocked.
- **`cora-firewall release TASK` also drops that task's dynamic entries** (a whole-address block that loses its second
  distinct task is demoted; blocks another task caused stay; a failed unblock keeps the entry and says so).
- `cora-floor dyn` (the ledger) and `cora-floor dyn-report decisions.jsonl` (what shadow would have done: the data for the
  shadow-to-enforce call). `tools/dyn_bench.py` (cost per decision, enforce in a throwaway namespace).
- `NftSets.unblock_flow`, `live_flows`, `live_ips`; `FloorSync.exempt_reason` / `track`; `Adjudicator(dyn=...)`;
  `release_task(..., dyn=...)`.
- Tests: `test_dynpolicy.py` (67) and `test_dyn_kernel.py` (7, real traffic). Re-adding a timed element refreshes its
  timeout on the kernel (checked), so a repeat offense is a plain `add`.

### Design notes
- The model is a 3B network and a task controls the address it touches and the text the model reads, so a model-only
  verdict that writes host-wide drops is an injection surface. Hence: shadow by default, the limits above, no ESCALATE,
  the target taken from the event, and web ports flow-only (nft cannot see SNI or Host, so a flow block on 443 still hits
  everything behind a shared address; the safety there is TTL, budgets and shadow, and a web address is promoted through
  the blocklist path, with a human).
- Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) are not global addresses, so the policy refuses them.

### Changed
- `tests/test_floor_gate.py`'s `Lab` takes `bind=` and `connect(..., ip=)` (backward compatible).

### Not done
- After a demotion the promoting hit has no flow entry of its own, so its destination is re-blocked on its next event.
- The ledger is rewritten on every decision; its cost grows with its size (about 1 ms empty, 7 ms at 500 entries here).
- `cora-floor unblock` / `unblock-flow` do not edit the ledger; reconcile (start, hourly) catches the difference.
- IPv6 targets are covered by unit tests, not by a kernel test.

## 0.5.1

### Added
- **Lockout pre-check.** Before installing the floor, and before every hot reload, the daemon finds the default
  gateway(s) and the live SSH peers (from `/proc`: established connections to port 22, and the client and port in
  `$SSH_CONNECTION`) and refuses if the lists would drop one of them. A refused reload keeps the previous sets.
  `--floor-allow-detected` allows them instead; `--no-floor-precheck` turns it off. Resolved-domain addresses never
  include a protected address.
- **Dead-man switch (`--floor-confirm SECONDS`, `cora-floor confirm`).** The floor is removed unless confirmed in
  time. The timer is a detached watchdog process, started and seen to report in BEFORE the floor is installed (if it
  cannot start, the floor is not installed), so a crashed or killed daemon cannot strand an unconfirmed floor. Confirm,
  rollback and the deadline decide under one lock; a failed removal is retried and the pending record kept until the
  floor is really gone. The daemon logs the outcome once and, after a rollback, stops touching the floor.
- **Asked once per allow set.** The confirmed fingerprint (table, priorities, and the allow set you configured:
  loopback, `--floor-allow`, the blocklist allow list) is kept in `--state-dir` (default `/var/lib/cora-sentinel`), so a
  restart or reboot with the same allow set does not prompt. Resolvers (DHCP) and detected peers are not part of it. A
  pending record from before a reboot is ignored (boot id).
- `cora-floor confirm | unconfirm | pending | rollback`, and `status` now shows a pending confirmation. `remove` is
  best-effort (tolerates parts that are already gone).
- **systemd packaging** (`deploy/`): `cora-sentinel.service` (`Restart=on-failure`, capped; `ExecReload` = SIGHUP;
  `ExecStopPost=cora-floor rollback`, which removes only an UNCONFIRMED floor; ordered after `nftables.service`;
  state and log directories), `cora-sentinel.conf` (the arguments, in one `CORA_ARGS` line) and `install-service.sh`
  (renders the unit, never overwrites your config, never enables or starts anything, `--uninstall [--remove-floor]`).
  See `docs/service.md`.
- Tests: `test_floorguard.py` (40), `test_service.py` (10) and `test_floor_confirm.py` (9, real kernel).

### Changed
- README: the 0.5.0 bare-metal results (492 passed, 3 skipped; the gate's measured behaviour).

### Not done
- Hot-reload is guarded by the pre-check but not by a dead-man (a reload only narrows protection if the lists change).
- `systemctl reload nftables` (a `flush ruleset`) removes the floor; restart the service afterwards. A self-heal was
  left out on purpose: it would also undo `cora-firewall purge`, the panic button.
- Non-SSH management paths and SSH on a port other than 22 (unless started from that session) are not detected.

## 0.5.0

### Added
- **Kernel-side blocklist floor (`--floor`, `cora_sentinel.nftsets`, `cora-floor`).** The first packet to a listed address
  no longer escapes: listed subnets and addresses live in nftables sets (`static4/6`, optional `dns4/6`, expiring
  `dyn4/6` and per-flow `dynflow4/6`) and are dropped in the kernel. Inbound at `prerouting`/`raw`; outbound at priority
  -5, just after the tap (-10), so the tap still logs and attributes the attempt and the daemon still escalates it.
  `--floor-out-priority -300` drops before the tap instead.
- **An allow set is checked first** (loopback, the resolvers in `/etc/resolv.conf`, `--floor-allow`, the blocklist allow
  list), so a bad list or verdict cannot lock the host out.
- **Delta sync in one transaction.** Only the difference is sent, deletes and adds together, so an address that stays
  listed is never absent while the list changes, and a daemon killed mid-sync leaves the old set or the new one. Hot reload
  (`kill -HUP`) now updates the sets (`Reloader(on_reload=...)`).
- **Kernel-expiring verdicts.** `NftSets.block_ip`, `block_flow` (one address+protocol+port, for shared addresses) and
  `unblock_ip`; no garbage-collection thread. `cora-floor block|unblock|block-flow|list|status|sync-static|ensure|remove`.
- Tests: `tests/test_nftsets.py` (30, unprivileged) and `tests/test_floor_gate.py` (7, real packets across two network
  namespaces): first-packet escape (both hooks), a flow block sparing other ports, drops continuing past the log rate,
  allow precedence, delta sync with a prober running throughout, and SIGKILL mid-sync then reconcile.

### Design notes
- Log and drop are **separate rules**. `limit rate ... log ... drop` in one rule drops only the packets under the limit
  and accepts the rest, so a scan would walk past the floor; the over-limit test pins this.
- The resolver's domain addresses are **not** loaded unless you pass `--floor-dns`: the floor is host-wide and many
  tracker names sit on shared CDN addresses. With `--floor-dns` a sync that would remove more than half of 20+ addresses
  (a resolver outage) is applied add-only.
- The floor persists if the daemon dies, on purpose. `cora-floor remove` or `cora-firewall purge` takes it out.

### Not done
- Adjudicator verdicts do not add to `dyn*` on their own. Blocking an address host-wide because one task misbehaved is a
  policy decision (shared addresses); the API and CLI exist, the automatic wiring does not.
- The audit log goes to NFLOG group 72 (`--floor-log-group`); nothing in the daemon binds it. Per-element counters
  (`cora-floor status`) are the audit trail unless you bind the group yourself.
- Allow-list domain entries are not mirrored into the kernel.

## 0.4.0

### Changed (behavior)
- **A blocklist hit is isolated at once, before it queues behind the model.** `Adjudicator.submit()` runs the same gate
  `handle()` uses and isolates the task; the model then judges the event and can only escalate. Measured from the task
  (first packet -> first `EPERM`): 5-6 ms against 1,505 ms with a 1.5 s model, on the real kernel. `--no-contain-first`
  restores the old order. The blocklist floor already guaranteed at least `ISOLATE`, so this changes when, not whether.
- **Stricter, never weaker, for two verdicts.** Where the model itself returns `SUSPEND` or `TERMINATE` for a blocklist
  hit, the floor used to add nothing, so the task ended up with no egress rule. It now also carries the egress drop.
  The end state is identical for every other verdict (pinned by a test over all six).

### Fixed
- **A full adjudicator queue left known-bad tasks uncontained.** `submit()` discarded the event when the 32-slot queue was
  full, and the model takes 2-4 s per event, so a burst of about 33 or more blocklist hits lost the rest entirely. They are
  now contained before queueing, and any dropped event is counted (`Adjudicator.dropped`), written to the decision log
  (`queue_dropped: true`) and logged as contained at the floor or "AND NOT CONTAINED".

### Added
- Decision fields `contained_first` and `contained_ms`; events carry `timing.seen_mono_s` (not shown to the model, not in
  reports).
- `tools/containment_latency.py`: black-box time to containment from a real task's point of view, floor-first ON and OFF
  alternating, with a fake model or your own (`--model`).
- IPv6 tap tests (TCP SYN, UDP once per flow). **Not run by the author**: the development kernel has no IPv6.

### Not done
- The first packet to a listed address still leaves: the tap logs it, it does not hold it. Preventing it needs the listed
  addresses in the kernel. Model-only events still wait for the model and can still be dropped when the queue is full
  (now loudly and on the record).

## 0.3.4

### Fixed
- **Every write operation is now one nft commit.** `cora-run`'s install and an ISOLATE each ran the idempotent
  `add table / set / chain` as a commit of its own even when the chain already existed, and `gc` committed once per dead
  task, under the lock an ISOLATE waits behind. Counted on the test machine: install 2 -> 1 commit, ISOLATE 2 -> 1
  (11.7 -> 3.2 ms), gc of five dead tasks 5 -> 1 (37 -> 7.3 ms). The ensure lines are included only when something is
  missing, and in the same transaction as the rule.
- **Re-isolating a task whose cgroup was recreated is atomic.** The old rule used to be deleted in one commit and the new
  one added in another, so for one commit-time the task was unblocked. Delete and add are now one transaction.

### Added
- `tools/nft_latency_experiments.py writes`: the commits and time per operation (install, sync, ISOLATE, gc) as live
  tasks accumulate, with `--check` requiring one commit each. The ISOLATE time is about one commit on that machine.
- `Firewall._ensure_lines()`, `TapRules._ensure_lines()` / `_ready()` / `_apply()`.

### Not done (deliberately)
- Writes stay on the nft command. Building rule expressions as netlink bytes would save only process start-up (about 1
  ms of a 14 ms transaction on the 28-core machine) at the cost of reimplementing nft's expression encoding. See
  `docs/tap-latency.md`.

## 0.3.3

### Fixed
- **Reading the tap rules was the dominant cost of every tap operation, and it grew quadratically with live tasks.**
  `nft list` prints a `socket cgroupv2` match by resolving the cgroup id to a path; the cost is (rules) x (cgroups it
  walks past before reaching each target), about 0.03 ms each. With the tap's 5 rules per task that is 1.8-2.0 s for a
  single listing at 160 live tasks (13 ms at 10), and it depends on where the machine's other cgroups sit in the
  kernel's listing order. The listing ran inside the tap lock (which every `cora-run` and the sync worker queue on), in
  `Firewall.gc` (which an ISOLATE waits behind), and in `active()` / `udp_enabled()` (run before every task launch).
  The rules are now read over netlink (`cora_sentinel.nftdump`), which is O(rules): 20 ms at 160 tasks, 100x faster,
  identical results on the real kernel in every state tested (empty, live counters, a duplicate rule, the egress chain).
  It falls back to the nft command, once and loudly, if netlink is unavailable; it is off with an injected runner, with
  no nft binary, and with `CORA_NFT_NATIVE=0`. Writes still go through nft.
- **"Not slow" was a fixed 100 ms.** An idle 28-core sync takes 100-111 ms, so `tools/nft_latency_experiments.py
  --check` failed there. It now means under 100 ms or within 2x of the fastest sync this machine has shown.

### Added
- `tools/nft_latency_experiments.py dump`: builds live tasks in steps and shows the nft command against netlink side by
  side with a "same rules?" column, so the cost can be checked on your own machine.
- `Firewall.chain_rules()`, `.chain_exists()`, `.set_exists()`, `.native`.

### Corrected
- `docs/tap-latency.md` now carries the cost model and what is and is not shown. An intermediate analysis blamed "UDP
  rules"; that came from two tables sitting on opposite sides of a large cgroup directory in the listing order, and is
  withdrawn. That the listing was the cause of the 1.5-13 s stalls seen under load is the best candidate, not yet shown
  on that machine: check `lock_wait_max` / `nft_max` in the monitor summary from a heavy parallel run.

## 0.3.2

### Added
- **The tap lock is bounded.** It was a plain blocking `flock`, so a holder that hung (stopped, or stuck in
  uninterruptible I/O) would hang its caller forever. It is now taken with a deadline: 30 s for the sentinel's sync
  worker (it logs the failure, keeps the event loop running and retries), 5 s for `cora-run` (it starts the task anyway
  and says its first connection may go unobserved). `CORA_TAP_LOCK_TIMEOUT` overrides both. The lock file records
  `pid name` of its holder, so a timeout says who is stuck and whether it is stopped or in uninterruptible I/O.
- Each sync also records **CPU pressure** (kernel PSI) and **which nft call was the slowest** (`-j list chain` is a
  dump, `-f -` a commit); both appear in the log line, the summary and the experiment tool.
- `TapLockTimeout`, `lock_timeout_from_env()`, `Firewall.timing.slowest_cmd`.

### Fixed
- **The nft verdict said "not general host load" whenever the no-op child was fast.** A 28-core run showed that a busy
  host can slow nft's commit without slowing a fork (80 spinners: nft x5 slower, fork 2 ms). With high CPU pressure it
  now says the CPUs were oversubscribed and that this is not evidence of commit contention.
- `tools/nft_latency_experiments.py --check` flagged that healthy 28-core result as a failure; the busy scenario now
  accepts "the whole host is slow" (few cores) or "the CPUs were oversubscribed" (many cores).

### Changed
- `docs/tap-latency.md` states what the 28-core data does and does not show, and gives a falsifiable test (RCU
  expedited) for the one effect it cannot explain: an idle slowest call of 79 ms.

## 0.3.1

### Added
- **Where a slow tap sync spends its time.** Each sync is split into lock wait (the cross-process tap lock), nft
  (wall time in nft subprocesses, with call count and slowest call) and other, plus a no-op child process as a control
  for "is starting any process slow right now". A sync over 500 ms is logged at once with the breakdown and what it
  suggests (the lock; nft or the kernel's transaction path; or the whole host). The monitor summary gains
  `lock_wait_max`, `nft_max`, `slowest_nft_call`, `noop_child_max` and `worst_tap_sync`. See `docs/tap-latency.md`.
- `tools/nft_latency_experiments.py`: produces each cause on purpose (lock hog, busy host, nftables commit contention)
  and shows whether the verdict names it correctly on your machine.
- `Firewall.timing` (a per-thread tally of nft time), `TapRules.last_timing`, `netmon.diagnose()`.

### Changed
- Every tap sync forks one extra no-op child (`true`, about 1 ms) on the sync worker, as the control.
- The nft verdict compares extra milliseconds against the fastest seen, not ratios or absolute times; two earlier
  versions of the rule were wrong in experiments (an idle sync called "a busy host"; a CPU-starved host blamed on nft).

### Not changed (known)
- The tap lock still has no timeout, so a hung holder would hang the sync worker.

## 0.3.0

### Added
- **`SIGHUP` hot reload of the blocklists.** The daemon re-reads `--blocklist`, `--blocklist-store` and
  `--blocklist-allow` without restarting; only the lists change (same nft rule handles, same sockets, cgroup tracking,
  firewall rules and model). A failed load keeps the previous lists; an empty result is refused rather than silently
  disabling detection; resolved addresses are carried over before the swap so there is no detection gap; new domains
  are resolved at once and removed ones stop matching immediately. See `docs/blocklist-updates.md`.
- `cora_sentinel.reload` (`Reloader`, `load_lists`), `Sentinel.set_blocklist()`, `DomainResolver.rebind()` / `.kick()`.

### Changed
- **`SIGHUP` no longer terminates the daemon**: it reloads, or is logged and ignored when no lists are configured.
- `ConnDetector.judge()` reads the list reference once per decision (it read it up to three times).
- `DomainResolver` resolves never-resolved names first, and marks a name whose lookup failed as tried so it cannot
  starve the rotation. Its cache no longer keeps domains that were removed from the list.
- Startup and reload build the lists through the same function, so they cannot disagree about what "the lists" are.
- `cora-blocklist accept` now says how to apply the update (`kill -HUP`).

## 0.2.0

### Added
- **Pinned, reviewed blocklist updates** (`cora-blocklist pull | diff | accept | status | verify`, and
  `cora-sentinel --blocklist-store DIR`). An upstream change is only ever *staged*: it reaches the active list when you
  approve that exact content by its sha256. Fetching is https-only with TLS verified, redirects may not leave https,
  and size and time are bounded (a trickling or endless server is cut off). `diff` flags a list that is emptied or
  gutted, that starts blocking your LAN, that is mostly rejected junk, or whose URL moved. The daemon refuses to start
  on a store whose active files do not match their pins. See `docs/blocklist-updates.md`.
- `cora-selfcheck` measures `nft` process-start and transaction latency, to show where time goes.
- `Blocklist.entries()`.

### Note
- The `cora-security` repo does not currently contain the starter blocklists (its history has four files).
  `docs/blocklist-updates.md` has the commands to publish them.

## 0.1.3

### Fixed
- **The event loop could stall for seconds** (bare metal: polls of 1,501 ms and 13,160 ms). It ran `nft` inline, behind
  a cross-process lock that `cora-run` also holds, and took the registry lock the adjudicator holds across an ISOLATE;
  events queued while short-lived tasks exited. Tap-rule sync and event delivery now run on worker threads, and the
  loop only does lock-free work. Measured with every `nft` call at 0.8 s: worst poll **4 ms** (2,418 ms before).
- `Firewall` now serializes its own read-then-write steps (it relied on the caller holding the registry lock across
  `nft`); the daemon no longer holds the registry lock across `Firewall.gc`; `ensure(pid)` takes no lock for a pid
  it already knows.
- A full delivery queue drops events **loudly** (counted in `dispatch_dropped` and noted on stderr), never silently.

### Added
- `tap_sync_ms_max` and `dispatch_dropped` in the monitor summary; `NetMonitor.flush()`.

### Note
- This closes the "Not resolved" item of 0.1.2: the cause was the stall, which the 0.1.2 instrumentation exposed.

## 0.1.2

### Fixed
- **Owner resolution used only the first pid in a task's cgroup.** One unreadable process (mid-`exec`, a zombie,
  a helper) dropped the event even when other live members existed. Any live member is now used.
- **A violation by a task that had exited vanished** from the verdict and report pipeline even though the tap had
  attributed it to a known task. It is now reported from the task's last known identity (`owner_exited: true` in
  the evidence); the gate's start-time and cgroup checks still refuse to act on the dead pid.

### Added
- Diagnostics: when an owner cannot be resolved the monitor records why (cgroup empty, process state, cmdline
  readability) in `owner_diag` and prints the first few; `poll_ms_max` and a one-time warning when a poll stalls.

### Not resolved
- On a bare-metal run, `test_every_zero_lifetime_udp_beacon_is_attributed_to_the_right_task` once lost all 40 events
  of the first-launched task to `owner_gone`, although the tap had counted them. **Not reproduced** here with a slow
  `nft` (0.4 s and 1.2 s per call) or with privilege-dropped tasks. The two changes above remove plausible causes;
  the diagnostics will name the real one if it recurs.

## 0.1.1

### Fixed
- **UDP flow dedupe could swallow another task's flow.** The once-per-flow nft set was keyed on
  `(daddr, dport, sport)` and shared by all tasks; the kernel picks UDP source ports at random, so two tasks'
  flows to one destination collide by birthday odds. Measured over 1,800 flows: about 2% of later tasks' flows
  were never attributed. The task's cgroup is now part of the key. Found on bare metal, where
  `test_every_zero_lifetime_udp_beacon_is_attributed_to_the_right_task` came up one short.
- An nftables that cannot key a set on the cgroup now fails with a message naming `--no-tap-udp`.

### Changed
- The UDP flow sets are now `cora_flow4` / `cora_flow6` (0.1.0's `cora_udp4` / `cora_udp6` are removed on teardown).
- UDP tests no longer depend on random source ports: beacons pin distinct ports, and a new oracle test checks
  exactness under any port allocator.

## 0.1.0

First packaged release.

### Added
- Per-task containment on cgroup v2 (`cora-cgroup`, `cora-run`): freeze, kill, throttle, and an nftables egress
  quarantine (`cora-firewall`, the `ISOLATE` verdict).
- **Flow tap** over NFLOG: connect-time attribution of TCP SYNs and the first packet of every UDP flow, with
  QUIC labelling and DNS query-name extraction. Pure Python, no eBPF.
- sock_diag monitoring: kernel-attributed dumps and a destroy-event audit.
- Blocklists (domains and subnets, with safety rails and an allow list) and anonymized violation reports
  validated against `cora.security.violation/v1`.
- A grammar-constrained local-model supervisor with a blocklist floor and deterministic gates.
- `cora-demo` and `cora-selfcheck`.

### Fixed during verification
- Stale egress rule after a task's cgroup was recreated under the same name.
- Duplicate tap rules from a `cora-run` / monitor race (4 of 30 tasks before, 0 of 60 after).
- `release` could leave a task frozen if issued mid-freeze.
- SYN retransmits and duplicate messages counted as new connections.
- A usage error surfaced as a traceback when the working directory was unwritable.
