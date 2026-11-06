# Changelog

## 0.8.9

### Fixed
- **The privileged CI job failed `test_listing_cost_no_longer_grows_with_the_number_of_live_tasks` with `FirewallError: nft timed out`.** The test compares nft's own listing of the tap chain, which is quadratic in the number of tasks, with the netlink read. `firewall.py` gives every nft call 10 s; at 140 tasks (700 rules) the legacy listing took about 11 s on a throttled 2-vCPU GitHub runner. It had passed in earlier runs, so it was simply close to the ceiling. Only the test was wrong; no product code changed.
  - **The scale is now 60 tasks (300 rules).** Measured on a 1-core sandbox: nft **275 ms at 60 tasks and 1,529 ms at 140**, a ratio of 5.6 against a predicted (140/60)² = 5.4, so the quadratic model holds and about 2 s is expected on the runner, five times under the ceiling. The contrast with netlink is still large (9 ms vs 275 ms there).
  - **The commit that lowered the loop (`b683ba2`) had left the test unable to pass**: the assertion still said `len(via_netlink) == 140` and the label `140 live tasks (700 rules)`, so it failed deterministically with `60 == 140`. The scale now comes from one constant, `TAP_TASKS`, used by the loop, the assertion, the comment and the label.
  - `CORA_TEST_TAP_TASKS=140` runs the original scale, for a machine that can take it (documented in `docs/ci.md`).
  - `test_the_listing_benchmark_takes_its_scale_from_one_constant_and_keeps_nft_well_under_its_ceiling` fails if the old literals come back, and if the default scale leaves 30 to 100 tasks.
  - Checked that the shrunk test still bites: with the netlink path disabled (both reads going through the nft command) it fails (`259 < 80`), and putting `== 140` back fails two tests. (A first attempt at the first break did not take effect and its "pass" was not counted; the redone one is the result above.)

## 0.8.8

### Fixed
- **One privileged-CI test failed**: `test_a_connection_from_a_nested_worker_becomes_an_event_instead_of_being_dropped[as an unprivileged user]`, with `ValueError: invalid literal for int() with base 10: ''`. 0.8.7 forced the worker to uid 65534 and assumed `nobody` could execute `sys.executable`. In CI that is the venv under `/home/runner/work/...`, which `nobody` cannot enter, so `cora-run`'s `os.execvp` failed with `EACCES`, the worker never started, and the test parsed an empty line. Only the test was wrong; no product code changed.
  - **Reproduced** by recreating CI's layout: a venv inside a directory only its owner can enter (mode 0700), with the tests run from that venv's python. (A first by-hand check misled me: `setpriv` resolved the path itself before dropping privileges. Replicating `cora-run`'s own sequence, `setgroups`, `setgid`, `setuid`, `execvp`, gave the CI error.)
  - **The worker's interpreter is now chosen by trying it.** `python_that_runs_as(uid, gid)` runs each candidate (this interpreter, its real path, `/usr/bin/python3`, `python3` on `PATH`, the base interpreter) as that user, dropping privileges as `cora-run` does and then executing, and takes the first that really runs. If none does, the variant skips and says why. Preferring `SUDO_USER` was not used: under CI's `sudo` that is the user the first variant already runs as, so the second variant would test nothing new, and as plain root without `sudo` it would be root.
  - The shared `task()` helper takes `python=` (the interpreter the *task* runs; `cora-run` itself still starts with this one, as root) and `cwd=`.
  - **A worker that fails to start is reported as such**, with its exit status (`the worker died before it started (exit status N)`), and a worker that has already exited is not "moved". Before, the other variant of the same test could pass by luck in that situation, because the pid was momentarily in the task cgroup.
  - Checked: the reachability trial, the exit-status report and the exited-worker guard each fail a test when disabled (a first attempt at that break did not take effect and survived; the redone one is caught by three tests); 12 consecutive runs, six in the CI layout and six with sudo's variables set, were clean.
- `tests/test_cgroup_nested.py` is 42 tests (+3: the probe, the empty-line report, the exited-worker guard).

## 0.8.7

### Fixed
- **Two real-kernel tests failed in the privileged CI job** (`tests/test_cgroup_nested.py`: `PermissionError: [Errno 13] Permission denied: '.../nest/sub'`). The CI job runs `sudo ./venv/bin/python -m pytest`, which sets `SUDO_UID`, and `cora-run` then drops the worker it starts to that user. The worker tried to create its own sub-cgroup inside a root-owned task cgroup and was refused. My sandbox runs as plain root with no `SUDO_UID`, so its workers stayed root and the failure never appeared there. Only the tests were wrong; no product code changed.
  - **A `chmod 0777` on the task directory is not enough** (tried): the `mkdir` then succeeds, but the move into the sub-cgroup fails with `EACCES`, because moving a process needs write access to the task's own `cgroup.procs` (the common ancestor), which stays root-owned. It would also have turned the event test into a false pass: the old worker swallowed the failed move and connected from the top-level task cgroup, which the pre-0.8.6 code handles too.
  - **The worker now creates nothing and moves nothing.** It waits until the test (root) has moved it into `nest/sub/worker`, as a launcher or a container runtime would, and only then connects. So it needs no permission, and it cannot connect before it is nested (the 0.8.6 test could pass without ever exercising the nested path).
  - **Both tests now run twice**: as the test runs, and as an unprivileged user (`SUDO_UID=65534`, exactly what makes `cora-run` drop privileges). The CI condition is therefore covered wherever the tests run as root, not only in CI.
  - `test_the_worker_needs_no_permission_because_the_test_does_the_moving` fails if the worker is ever given the power to create or move cgroups itself.
  - Checked: with the original bug put back (`pids()` ignoring sub-cgroups, or `cgroup_of` matching exactly) the tests fail in both modes; 12 consecutive runs, six as root and six with sudo's variables set, were clean.

### Observed, not changed
- An unprivileged process inside a task cgroup cannot create sub-cgroups, or move into them, unless the task cgroup is delegated to it (the directory and its `cgroup.procs` chowned to it). `cora-run` does not delegate. So the nested-cgroup case that 0.8.6 fixes arises where sub-cgroups are made by root or by a manager that delegates (systemd, a container runtime), not by an unprivileged task on its own. Whether `cora-run` should delegate its task cgroup to the user it drops to is a design question, not decided here.

## 0.8.6

### Fixed
- **A task whose workers live in sub-cgroups lost its events.** A browser or a flatpak puts its workers in `<root>/<task>/sub/worker`, and
  cgroup v2's `cgroup.procs` lists only the processes *directly* in a cgroup. So the tap flagged the connection, the owner lookup found
  nobody (`owner of task 'x' unresolvable: cgroup.procs empty`) and dropped the event, and `tick()` never monitored the workers.
  Reproduced on the real kernel before the fix (`syn_hits=3 owner_gone=3 events=0`, `discover()` empty) and green after (`owner_gone=0 events=3`).
  - `CgroupRoot.cgroup_of(pid)` takes the first path component below the root by string parsing alone (no directory walk): a pid in
    `task-a/sub/worker` is the task `task-a`. Anything outside the root, the root itself, a sibling sharing the prefix, an invalid first
    component and a removed task directory are still `None`.
  - `CgroupRoot.pids(task, nested=True)` and so `discover()` look below the task directory with a **bounded** walk (`MAX_NEST_DEPTH` 8,
    `MAX_SUBCGROUPS` 1024, `os.scandir`, never following a symlink out of the root, own processes first). This is the part that makes events
    appear; the spec's `cgroup_of` change alone would not have, because events never come from a pid nothing enumerates.
  - Freeze, kill and the per-task nft rule already cover descendants (cgroup v2 semantics; the nft match is not verified end to end here).
- **A task with more than 245 processes ended the daemon.** The VIP pool is a /24; the 246th `ensure()` raised `RegistryError:
  SUBNET_EXHAUSTED` out of `tick()`, and the main loop had no guard. Nested discovery makes this far easier to hit, so `tick()` now skips a
  pid it cannot give a VIP (logged, rate-limited, `vip_skipped`) and the main loop calls `Sentinel.guarded_tick()`, which logs and counts a
  failed tick and carries on (`tick_errors`).

### Added
- **In-flight coalescing** (`Adjudicator`). While an evaluation for `(task, kind)` is queued or running, a further event of that kind is
  folded into it: counted, noted in its decision as `coalesced: {count, destinations[, follow_up]}`, and not queued. Invariants, each pinned by
  a test and by a deliberate break: it **takes no pin and registers nothing** (nothing of a coalesced event can leak); **never across kinds**
  (a `path_violation` is not covered by a pending connection verdict); **never a blocklist hit** (always pinned, isolated at `submit()`, judged on
  its own); **never for ever** (`IN_FLIGHT_MAX_AGE_S`, 5 minutes, so a lost evaluation cannot silence a task); a full queue and an exception both
  clear the record; and **never a hidden tail**: if the verdict did not contain the task (`ALLOW`, `THROTTLE`, `ESCALATE`, or an `ISOLATE` that
  could not be carried out) and the burst's latest event differs from the one judged, it is judged once afterwards. A burst costs two
  evaluations at most. Counters: `coalesced`, `follow_ups`, `stale_in_flight`; the `[verdict]` line reads `+N coalesced`.
  - **A premise correction:** `_fire`'s 30 s cooldown already collapses twenty connections to *one destination* into one event (a test pins
    that). What stalls the model is a burst to many *different* hosts, or the same host again after the cooldown while the queue is stalled.
    Coalescing is keyed on `(task, kind)`, not on the destination, to cover the first case; the cost is that under `--dyn-policy` only the judged
    event's destination is considered for a dynamic kernel drop (the whole cgroup is isolated by the verdict regardless).
- **`violation.proto` and `violation.via`**, optional fields of `cora.security.violation/v1` (`schema/violation.schema.json` is regenerated from
  `report.py`; the validator and the JSON Schema agree). `proto`: `tcp`, `udp`, `quic`, `dns`, `unknown`. `via`: `syn_tap`, `udp_tap`,
  `dns_tap`, `sock_diag`, `proc_tcp`, `unknown`; `dns_tap` is reserved (DNS goes through the UDP tap, so it reads `proto: dns`, `via: udp_tap`),
  and a test fails if the code emits a `via` the enum lacks or the enum holds one nothing emits.
  - Every connection detector now records both, in a new top-level event field `detection` (not in `anomaly`, so **the model's prompt is
    unchanged**): the SYN and UDP taps (`syn_tap`, `udp_tap`), the live scan (`sock_diag`) and the `/proc/net/tcp` path (`proc_tcp`).
  - A schema v1 consumer built from a copy older than 0.8.6 rejects a report that carries them (the schema forbids other extra keys). No consumer
    pins v1 yet; once one does, a further addition needs a new id. Documented in `docs/violation-reports.md`.
- Tests: `tests/test_cgroup_nested.py` (36: the `cgroup_of` table, the bounded walk, the VIP pool, three real-kernel tests including the
  reproduction), `tests/test_inflight.py` (49, +16: coalescing), `tests/test_report.py` (54, +32: proto/via and the plumbing at all three event
  sources). Every invariant above was mutation-checked (24 deliberate breaks, each fails a test; one test was added because a break survived).

### Changed
- `README.md`: `Status: beta (0.8.6)` and the measured test counts. The root copies `violation.schema.json` and `violation.example.json` are synced, and
  `test_a_root_copy_of_the_schema_or_example_is_never_stale` keeps them so (it skips once they are deleted).
- `CgroupRoot.pids()` now includes sub-cgroup processes by default (`nested=False` for the old behaviour); `build_payload(..., detection=)`.

### Housekeeping
- `superseded-flat/` (21 old flat-layout `.py` files, not release patches) should be untracked: `git rm -r --cached superseded-flat/`. `.gitignore`
  already lists it; ignore rules never untrack a file git already tracks, which is why it was still committed. Nothing in the tests or the
  package needs it (checked on a clone without it).

## 0.8.5

### Fixed
- **A process that exits while its event waits behind the model no longer defeats the gate.** The next `tick()` released its VIP, so the
  gate refused a perfectly good verdict ("blocked"). `VirtualNet.pin()` / `unpin()` keep the VIP registered while an event is in flight:
  `Adjudicator.submit()` pins, `handle()` unpins in a `finally` after the decision is written (only what `submit()` pinned, so a direct
  `handle()` call never steals a pin), and `release()` defers while pinned. A queue-full drop unpins at once. Two additions the design
  needed: a **pin lease** (`PIN_MAX_AGE_S`, 5 minutes) so a lost unpin cannot leak a VIP for good, and a **pid-reuse guard** (a live
  process that reuses a deferred pid takes the VIP over, so the old event's late unpin cannot free a VIP now in use).
  - This is not a leak fix: a stray VIP was always reclaimed by the next `tick()`. The real hazard was the opposite, premature release.
- **`ISOLATE` goes ahead when the triggering process has exited, if its cgroup is provably the same one.** The event now records
  `subject.cgroup_id` (the cgroup directory's inode: a cgroup removed and recreated under the same name gets a new one; the model's
  prompt never includes it) from both the `tick()` path and the connect-time tap. The gate (`Adjudicator._gate(subj, action)`) relaxes
  only when the process is **gone** (not merely different), the action is in `GONE_OK = ("ISOLATE",)`, and the identity matches; the
  decision records `OK_PROCESS_GONE`. `TERMINATE` (`cgroup.kill`, irreversible, would hit a later task that reused the name),
  `SUSPEND` and `THROTTLE` stay strict. Everything else is unchanged and fails closed: a live pid with a different start time is
  `PID_REUSED`, a pid that left the cgroup is `CGROUP_MISMATCH`, and an event with no recorded identity / a removed cgroup / a replaced
  cgroup is refused (`CGROUP_UNPINNED` / `CGROUP_GONE` / `CGROUP_REPLACED`). A decision whose task the policy floor had already isolated at
  `submit()` reads `already-contained` instead of `blocked`.
- **A fresh install no longer fails closed with `[Errno 2]` when you add the suggested `--blocklist` / `--blocklist-allow` flags.** The
  two directories (`/etc/cora-sentinel/blocklists`, `/etc/cora-sentinel/allow`) now exist after install, each with an inert comment-only
  `00-local.txt` (`deploy/seed/`, one source of truth). The `.deb` ships them as **conffiles** (an upgrade keeps your edits, deleting one
  is respected, purge removes them and tidies the directories; a list file you added yourself is never removed) and `postinst` also runs
  `mkdir -p` on the two paths. `deploy/install-service.sh` creates them and seeds a directory only if it holds no file.
  - `postinst` is `/bin/sh` (dash), which has **no brace expansion**: `mkdir -p /etc/cora-sentinel/{blocklists,allow}` there creates
    one directory literally named `{blocklists,allow}`. The two paths are written out, and a test guards it.

### Added
- `tests/test_inflight.py` (33): the pin/unpin bookkeeping (refcount, deferral, idempotent release, unbalanced unpin, the lease, the
  pid-reuse guard, 700 interleaved pids never filling the /24), the adjudicator (pin on submit, unpin after the decision, full queue,
  exception, direct `handle()`, the worker thread), every gate branch above, early containment, the recorded identity (including the
  model never seeing it, and a real-kernel test that a recreated cgroup gets a different identity and that the tap path records it).
  Mutation-checked: nine deliberate breaks each fail it.
- Installer, deb and lifecycle tests for the list directories; `packaging/lifecycle_test.sh` checks them with real `dpkg` (they load, an
  edit survives an upgrade, `postinst` restores a removed directory, purge removes them).
- `tests/test_repo_root.py`: only expected files and directories at the repository root, and no patches, zips, notes or built packages
  tracked outside the old layouts.

### Changed
- `CgroupRoot.cgroup_id(name)`; `build_payload(..., cgroup_id=)`; `Sentinel.cgroup_id_of(name)`.
- Two existing deb tests now expect four conffiles (the config, the two templates, logrotate).

### Housekeeping
- Removed from the repository root: `0.8.4-INSTALL.txt`, `0.8.4.patch` and `cora-sentinel-0.8.4.patch` (delivery files that ended up
  committed because the 0.8.x zips carried them at their root: they no longer do), and `MANIFEST.sha256`, which listed the 29 files of the
  old flat layout (none of them at the root any more) and was read by nothing except the legacy self-checks in their own directories.
- `MANIFEST.in`'s comment updated; `.gitignore` now also ignores a `models` symlink (`models/` does not match one).

## 0.8.4

### Added
- **The daemon echoes its arguments at start**: `[cora-sentinel] VERSION starting with: ARGS` (via `shlex.join`, so a value split at a
  space or carrying a stray quote is visible), before anything else; not for `--selftest`. A mangled config is now visible in the
  first line of the journal.
- **It refuses arguments that look like unexpanded shell syntax**: `$VAR`, `${VAR}`, `$(cmd)`, `$1`, a backtick, or a quote mark
  stuck to a value, with exit status **2**, naming the argument, before opening any file. systemd's `EnvironmentFile` does no shell
  expansion or quoting, so these used to reach the daemon as literal text and it ran with arguments nobody meant. `~` is not refused
  (the daemon expands it). `--allow-shell-chars` is the escape hatch for a literal `$`.
- **`RestartPreventExitStatus=2` in the unit**: a usage error (this, or an unknown option) is not restarted, so it fails once and loudly
  instead of looping into `start-limit-hit`.
- `tests/test_args.py` (37): every shape flagged, ordinary arguments (including `~`, CIDRs, `#`, `%`, a bare `$`) not, the refusal
  before any file exists, the echo first and quoted, the escape hatch, `--selftest`/`--help` untouched, a real process exits 2, and the
  shipped config can never trip its own check.
- docs/service.md: "If the service runs with the wrong arguments".

### Why
A live service ran for a day with a config that mixed shell syntax into `CORA_ARGS`; nothing said so, and the questions "where are the
events going" and "is the model on" could only be answered by reading `/proc/PID/cmdline` by hand.

## 0.8.3

### Fixed
- **Two live sentinel tests could fail on a slow machine** (`test_net.py::test_live_outbound_flagged`, `test_blocklist.py::
  test_live_listed_address_trips_even_when_allowlisted`): each started a child Python and polled for 5 seconds from that moment, so
  the window also had to cover the child's interpreter start-up and connect. One failed once on a busy workstation and one once on a
  hosted runner (Python 3.11), and both passed when run alone. The child now says `ready` once it has connected; the test waits for
  that and only then starts polling, and it waits for the specific event kind, not any event (`tests/_live.py`).
  - **Proved red then green:** with the child connecting 7 seconds late the unchanged tests failed (empty event list, the reported
    shape); with the fix they pass. They still fail, after a full 10 s, when the detector flags nothing (runtime mutation).
  - `CORA_TEST_SLOW_START=<seconds>` (new) makes the child connect late on purpose. `tests/test_live.py` (7) covers the helper,
    and a guard fails if either test goes back to a fixed 5 s window.
  - The failure on the hosted runner was diagnosed from the test's shape and reproduced by delaying the child; the runner's log was
    not available, so the cause there is likely, not proven.
- **`--net-allow` replaces its default, and the help did not say so.** `--net-allow` is `append` with no default, and the policy is
  `net_allow if not None else DEFAULT`, so adding your LAN silently drops loopback and 10/8 unless you list them too. The help (and so
  the man page) now says it.

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
