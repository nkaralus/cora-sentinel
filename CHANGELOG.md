# Changelog

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
