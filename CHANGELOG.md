# Changelog

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
