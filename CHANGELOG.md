# Changelog

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
