# cora-sentinel

An **out-of-band security sentinel for Linux tasks.** It watches what a task talks to, and contains it
when it talks to something it shouldn't: tracker domains, rogue subnets, anything outside an allowlist.

Deterministic code does the detecting and the enforcing. A small local model (grammar-constrained, so it
can only emit a valid verdict) proposes *what to do*, and deterministic gates decide whether it *may*.
The model is never in the hot path and never chooses the target.

```
 task (a cgroup)                        flow tap (nftables -> NFLOG)  TCP SYN, UDP/QUIC first packet, DNS name
   │  connect() / sendto()  ───────────  sock_diag dump + destroy events (TCP)         ┐
   │                                                                                    ▼
   │                                      judge: blocklist / allowlist ──► anomaly event (names the TASK)
   │                                                                                    │
   │                                      local model (GBNF) ──► verdict ──► policy floor ──► gates ──► action
   ▼                                                                                                    │
 ISOLATE: nft drops its egress  ◄────────────────────────────────────────────────────────────────────────┘
          (SUSPEND = cgroup.freeze, TERMINATE = cgroup.kill, THROTTLE = cpu/memory)    + anonymized report
```

**Status: alpha (0.1.0).** Verified by the test suite on Linux 6.18 (a VM), and by the author on bare-metal
Ubuntu for the TCP tap and the demo. UDP/QUIC/DNS support has so far only been verified in the VM.

## Requirements

- Linux with **cgroup v2**, **nftables** (UDP tapping needs `typeof` sets keyed on `socket cgroupv2`: verified
  on nft 1.0.9 / Linux 6.18; `--no-tap-udp` taps TCP only), `NETLINK_SOCK_DIAG`, and the `nfnetlink_log` module.
- **Root.** Cgroups, nftables and NFLOG all require it. (`cora-selfcheck` says which pieces you have.)
- Python 3.10+. Run and tested on 3.12 only so far. **No other Python packages are needed**: the safety gate
  (`engine-telemetry-bus`) is vendored, pinned to one commit and checked by `cora-selfcheck` (see
  [docs/packaging.md](docs/packaging.md)).
- Optional: a GGUF model such as Qwen 2.5 3B, through the `[model]` extra.

## Install

```bash
python3 -m venv venv && . venv/bin/activate
pip install "git+https://github.com/nkaralus/cora-sentinel"
# the local model (a prebuilt CPU wheel avoids compiling llama.cpp):
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
cora-selfcheck                          # what this machine can and cannot do, and what each gap costs
```

For development: `pip install -e ".[dev]"`.

**A package for Ubuntu/Debian.** `packaging/build_release.sh` builds an sdist, a wheel and a native `.deb`
(`Architecture: all`, depends on `python3` and `nftables` only). Installing it does not start the service; removing it stops
the service and removes the kernel floor; purging keeps the audit logs. See [docs/packaging.md](docs/packaging.md)
(including how to side-install `llama-cpp-python` for the model under Ubuntu's PEP 668 restriction).

## Try it

```bash
sudo ./venv/bin/cora-demo --model models/qwen2.5-3b-instruct-q4_k_m.gguf
```

The demo creates its own cgroup, nft table and temp directory, never touches a production `inet cora`
table, and cleans up even on Ctrl-C. It prints a timeline: detection, model verdict, decision, the task's
own proof that its network is blocked, and an anonymized report.

| Flag | What the task does |
|---|---|
| *(none)* | holds a TCP connection to a stand-in "tracker" on your LAN address (nothing leaves your machine) |
| `--ephemeral` | zero-lifetime TCP beacons: connect, then close at once |
| `--udp` | QUIC-looking UDP datagrams to port 443 |
| `--domain NAME` | a real connection to a real listed domain |
| `--no-nflog` | the same, with the flow tap off: shows what slips through without it |
| `--dry-run` | detect and judge, enforce nothing |

## Run it for real

```bash
sudo ./venv/bin/cora-sentinel \
    --cgroup-root /sys/fs/cgroup/cora --nft --nflog \
    --blocklist ./blocklists --blocklist-allow ./allow \
    --model models/qwen2.5-3b-instruct-q4_k_m.gguf          # add --enforce when you trust it

sudo ./venv/bin/cora-run my-task python3 job.py             # start a task inside its cgroup
```

Without `--enforce` nothing is acted on: events and decisions are written, not executed. `cora-run` drops
back to your uid under `sudo` and installs the task's tap rules *before* `exec`, so even its first packet
is already attributed. Run `cora-sentinel --help` for every flag.

Review and undo:

```bash
sudo ./venv/bin/cora-firewall list              # who is isolated, packets and bytes dropped
sudo ./venv/bin/cora-firewall release my-task   # thaw + unblock + reset limits, in one action
sudo ./venv/bin/cora-cgroup list                # tasks, pids, frozen / freeze_requested
sudo ./venv/bin/cora-firewall purge             # panic button: delete the whole nft table
```

### The kernel floor (`--floor`)

Without it the first packet to a listed address still leaves: the tap logs it, it does not hold it. With
`--floor` the blocklist's subnets and addresses are loaded into nftables sets and dropped in the kernel, inbound
(prerouting, `raw`) and outbound (just after the tap, so the tap still sees and attributes the attempt):

```bash
sudo ./venv/bin/cora-sentinel --cgroup-root /sys/fs/cgroup/cora --nft --nflog --floor \
    --floor-allow 192.168.0.0/16 --blocklist ./blocklists --blocklist-allow ./allow
sudo ./venv/bin/cora-floor status                 # elements per set, packets dropped in / out
sudo ./venv/bin/cora-floor block 203.0.113.9 600  # drop one address host-wide for 10 minutes (kernel expires it)
sudo ./venv/bin/cora-floor remove                 # take the floor out (the per-task egress chain stays)
```

- **It is host-wide.** Unlike `ISOLATE` (one task), a floor drop affects every process. Loopback, the resolvers in
  `/etc/resolv.conf`, `--floor-allow` and the blocklist allow list are always accepted first.
- **It outlives the daemon.** The sets and chains stay in the kernel if the daemon dies; restart reconciles them.
  `cora-floor remove` or `cora-firewall purge` takes them out.
- **Domains are not on by default.** `--floor-dns` also drops the addresses the resolver found for listed domains,
  but many tracker names share CDN addresses, so that can break unrelated sites. Allow-list domains are not mirrored.
- A list reload (`kill -HUP`) updates the sets as one transaction per set pair: an address that stays listed is
  never unblocked while the list changes.

**Not locking yourself out.** The daemon refuses a floor (or a reload) that would drop the default gateway or a live
SSH peer unless you allow them (`--floor-allow-detected`, `--no-floor-precheck`), and `--floor-confirm 120` installs it
with a dead-man: it removes itself unless `sudo cora-floor confirm` arrives in time. The timer is a separate process,
armed before the floor goes in, so a crashed daemon cannot strand it. You are asked once per allow set, so unattended
restarts and reboots do not prompt. See [docs/service.md](docs/service.md).

### Dynamic policy (`--dyn-policy`)

When the model isolates a task for talking to a public address, the next task to reach it would still get its first
packet out. `--dyn-policy` can turn that verdict into a short-lived kernel drop of the destination. It is **off in
effect by default: the default is `shadow`**, which records what it *would* do in the decision log and touches nothing.
Web ports (80/443) are blocked per flow only, never the whole address; other ports escalate to the whole address after
two distinct tasks; there are budgets (20 writes/min, 512 live, 8 targets per task per hour); and `cora-firewall release
TASK` drops what that task caused. See [docs/dyn-policy.md](docs/dyn-policy.md), and review a week of shadow data with
`cora-floor dyn-report sentinel_decisions.jsonl` before you consider `--dyn-policy enforce`, and rehearse a
tweak against the recorded data with `cora-floor dyn-replay decisions.jsonl --task-cap 4` (see docs/dyn-policy.md).

### As a service

```bash
sudo deploy/install-service.sh --bindir "$PWD/venv/bin"   # writes the unit; enables and starts nothing
sudo systemctl enable --now cora-sentinel && sudo cora-floor confirm
```

`Restart=on-failure` (capped), `systemctl reload` re-reads the blocklists, and stopping leaves a confirmed floor in
place while an unconfirmed one is removed. Details, the lifecycle table and the caveats: [docs/service.md](docs/service.md).

## How a decision is made

1. **Detect** (deterministic). A flow is a violation if it is on a blocklist, or outside the allowlist. A
   blocklist hit beats the allowlist; an allow-list exception beats the blocklist.
2. **Judge** (model). Qwen proposes one of `ALLOW`, `THROTTLE`, `ISOLATE`, `SUSPEND`, `TERMINATE`,
   `ESCALATE`, constrained by a GBNF grammar to exactly that shape. Anything unusable becomes `ESCALATE`.
3. **Floor** (policy). A blocklist hit can never be waved through: the model may escalate, never downgrade
   below `ISOLATE` (`--no-blocklist-floor` turns this off). Low confidence becomes `ESCALATE`.
4. **Gate** (deterministic). The *target comes from the event, never from the model.* Before acting, the
   bus gates (`GI_1`-`GI_3`) must pass, the process start time must still match (PID reuse), and the pid
   must still be in the task's cgroup. The check and the action happen under one lock.
5. **Act.** `ISOLATE` drops all non-loopback egress for the task's cgroup and leaves it running;
   `SUSPEND` freezes the whole tree; `TERMINATE` kills it; `THROTTLE` limits it. All but `TERMINATE` are
   reversible with `cora-firewall release`.

Everything fails closed: bad model output, a failed gate, a missing bus or a reused pid all end in no action.

## What is detected, and from where

| Source | Sees | Attributes to a task? |
|---|---|---|
| **Flow tap**, TCP | every SYN a task sends | **yes**, at send time, by cgroup (even zero-lifetime) |
| **Flow tap**, UDP | the first packet of each flow; labels QUIC (udp/443); reads the DNS query **name** | **yes** |
| sock_diag dump | TCP sockets alive during a poll (default 100 ms) | yes, by the kernel's cgroup id |
| sock_diag destroy events | every TCP socket, none missed | **no** (the kernel omits the cgroup): audit only |
| `/proc/net/tcp` | the fallback without sock_diag | via fd scanning |

Why the tap exists: without it, a TCP beacon that opens and closes between two polls is detected but has
no owner, and **UDP is invisible entirely.** See [docs/architecture.md](docs/architecture.md).

## Blocklists and reports

- Lists are plain files, one list per file (file name = list name). Accepted per line: CIDR, IP, domain
  (also matches subdomains), `*.domain`, hosts-file lines, adblock `||domain^`. Entries broader than /8
  (/16 for v6) and anything overlapping loopback are **rejected**, so a poisoned list cannot quarantine
  everything. See [`examples/`](examples/).
- Domains match **by name** when a task does a plain DNS lookup, and **by resolved address** otherwise
  (resolved hourly in the background; `--no-resolve` disables it). A CDN address shared with something you
  need can false-positive: put exceptions in the allow directory.
- Each blocklist hit produces an **anonymized report** in `cora_reports/` (JSON plus a ready issue body),
  validated against [`schema/violation.schema.json`](schema/violation.schema.json) (`cora.security.violation/v1`).
  It holds the list, the entry, a public destination IP and port, the action taken, an hour-truncated time
  and a salted pseudonym for the task. It never holds hostname, user, pid, task name, command line, local
  ports, private addresses or the model's free text. Reports are **never sent**: review, then file them.
  The report does not currently say which protocol was involved. See [docs/violation-reports.md](docs/violation-reports.md).

### Keeping lists current

`cora-blocklist pull` fetches lists from a URL, but **never changes what the sentinel enforces by itself**: an
update is only *staged*, you review the diff, and you approve that exact content by its sha256. TLS is verified,
downloads are size- and time-limited, a list that is emptied or starts blocking your LAN is flagged, and
`cora-sentinel --blocklist-store DIR` refuses to start if any active list is not what was approved. Prefer URLs
pinned to a commit. There are no signatures. After `accept`, `kill -HUP <pid>` applies the update **without
restarting**: only the lists change (taps, cgroup tracking and firewall rules are untouched), a failed or empty
reload keeps the current lists, and resolved addresses carry over so detection has no gap. See
[docs/blocklist-updates.md](docs/blocklist-updates.md).

A blocklist hit is isolated at once, before it queues behind the model: a task's egress is cut about 4-6 ms after its
first packet instead of after the model's 2-4 s (and a full queue can no longer leave it uncontained); see
[docs/containment-latency.md](docs/containment-latency.md). Reading the tap rules back is done over netlink, not with `nft list` (whose cost grows quadratically with live
tasks: 160 tasks cost 1.8-2.0 s per listing, 20 ms over netlink), and every write (install, ISOLATE, gc) is one nft
commit. Slow tap installs are explained, not guessed at: each sync is split into lock wait / nft / other with a no-op-process
control, and `tools/nft_latency_experiments.py` checks the verdict against causes it produces on purpose. See
[docs/tap-latency.md](docs/tap-latency.md).

## Measured behaviour

Environment matters, so each number says where it came from.

| What | Result | Where |
|---|---|---|
| Zero-lifetime TCP beacons, 3 concurrent tasks (125) | all attributed to the right task, 0 lost | VM, Linux 6.18 |
| The same beacons with sock_diag only | 0 of 60 attributed | VM |
| Zero-lifetime UDP beacons, 3 tasks (125) | all attributed, 0 lost | VM |
| One-way UDP flood, 20,000 packets, one flow | 1 event | VM |
| TCP flood, 1,500 connections | 1,500 counted, 0 lost | VM |
| `connect()` call to userspace receipt (TCP) | median 79 µs, p99 209 µs, max 2.5 ms | VM |
| the same | median 34 µs, p99 565 µs, max 3.1 ms | author's bare metal |
| sock_diag dump at ~2,000 sockets | 11 ms (vs 21 ms for `/proc` parse + fd scan) | VM |
| Model verdict, Qwen 2.5 3B | 2.1 to 4.1 s | author's bare metal |
| 50 SYNs sent right after a `dyn` element is added, each hook | 0 reached the listener, all 50 counted as dropped | author's bare metal, 2 netns |
| 300-connection flood far past the 10/s log limit | 0 got through, all 300 dropped | same |
| Re-syncing a 1,500-address list for 4 s while probing a listed address | 0 probes got through | same |
| SIGKILL mid-sync, 8 rounds | the set was always the old list or the new one, never a mix | same |

Latencies are upper bounds and are *receipt* times: the kernel supplies no timestamp for locally generated
packets.

## Known limits

- **Root only.** There is no unprivileged mode.
- **TCP and UDP only.** Encrypted DNS (DoH, DoT, DoQ) hides query names. QUIC **hostnames are not
  recoverable** (that needs AES, may span two packets, and ECH hides it); QUIC is labelled and matched by
  address.
- **The lockout guard is best effort.** The pre-check sees the default gateway and SSH on port 22 (or the port in
  `$SSH_CONNECTION`); other management paths need `--floor-allow`. The dead-man is the net underneath it.
- **Dynamic policy is only as good as the model's verdicts.** It is bounded (see docs/dyn-policy.md) but a block on a
  web address is still a block on everything behind it, which is why web ports are flow-only and why shadow is the default.
- **The kernel floor is address-level.** It cannot match names, and a listed address shared with something you use is
  dropped for everything on the host (`--floor-allow` is the remedy). Fed from the lists' addresses and subnets only,
  unless you opt in to `--floor-dns`.
- **The tap needs a task's rules to exist before its first packet.** `cora-run` guarantees it; a task
  started another way is unobserved until the monitor's next sync (one poll interval).
- **No UDP view of flows that began before the tap**, until they go idle and start a new flow.
- **No pid**, only the task; no kernel timestamp.
- A task that starts and exits before the monitor has seen it alive (one poll, 100 ms by default) cannot be resolved
  to a process: its violation is logged with the reasons but not sent to the model. A task seen alive and then
  gone is still reported, and the gate refuses to act on the dead pid.
- `ISOLATE` is a **quarantine**, not a surgical rule: it also drops DNS and replies to inbound traffic.
  A dropped TCP SYN times out; it does not fail instantly.
- A UDP flow is identified by **task, destination and source port**. Within one task, an identical flow
  repeated inside the idle timeout (30 s) is one flow. Each address family holds 65,536 flows; beyond that new
  flows are not logged.
- The dump path maps only a task's own cgroup, not nested sub-cgroups (untested).
- `THROTTLE` needs the cpu/memory controllers delegated; otherwise it falls back to `nice +10`, which
  `release` does not undo.
- Verdict *quality* is the model's: only its *shape* is guaranteed. A 0.5B model in testing answered
  SUSPEND to everything and parroted prompt text into its reasons. Run `python -m cora_sentinel.verdict --probe MODEL`.

## Testing

```bash
pip install -e ".[dev]"
python -m pytest -q                              # unprivileged: kernel tests skip cleanly
sudo -E ./venv/bin/python -m pytest -q           # everything (CORA_GGUF=path adds the real-model test)
```

At 0.4.0: **453 passed, 5 skipped** as root against the installed wheel (the skips: IPv6 sock_diag, two tests that
only apply when not root, and two IPv6 tap tests that have never been run on a kernel with IPv6; the real-model
test ran), and **382 passed, 76 skipped** unprivileged. The unprivileged run is what CI executes.

At 0.5.0: **492 passed, 3 skipped** as root on bare metal (28 cores, 2:57), including `tests/test_floor_gate.py`: real
TCP between two network namespaces, each with its own throwaway table, so the host ruleset is never touched.
`tests/test_nftsets.py` (30 tests) needs no kernel and runs in CI.

0.5.1 adds `tests/test_floorguard.py` (40, no kernel), `tests/test_service.py` (10, validates the unit with
`systemd-analyze` when present) and `tests/test_floor_confirm.py` (9: a real watchdog process, a SIGKILLed daemon, the
real `/proc` decoding, and the daemon end to end; they skip without root, nft and `ip netns`, and the daemon ones also
need a cgroup v2 mount, or `CORA_TEST_CGROUP_MOUNT`).

0.6.0 adds `tests/test_dynpolicy.py` (67, no kernel) and `tests/test_dyn_kernel.py` (7: real traffic is cut and
restored by the policy's decisions; they use a public address aliased inside the lab, because the policy refuses private
ones). `tools/dyn_bench.py` measures the per-decision cost.

0.8.0 adds `tests/test_vendor.py` (the vendored gate matches its lock, a shadowing `subnetbus` is ignored, the update tool)
and `tests/test_packaging_deb.py` (wheel, sdist and `.deb` contents, reproducibility, and the maintainer scripts against
stubbed commands). `packaging/lifecycle_test.sh` is the real install/upgrade/remove/purge, for a disposable machine only.

0.7.0 adds `tests/test_dynreplay.py` (26, no kernel: the logs are produced by running the live policy over synthetic
scenarios) and `tests/test_dynreplay_kernel.py` (4: the private-namespace mode; the host ruleset is compared before and
after). The two daemon end-to-end tests also replay the real daemon's own logs with `--check`.

0.6.1 adds `tests/test_daemon_dyn.py` (2: the real daemon with a stub model and real `cora-run` tasks; shadow records
`would_block`, and in enforce a brand-new task's first packet to an isolated task's destination is dropped).
Daemon tests launch with `nsenter`, not `ip netns exec`, which would hide the host's cgroup mount.

## Layout

```
src/cora_sentinel/   daemon  netmon  nflog  nftdump  nftsets  floorguard  dynpolicy  dynreplay  sockdiag  firewall  cgroup  blocklist  blocklist_store  reload  report  verdict  run  demo  selfcheck
tests/               unit tests, plus kernel tests that skip without root
schema/              violation.schema.json (cora.security.violation/v1)
examples/            starter blocklists, an allow list, an example report
docs/                architecture.md, service.md, dyn-policy.md, violation-reports.md
deploy/              cora-sentinel.service, cora-sentinel.conf, install-service.sh
```

Commands: `cora-sentinel`, `cora-run`, `cora-demo`, `cora-cgroup`, `cora-firewall`, `cora-floor`, `cora-blocklist`,
`cora-report`, `cora-selfcheck`.

## Related repositories

[`engine-telemetry-bus`](https://github.com/nkaralus/engine-telemetry-bus) (the gates and registry, vendored here at
commit `ac3f126` under `src/cora_sentinel/_vendor/subnetbus`; `tools/vendor_bus.py` updates it) and [`cora-security`](https://github.com/nkaralus/cora-security) (blocklists and the report schema).

## License

MIT. See [LICENSE](LICENSE).
