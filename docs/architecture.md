# Architecture and design notes

This is the reasoning behind the design, including the places where a measurement overturned the plan.
Everything marked *measured* was observed on a real kernel (Linux 6.18 in a VM, with the TCP tap and demo
re-run on the author's bare-metal Ubuntu), not assumed.

## The principle: deterministic enforcement, advisory model

```
detectors (deterministic) -> event -> model proposes a verdict -> policy floor -> gates -> executor
```

* The model is **out of band**: it runs on a worker thread, never in a poll loop, and an event that outlives
  its task is simply refused by the gate.
* The model **never chooses the target.** The gate is built from the event's own subject (task, pid, start
  time, virtual IP), so hostile text in a command line can influence a *verdict* but not *who gets hit*.
* A GBNF grammar makes the output always parse: `verdict`, `confidence`, `reason`, a fixed key order, a
  bounded reason. Anything unusable fails closed to `ESCALATE`.
* Gates run under the registry lock together with the action (no check-then-act race), and verify three
  identities: the bus node and IP, the process **start time** (PID reuse), and the pid's **current cgroup**.
* A **blocklist floor** exists because deterministic detections should not depend on a model's mood: a small
  model in testing answered SUSPEND to everything. The model may escalate; it may not downgrade below ISOLATE.

## Where a connection can be seen, and who owns it

The hard problem is **attribution**: knowing *which task* made a connection that may last microseconds.

| Source | Coverage | Attribution | Measured |
|---|---|---|---|
| sock_diag **dump** | sockets alive at poll time | kernel cgroup id (`INET_DIAG_CGROUP_ID`, equals the cgroup directory's inode) | needs `CAP_NET_ADMIN`; 11 ms at ~2,000 sockets |
| sock_diag **destroy events** | every TCP socket | **none**: `inode=0`, no cgroup attribute | cookie equals the live-dump cookie |
| **NFLOG flow tap** | first packet of every flow, TCP and UDP | **by the rule itself**, at send time | 125/125 zero-lifetime beacons, per task |

* The destroy stream is a real multicast (the mechanism behind `ss -E`), so *detection* of a blocklisted
  destination cannot slip. But it names no owner, so a beacon that closes between two polls is only an
  unattributed "slip", and nothing is acted on (guessing an owner could quarantine the wrong task).
* With sock_diag alone, zero-lifetime TCP connections were **0 of 60 attributed**; a connection living at least
  one poll interval was **25 of 25**. The tap removes that boundary.
* The tap runs at nftables priority **-10**, before the egress-drop chain at **0**, so an isolated task's
  attempts are still logged.
* The **cookie** is the identity that links a live socket to its destroy event, which is how a socket seen
  alive is never counted again as a slip.

## The NFLOG tap, in detail

The kernel matches the sending socket's cgroup (`socket cgroupv2 level N "<path>"`) and queues a message.

* **`level` and `path` are different things.** `level` is the depth in the cgroup2 tree; `path` is what `nft`
  looks up from `/sys/fs/cgroup`. On a hybrid layout (cgroup2 mounted below `/sys/fs/cgroup`) they differ.
* **nft's JSON shows only the resolved path for that match, not the id,** so a rule's cgroup id is written into
  its comment. A cgroup deleted and recreated under the same name gets a new id; that is how stale rules are
  recognised. (This also fixed a real bug: `block()` once decided "already blocked" by name alone.)
* **No kernel timestamp** (`NFULA_TIMESTAMP` is absent for locally generated packets) and **no pid**.
* `queue-threshold 1` and a 10 ms flush make delivery immediate. A rule's `snaplen` can only shrink the
  instance's copy range, so the instance is configured for the largest (320 bytes, enough for a DNS question).

### Why UDP uses a dynamic set and not `ct state new`

*Measured:* `ct state new` logged **all three packets of one flow** (source port repeated three times).
Conntrack's NEW stays true for every packet until a reply is seen, so a one-way UDP stream would be logged
packet by packet: a flood vector against the monitor itself.

The replacement is a per-family dynamic set keyed on `(task cgroup, daddr, dport, sport)` with a timeout. One rule refreshes
and returns for a known flow; the next adds and logs a new one. *Measured:* 23,005 packets, including a
20,000-packet one-way flood, produced exactly 4 events. It also removes the conntrack dependency.
Five rules per task: one TCP, and a gate + log rule for each of IPv4 and IPv6.

**The task is in the key on purpose.** The kernel picks a UDP source port at random from about 28,000, so
flows to one destination share a source port by birthday odds (about 1 run in 4 at 125 flows). The first
version keyed the set on `(daddr, dport, sport)` only, shared by every task, and a second task's flow was
swallowed. *Measured* over 1,800 flows from 3 tasks: later tasks lost 27 of 593 and 12 of 592 flows (about 2%).
With the cgroup in the key the loss is zero, under any port allocator. Within one task the same destination
from the same source port inside the timeout is the same flow, and the per-task cooldown would collapse its
events anyway. The key needs an nftables with `typeof` sets and a `socket cgroupv2` key (verified on nft
1.0.9, Linux 6.18); if yours refuses it, `--no-tap-udp` taps TCP only.

### What the payload gives us

* **DNS (udp/53):** the query *name*, in clear text, attributed to the task even through a local resolver
  stub. A listed name is a hit at lookup time, before any connection. Encrypted DNS is invisible.
* **QUIC (udp/443):** labelled from the long-header bits and a known version. The hostname is **not**
  recoverable: unprotecting an Initial packet needs AES (not in the stdlib), the ClientHello can span two
  packets (post-quantum key shares), and ECH hides the name regardless.

## Bugs that measurement found

These are recorded because each came from a test that could fail, not from review.

| Found by | Bug | Fix |
|---|---|---|
| a recreated-cgroup test | `block()` reported "already blocked" for a new task with an old name | rule comments carry the cgroup id |
| a flood test | retransmitted SYNs counted as new connections | coalesce by TCP initial sequence number |
| a race test | `cora-run` and the monitor both did read-then-add: **4 of 30** tasks got duplicate rules | file lock + duplicate detection + periodic re-verify (now **0 of 60**) |
| a repeated run | a dump could judge a `SYN_SENT` socket before its tap message was read | drain the tap before judging a dump |
| a release test | `release` read the *actual* frozen state; freezing is asynchronous, so it could skip the thaw and leave a task frozen | key on the *requested* state (`cgroup.freeze`) |
| an unprivileged run | the daemon opened its default output file before validating flags | validate first; clean error on an unwritable path |
| a bare-metal run | the UDP flow set was shared across tasks, so one task's flow could suppress another's (about 2% of later tasks' flows at scale) | the task's cgroup is part of the key |
| bare-metal instrumentation | the event loop ran `nft` and took locks inline: polls of 1.5 s and 13 s, events processed after their task exited | tap sync and delivery moved to workers; the loop only does lock-free work |
| an executor review | an unknown verdict fell into the kill branch | explicit dispatch; unknown verdicts do nothing |

The one failure that was hard to find: on bare metal the first-launched task's 40 UDP events were all `owner_gone`,
although the tap counted them. It first resisted reproduction (a slow `nft` at 0.4 s and 1.2 s, privilege-dropped
tasks), because the reproduction had no per-poll timing and counting polls cannot rule out an occasional stall.
Adding `poll_ms_max` showed it on the author's machine (a 1,501 ms poll, then 13,160 ms) and reproduced it here
(2,418 ms with a 1.2 s `nft`). The cause was the event loop running `nft` inline, behind a cross-process lock that
`cora-run` also holds, so events queued while a short-lived task exited. See the next section.

## Threads, and what may block

| Thread | Does | May block on |
|---|---|---|
| **event loop** (`netmon`) | drains the NFLOG and destroy sockets, dedupes, judges, resolves the owner from `/proc` | **nothing**: no `nft`, no file lock, no registry lock |
| tap sync worker | applies the *latest wanted* rule set (coalesced) | `nft`, the per-table file lock |
| delivery worker | builds the event and fires it | the registry lock (queue of 4,096; overflow is dropped **loudly**) |
| adjudicator | model, gates, action; holds the registry lock across the action so check and act are atomic | `nft` (an ISOLATE), the model |
| reload worker | on `SIGHUP`, rebuilds the lists and swaps them atomically (the handler only sets a flag) | file reads, store verification |
| resolver | resolves listed domains to addresses hourly, and at once for new ones after a reload | DNS |
| daemon main | memory/path detectors, `Firewall.gc` | `nft` (the Firewall serializes itself) |

Detection is never held up by slow enforcement: only delivery can lag. *Measured* with every `nft` call at 0.8 s:
the loop's worst poll was **4 ms** (2,418 ms before the change) while the sync worker took 1,616 ms; every flow was
still attributed. Steady-state `ensure(pid)` takes no lock, and `Firewall` serializes its own read-then-write steps
instead of relying on a caller holding the registry lock across `nft`.

**Containment path.** tap -> netmon loop -> delivery worker -> `Adjudicator.submit`, which isolates a blocklist hit
*right there* (gate, then one nft commit), then queues the event for the model, which can only add to it. See
[containment-latency.md](containment-latency.md).

Since 0.3.1 each tap sync is also split into lock wait / nft / other plus a no-op-child control, and a slow one is
explained in the log: see [tap-latency.md](tap-latency.md). Since 0.3.3 the kernel's rules are READ over netlink
(`nftdump`) rather than with `nft list`, whose cost grows quadratically with live tasks; writes still go through nft.

## Containment

* **Freeze** is `cgroup.freeze`: reversible and covers the whole tree. It is asynchronous (see above).
* **Terminate** is `cgroup.kill`: SIGKILL to the whole tree, kernel 5.14+.
* **Isolate** drops everything leaving a non-loopback interface for the task's cgroup. *Measured:* a dropped
  **UDP** send fails at once with `EPERM`; a dropped **TCP** SYN simply **times out**, like a blackhole.
* Rules live in a table of their own. Removing it removes every rule Cora added and nothing else. The kernel is
  the source of truth: a restarted daemon reads the ruleset back.
* The per-table lock file is never unlinked by the real sentinel (a process holding the old inode would stop
  excluding a new opener); only the demo, which owns its table, removes its lock.

## Blocklists

Rails exist because a poisoned list can quarantine every task: entries broader than /8 (/16 for IPv6) and
anything overlapping loopback are rejected, and an allow list always wins. Domains match by DNS name when the
task does a plain lookup, and by resolved address otherwise, which can false-positive on a shared CDN address.

## Schema evolution

`cora.security.violation/v1` is strict (`additionalProperties: false`) and committed to `cora-security`.
Adding a field is therefore a **new schema id**, not an edit.
