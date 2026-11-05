# Why was a tap rule late? Splitting a slow sync into lock, nft and host

A new task's tap rules are installed by the **tap sync worker** (and by `cora-run` before it execs). Two things can make
that slow, with different fixes: waiting for the cross-process **tap lock**, or time spent **inside nft**. And slow nft
has more than one cause. Every sync is measured so you can tell which.

## What is measured

| Number | Meaning |
|---|---|
| **lock wait** | time spent waiting for the cross-process lock (`/run/lock/cora-tap-<table>.lock`), held by `cora-run` or another sync |
| **nft** | wall time inside nft subprocesses, with the call count, the slowest call, and **which call it was** (`-j list chain` is a dump; `-f -` is a transaction commit) |
| **other** | the rest: Python, the GIL, disk, and the netlink reads (a millisecond or two) |
| **no-op child** | how long `true` took, just before the sync: a control for "is starting *any* process slow right now?" |
| **CPU pressure** | the share of the sync during which some task was waiting for a CPU (the kernel's PSI, `/proc/pressure/cpu`); absent on kernels without it |

The nft tally is per thread, so the sync worker's numbers are not mixed with the adjudicator's. None of this runs on the
event loop (see `architecture.md`); the cost is one extra no-op child per sync, on the worker (about 1 ms).

## Where it shows up

A sync over 500 ms is reported at once, in the log:

```
[cora-sentinel] tap sync took 1575 ms = lock wait 1568 + nft 7 (2 calls, slowest 4 [-f -]) + other 0; a no-op child
took 2 ms. CPU pressure during it: 2%. Suggests: mostly waiting for the cross-process tap lock: another holder (e.g.
cora-run installing rules) kept it that long
```

and the end-of-run summary carries `tap_sync_ms_max=… (lock_wait_max=… nft_max=… slowest_nft_call=… noop_child_max=…
cpu_pressure_max=…%)`, plus `worst_tap_sync: …` (the breakdown of the single slowest sync) if there was a slow one.

## The biggest cost was reading the rules, and it grew with load

A 28-core bare-metal run showed an *idle* sync whose slowest call was **`[-j list chain]`, 79-84 ms**: the dump, not a
commit. That led to the cause:

**`nft list` prints a `socket cgroupv2` match by resolving the cgroup id back to a path, and the cost of that grows
with how many cgroups it has to get through.** Measured on a Linux 6.18 / nft 1.0.9 test machine:

| what | result |
|---|---|
| process start (`nft --version`) | 1.5 ms, flat |
| text, JSON and `-nnn` listings | identical: it is not formatting |
| a chain **without** cgroup rules, in the same table | 2 ms whatever the cgroup count |
| 1,000 extra cgroups, the directory given ten different names: **six** list *before* ours | 233-306 ms (8 rules), 1,150-1,290 ms (40 rules) |
| ... and the other **four** list *after* ours | 3.4-3.8 ms (8 rules), 8-11 ms (40 rules) |
| **only our own tasks**, UDP rules (5 per task), 10 / 40 / 80 / 160 live tasks | 13-19 / 118-140 / 431-515 / **1,786-2,021 ms** (two runs); netlink 1.2-1.6 / 4.9-6.0 / 9-10 / 20-22 ms |

Read together: the cost is (rules in the chain) x (cgroups the walk visits before reaching each rule's target) x about
0.03 ms. *Which* cgroups are visited first depends on the kernel's listing order, which follows a hash of the directory
names, so it is fixed for a given machine and differs between machines (and between my test runs, which is how I first
mis-blamed the UDP rules: my TCP and UDP tables happened to sit on opposite sides of the big directory). I measured the
effect and its scaling; I did **not** read nft's source, so "it walks the cgroup tree" is the explanation that fits, not
a quoted fact.

It is also **quadratic in live tasks**, with no external cgroups at all: each task adds 5 rules *and* another sibling
cgroup for later lookups to walk past (80 -> 160 tasks multiplied the time by about 4). The listing ran inside the tap lock,
which every `cora-run` launch and the sync worker serialize on, so a burst of task launches paid it over and over; and in
`Firewall.gc`, which an ISOLATE waits behind. `active()` (run before every `cora-run` pre-install) and `udp_enabled()`
used a plain `list`, which prints the same rules and so pays the same.

### The fix: read the kernel's rules over netlink

`cora_sentinel/nftdump.py` asks the kernel directly (`NFT_MSG_GETRULE` dump, `GETCHAIN`, `GETSET`). The kernel's dump
carries the raw ids, so the cost is O(rules): **160 tasks went from 1.8-2.0 s to 20 ms**, and the cost no longer depends
on where the machine's other cgroups sit. It reads exactly what the callers use: each rule's handle, comment and first
counter, and whether a chain or set exists. Writes still go through nft.

- **It agrees with nft.** On the real kernel, rules read both ways are identical in every state tested: empty, live with
  real packet counters, with an injected duplicate rule, for the tap chain and the egress chain.
- **It falls back, once, loudly.** Any netlink failure (no `CAP_NET_ADMIN`, no netlink support) switches that `Firewall`
  to the nft command and prints one message; the result is the same, only slower.
- **It is off where it must be:** with an injected runner (a test's fake must see every read), with no nft binary
  (a missing nft stays a clear error from any operation, not an empty listing), and with `CORA_NFT_NATIVE=0`.
- Not read natively: the `-f -` writes (they do not list, and were measured fast).

**Check it on your machine:** `sudo python3 tools/nft_latency_experiments.py dump --tasks 160` builds live tasks in steps
and shows the nft command against netlink side by side, with a "same rules?" column. What is *not* yet shown is that this
was the cause of the 1.5-13 s stalls you saw under load: it is the best candidate (a listing that is quadratic in live
tasks, held under a lock that every launch queues on), but the evidence on your machine is the `lock_wait_max` / `nft_max`
in the monitor summary from a heavy parallel run with this version. If they stay small, it was.

## Writes: one commit per operation

Reads were the big cost; the write side had a smaller, different problem: operations that spent **more than one nft
commit** (a transaction, which waits for the kernel to finish committing) where one would do. Counted and timed on the
test machine, with the table growing:

| operation | commits before -> after | time before -> after (0 live tasks) |
|---|---|---|
| `cora-run` install, under the tap lock | 2 -> **1** | 11.7 -> 3.4 ms |
| an ISOLATE (`Firewall.block`) | 2 -> **1** (3 when the old rule was stale) | 11.7 -> **3.2 ms** |
| `Firewall.gc` of 5 dead tasks, under the lock an ISOLATE waits behind | 5 -> **1** | 37 -> 7.3 ms |
| the sentinel's `sync` adding a task | 1 -> 1 (it already batched) | unchanged |

- `install` and `block` used to run an idempotent `add table / set / chain` as its own commit even though the chain
  already existed. They now include it only when something is actually missing, and in the *same* transaction as the rule.
- Re-isolating a task whose cgroup was recreated used to commit "delete the old rule" and "add the new one" separately,
  so for one commit-time the task was **unblocked**. It is now one atomic transaction: delete and add together.
- `gc` is one transaction however many tasks died.

A commit costs about 3-6 ms on the test machine and does not grow with the number of rules. What still grows at 160 live
tasks is the netlink *read* (about 21 us per rule, about 17 ms for 800 rules, parsed in Python): that is what `install`
and `sync` spend there now, and it is linear, not quadratic. It is the next lever if the numbers ever call for it.

`sudo python3 tools/nft_latency_experiments.py writes --tasks 160` measures this on your machine, one row per size. Its
ISOLATE time is, in effect, your machine's cost of a single commit. If that is tens of milliseconds, the commit itself is
the remaining cost. On the test kernel most of a commit was waiting for an RCU grace period (a bare `add table` +
`delete table` took 8.0 ms, and 2.0-2.8 ms with `/sys/kernel/rcu_expedited=1`, repeatable). That is a system-wide kernel
setting with a cost (it interrupts every CPU), so it is yours to decide; nothing here changes it.

### Why the writes are not done over netlink too

Reads were cheap to do natively because the callers need three fields from a rule. Writes would mean building each
rule's expressions (`socket cgroupv2`, payload matches, log, counter, set lookup and update, comment) as kernel netlink
bytes: reimplementing part of libnftnl, where one wrong byte means a rule that silently does not match. And it would
save little: process start-up is about 1 ms of a roughly 14 ms transaction on the 28-core machine (`cora-selfcheck`: 1
ms start, 14 ms transaction), so almost all of a commit is the kernel's. Batching got most of the benefit without that
risk. Revisit only if the `writes` scenario ever shows process start-up dominating.

## How the verdict is reached

| lock wait | nft | no-op child | CPU pressure | verdict |
|---|---|---|---|---|
| **most of the time** | | | | waiting for the lock (measured directly: firm) |
| small | **most** | barely delayed | **>= 50%** | the CPUs were **oversubscribed**: load reaching nft's kernel path, *not* evidence of commit contention |
| small | **most** | barely delayed | **< 10%** | nft or the kernel's transaction path itself: consistent with commit contention, or a slow commit (e.g. an RCU grace period) |
| small | **most** | barely delayed | between, or unknown | nft or the kernel path; load can still slow it without slowing fork: inconclusive |
| small | **most** | delayed too | | the whole host is slow (CPU or fork pressure) |
| small | most | somewhat delayed | | mixed |
| small | small | | | neither (Python, the GIL, disk) |

"Not slow" means under 100 ms **or within 2x of the fastest sync this machine has shown** (a fixed number is wrong on
some machine: an idle 28-core sync took 100-111 ms). "Delayed" is judged by **extra milliseconds against the fastest this
run saw**, not by ratios: under 10% of nft's extra delay (and under 30 ms) is "barely", 15% or more is "too". These
thresholds are heuristics. **The numbers are the ground truth; the verdict is a convenience.**

**A fast no-op child does not mean an idle host.** On a many-core machine, saturating the CPUs slowed nft x5 while a fork
took 2 ms. And a slow *dump* and a slow *commit* are different problems: in a loaded run the slowest call was the dump
(`-j list chain`, 397 ms) in one scenario and the commit (`-f -`, 221 ms) in another. The label tells you which.

## Does the verdict deserve trust? Test it on your machine

`tools/nft_latency_experiments.py` produces each cause on purpose (real nft, real flock, real load) and shows what the
tool says. It needs root, touches only scratch tables (`coraexp*`), its own cgroup directory and temp files, and removes
them on exit.

```bash
sudo python3 tools/nft_latency_experiments.py            # idle, lock, busy, kernel, dump
sudo python3 tools/nft_latency_experiments.py idle lock --check     # exit 1 if a stalled scenario is named wrongly
```

The `kernel` scenario (16 low-priority loaders doing tiny nft transactions) cannot be separated from load on one core
(the loaders themselves showed 35% CPU pressure); use a many-core machine. The `busy` scenario is named "the whole host is
slow" where fork slows too (few cores) and "the CPUs were oversubscribed" where it does not (many cores).

## The tap lock is bounded

The lock used to be a plain blocking `flock`, which has no timeout: a holder that hangs (stopped, or stuck in
uninterruptible I/O) would hang its caller forever. Now it is taken with a deadline:

| Caller | Waits at most | If it times out |
|---|---|---|
| the sentinel's sync worker | 30 s | logs `tap rule sync failed: could not get the tap lock ...: held by pid N (name, state)`, keeps the event loop running, and **retries** on the next poll |
| `cora-run` (pre-install) | 5 s | prints `tap pre-install SKIPPED: ...`, **starts the task anyway**, and says what that costs: its first connection may go unobserved until the sentinel installs the rule |

`CORA_TAP_LOCK_TIMEOUT` (seconds) overrides both; a non-numeric, zero, negative or infinite value is ignored with a
message. The lock file holds `pid name` of whoever holds it, so a timeout says **who** is stuck and whether it is stopped
(`T`), in uninterruptible I/O (`D`), or just slow. Polling adds at most 5 ms after the lock is released. Holding the lock
is now much shorter (no slow listing inside it), and a legitimately slow holder is still bounded by nft's own 10 s
per-call timeout.
