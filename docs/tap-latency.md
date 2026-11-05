# Why was a tap rule late? Splitting a slow sync into lock, nft and host

A new task's tap rules are installed by the **tap sync worker** (and by `cora-run` before it execs). Two things can make
that slow, and they have different fixes: waiting for the cross-process **tap lock**, or time spent **inside nft**. And
slow nft has two very different causes: the *host* is too busy to run anything, or something in **nft or the kernel's
nftables transaction path** is slow. Since 0.3.1 every sync is measured so you can tell which.

## What is measured

| Number | Meaning |
|---|---|
| **lock wait** | time spent waiting for the cross-process lock (`/run/lock/cora-tap-<table>.lock`), held by `cora-run` or another sync |
| **nft** | wall time inside nft subprocesses, with the call count and the slowest single call |
| **other** | the rest: Python, the GIL, disk |
| **no-op child** | how long `true` took, measured just before the sync, under the same conditions: a control for "is starting *any* process slow right now?" |

The nft tally is per thread, so the sync worker's numbers are not mixed with the adjudicator's. None of this runs on the
event loop (see `architecture.md`); the cost is one extra no-op child process per sync, on the worker (about 1 ms).

## Where it shows up

When a sync takes more than 500 ms the sentinel says so at once, in the log:

```
[cora-sentinel] tap sync took 1575 ms = lock wait 1568 + nft 7 (2 calls, slowest 4) + other 0; a no-op child took 2 ms.
Suggests: mostly waiting for the cross-process tap lock: another holder (e.g. cora-run installing rules) kept it that long
```

and the end-of-run summary carries `tap_sync_ms_max=… (lock_wait_max=… nft_max=… slowest_nft_call=… noop_child_max=…)`,
plus `worst_tap_sync: …` (the breakdown of the single slowest sync) if there was a slow one.

## How the verdict is reached

| lock wait | nft | no-op child | verdict |
|---|---|---|---|
| **most of the time** | | | waiting for the lock (this one is measured directly, so it is firm) |
| small | **most of the time** | barely delayed | points at **nft or the kernel's transaction path** |
| small | **most of the time** | delayed too | **the whole host** is slow (CPU or fork pressure), not a netlink problem |
| small | most of the time | somewhat delayed | mixed: host load is part of it, not all |
| small | small | | neither (Python, the GIL, disk) |

"Delayed" is judged by **extra milliseconds against the fastest this run saw**, not by ratios (a no-op child going from
1 ms to 4 ms is a x4 "slowdown" that is only jitter): the child suffers under 10% (and under 30 ms) of nft's extra delay
-> nft alone; 15% or more -> the whole host. These thresholds are heuristics. **The numbers are the ground truth; the
verdict is a convenience.** A daemon that starts under load has no idle baseline until it sees a fast sync, and falls back
to absolute rules until then.

## Does the verdict deserve trust? Test it on your machine

`tools/nft_latency_experiments.py` produces each cause on purpose (real nft, real flock, real load) and shows what the
tool says. It needs root, touches only scratch tables (`coraexp*`), its own cgroup directory and temp files, and removes
them on exit.

```bash
sudo python3 tools/nft_latency_experiments.py            # idle, lock, busy, kernel
sudo python3 tools/nft_latency_experiments.py idle lock --check     # exit 1 if a stalled scenario is named wrongly
```

The `kernel` scenario runs 16 low-priority loaders doing tiny nft transactions in a loop, which queue on the kernel's
commit mutex while leaving the CPU free. Measured on the author's test machine (a **single-core** microVM), twice:

| cause | worst sync | verdict |
|---|---|---|
| idle | 19-26 ms | not slow |
| another process holds the lock | 263-267 ms = lock 248 + nft 14-18 | waiting for the lock |
| host busy, 40 spinning processes | 536-604 ms = nft 536-603; no-op child 59-91 ms | the whole host is slow |
| nft commit contention, CPU free | 244-249 ms = nft 243-248 (slowest call 222-227); no-op child 4-6 ms | points at nft / the kernel path |

**Limits of that evidence.** One core means kernel work and host load are the same resource: an earlier attempt with
30,000-rule transactions (long CPU-bound kernel work) was named "kernel" in one run and "whole host" in the next, which
is physically right for one core and not a clean test. The low-CPU generator avoids it, but more cores separate the two
far better, so run the tool on your own hardware. If its verdict surprises you, the log line and the tool's output are
what to look at.

## Known hazards this did not change

- The tap **lock has no timeout**: a holder that hangs would hang the sync worker (new tasks would then get no tap
  rules, silently apart from the slow-sync note once it finally returns). `cora-run` holds it only for a few nft calls.
- Each nft call has a 10 s timeout, so one call cannot exceed that; a sync is the sum of its calls plus the lock wait.
