# Time to containment

How long from a task's first packet to a listed address until its egress is actually cut?

## What it was, and what it is

| | measured from the task (first packet -> first `EPERM`) |
|---|---|
| before (the model decides, then the task is isolated) | **1,505-1,507 ms** with a 1.5 s model; **2,006 ms** with a 2.0 s model |
| now (a blocklist hit is isolated at once) | **5-6 ms** (1.5 s model); median **4 ms**, p99 6 ms (2.0 s model, 5 trials) |

Measured on a single-core test machine with a fake model; `tools/containment_latency.py --model your.gguf` measures it
with your real model on your machine. The probe sends one datagram per millisecond, so the numbers have about 1 ms of
resolution.

The enforcement step itself (`Firewall.block`) was already about 1.5 ms. The rest of the 2-4 s was the **model**: the
adjudicator called it first, then applied the floor, then the gate, then the action.

## What changed

`Adjudicator.submit()` (called from the sentinel's delivery thread) now isolates the task of a **blocklist hit** before
the event is queued behind the model, using the same gate `handle()` uses. The model still judges the event afterwards and
can still escalate. `--no-contain-first` restores the old order.

Why this is safe to do early: the blocklist floor already guarantees *at least* `ISOLATE` for these events whatever the
model says (it upgrades `ALLOW`, `THROTTLE` and `ESCALATE`; the code comment is "the model may only escalate from
here"). So early isolation changes when, not whether.

### One behavior difference: stricter, never weaker

Where the model itself escalates past the floor, `SUSPEND` or `TERMINATE`, the floor used to add nothing, so the task
ended up frozen or killed with **no egress rule**. Now it also carries the egress drop. A killed task's rule is
garbage-collected; a frozen task that a person thaws stays network-cut until it is released (`cora-cgroup release`). For
every other model verdict the end state is identical. A test pins exactly this relationship for all six verdicts.

## A second problem this fixes: the queue failed open

The adjudicator is one thread with a 32-slot queue, and each event takes the model's 2-4 s. `submit()` used to print
"queue full, event dropped" and discard the event, so in a burst of more than about 33 known-bad events, the rest were
**never contained at all**, not merely late. Now:

- a blocklist hit is contained *before* it reaches the queue, so a full queue cannot lose its containment;
- a dropped event is counted (`Adjudicator.dropped`), written to the decision log (`queue_dropped: true`, with the
  containment it got), and logged as "its task was already contained at the policy floor" or **"AND NOT CONTAINED"**.

## What it does not do

- **The first packet still leaves.** The tap logs a packet; it does not hold it. This change cuts everything *after* the
  first packet within milliseconds. Preventing the first packet needs the listed addresses in the kernel (an nft set matched
  on the task's cgroup, dropped in the same hook) so no userspace round trip is involved. That would be a separate step.
- **Only blocklist hits.** Model-only detections (paths, memory, policy) still wait for the model, one at a time, and a
  full queue still drops them. That is now loud and recorded as `DROPPED` instead of silent, but not solved.
- The numbers above are from a test machine with a fake model. On real hardware they depend on the model for the OFF
  case and on the tap, the gate and one nft commit for the ON case.

## In the logs

Each decision for a contained event carries `contained_first` (the early action, its gate result, how long the action
took, and ms since the tap first saw it) and `contained_ms` (first seen -> first containment, whichever path got there).
Events carry `timing.seen_mono_s`, a process-local monotonic timestamp: only differences are meaningful. It is not part
of what the model is shown, and it is not in the anonymized reports.

## Measuring it

```bash
sudo python3 tools/containment_latency.py                          # a fake model that takes 2.0 s
sudo python3 tools/containment_latency.py --model ~/models/q.gguf  # your real model (needs llama-cpp-python)
sudo python3 tools/containment_latency.py --check                  # exit 1 if floor-first is not clearly faster
```

It starts real tasks with `cora-run`, runs the whole pipeline in-process, and alternates floor-first ON and OFF so
drift affects both. It touches only a scratch nft table (`coralat*`), its own cgroup directory and the documentation
address 203.0.113.1, and removes them on exit.
