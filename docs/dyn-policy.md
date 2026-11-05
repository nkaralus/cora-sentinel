# Dynamic policy: model verdicts into kernel drops

When the model isolates a task for talking to a public address, the next task to reach that address would still get its
first packet out. `--dyn-policy` turns the verdict into a short-lived, host-wide kernel drop of that **destination**
(the `dyn4/6` and `dynflow4/6` sets from the kernel floor). It is the riskiest thing the daemon does, so it ships in
**shadow** and is boring and bounded on purpose.

```bash
cora-sentinel ... --model m.gguf                          # shadow is the default: decisions.jsonl gains a "dyn" field
cora-floor dyn-report sentinel_decisions.jsonl            # after a week: what it WOULD have blocked
cora-floor dyn                                            # the ledger: active blocks (or would-be blocks) and why
cora-sentinel ... --model m.gguf --enforce --floor --dyn-policy enforce
```

## Why it is cautious

The model is a 3B network of text, and a task controls both the address it connects to and the text the model reads
(DNS names, its command line). A hostile task could try to talk the model into isolating it *because* it touched a
victim address, and cutting that address off for the whole host. Everything below limits that blast radius. The target
always comes from the event's evidence, never from the model.

## Modes

| Mode | Kernel | Ledger | Notes |
|---|---|---|---|
| `off` | untouched | none | |
| `shadow` (default) | untouched | `dyn-ledger-shadow.json` | computes budgets, escalation and promotion exactly as enforce would, and records `would_block` etc. |
| `enforce` | writes | `dyn-ledger-enforce.json` | needs `--model`, `--enforce`, `--floor`. Stays in shadow for any decision the adjudicator only dry-ran. |

Shadow only does anything when there is an adjudicator (`--model`).

## Who is eligible

All of these, or the decision gets a `skipped` record with the reason and nothing is written:

- the **model** chose ISOLATE (not the blocklist floor: those addresses are already in the static sets), at confidence
  of at least `--dyn-min-conf` (0.9), the gate passed and the action ran. **ESCALATE never writes**: "needs a human"
  must not become a host-wide kernel drop;
- the destination is public and global, not allowed (`--floor-allow`, resolvers, the blocklist allow list) and not
  protected (default gateway, live SSH peers);
- the port is not infrastructure: DNS (53, 853) and NTP (123). A task using another public resolver must not make the
  host lose DNS.

## What it blocks

| | First sighting | Repeat offense | Whole address (`dyn4/6`) |
|---|---|---|---|
| **80 / 443** (tcp and udp) | the flow, 10 min | x4, up to 24 h | **never** |
| **other ports** | the flow, 10 min | x4, up to 24 h | after **2 distinct tasks** on non-web ports of it within an hour: 30 min, x4, up to 24 h |

A *flow* is (address, protocol, port). A *repeat offense* is a hit after the block expired, or a different task hitting
it while active (the same task again is a no-op). On web ports a flow block is nearly as wide as an address block: nft
cannot see SNI or Host, and QUIC names are not recoverable, so it hits every site behind a shared address. The safety
there is the TTL, the budgets and shadow mode. To block a web address for good, use the blocklist path with a human in
the loop.

## Limits

20 kernel writes per minute (token bucket; a repeat offense spends one too), 512 live elements, 8 distinct targets per
task per hour (so one noisy task cannot block the internet one verdict at a time). A denied decision records why
(`budget`, `standing_cap`, `task_cap`). Tune with `--dyn-write-budget`, `--dyn-max-live`, `--dyn-task-cap`.
The kernel expires every element itself; there is no cleanup thread.

## Undo

`cora-firewall release TASK` also drops what that task alone caused: its flow blocks, and a whole-address block that no
longer has two distinct tasks behind it (it is demoted). Blocks another task independently caused stay. A false positive
leaves no offense history. The promoting hit never had a flow entry of its own, so after a demotion its destination is
blocked again (flow level, offense 1) on its next event. If the kernel refuses an unblock the entry is kept and the
output says `dyn-unblock-FAILED`.

## The ledger

JSON in `--state-dir` (default `/var/lib/cora-sentinel`, mode 0700), one file per mode, under a `flock` because
`cora-firewall release` is a different process from the daemon. It holds the blocks, the offense memory (7 days), the
promotion window, the budget bucket and the per-task counters. An unwritable state directory falls back to memory with
a warning; a corrupt file is set aside as `.corrupt` and replaced. The daemon reconciles it against the kernel at start
and hourly, so an element an operator removed by hand is not remembered as blocked. It is rewritten on every decision,
so its cost grows with its size (about 1 ms empty, about 7 ms at 500 entries on the development machine:
`python tools/dyn_bench.py`), which is small next to a 2-4 s model call.

## Reviewing shadow data before enforcing

```bash
cora-floor dyn-report sentinel_decisions.jsonl
```

Read it for: **targets on web ports** (the shared-address risk: would any of them have been a CDN you use?), the
`skipped` reasons (a lot of `low_confidence` means the threshold is doing the work; `budget` or `task_cap` means a
noisy task), and how often a repeat offense escalated. Switch to `enforce` when nothing in the would-block list is an
address you would be unhappy to lose.
