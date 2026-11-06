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

Shadow only does anything when there is an adjudicator (`--model`), and only for tasks it can actually isolate: ISOLATE
needs a cgroup **and** nft, so the daemon must have `--nft --cgroup-root` (the shipped config does). Without them every
ISOLATE becomes an ESCALATE and the log simply has no `dyn` records. It does not need `--enforce`: a dry-running
adjudicator records `would_*` too. Collect shadow data in the adjudicator mode you will actually run, because an enforcing
one stops a task's further events (it is isolated) and a dry-running one does not (more repeat hits, more `dedupe`).

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

## Deploying in shadow

Add the model (and your lists) to `CORA_ARGS` in `/etc/cora-sentinel/cora-sentinel.conf`, then `systemctl restart`:

```
CORA_ARGS=--cgroup-root /sys/fs/cgroup/cora --nft --nflog --floor --floor-confirm 120 --model /var/lib/cora-sentinel/models/qwen2.5-3b-instruct-q4_k_m.gguf --blocklist /etc/cora-sentinel/blocklists --out /var/log/cora-sentinel/events.jsonl --decisions /var/log/cora-sentinel/decisions.jsonl --report-dir /var/lib/cora-sentinel/reports
```

`--dyn-policy` is not needed: shadow is the default. The line `dyn policy: shadow` appears in the journal at start.
The decision log is `/var/log/cora-sentinel/decisions.jsonl`, rotated by size (the installer adds the logrotate config);
across rotations: `zcat -f /var/log/cora-sentinel/decisions.jsonl* | cora-floor dyn-report /dev/stdin`.
Anything in the report with `no_destination` or `bad_flow` means an event had a shape the policy did not expect: report it.
`--floor` is separate from the dynamic policy (it enforces your static lists); drop it for a purely observational run.

## Rehearsing against recorded data (`cora-floor dyn-replay`)

Shadow mode records what the policy decided; `dyn-replay` lets you ask "what if" about it without waiting another week.
It feeds every recorded ISOLATE back through the real policy code with a clock that follows the recorded timestamps, so
TTLs expire, budgets refill and windows slide as they did, in seconds.

```bash
cora-floor dyn-replay /var/log/cora-sentinel/decisions.jsonl                          # events.jsonl is found next to it
zcat -f /var/log/cora-sentinel/decisions.jsonl* | cora-floor dyn-replay - \
    --events /var/log/cora-sentinel/events.jsonl --events /var/log/cora-sentinel/events.jsonl.1   # across rotations
cora-floor dyn-replay decisions.jsonl --task-cap 4 --write-budget 10                  # B (your settings) vs A (defaults)
cora-floor dyn-replay decisions.jsonl --check                                         # does it reproduce the live record?
```

**Both logs are needed.** A decision has the verdict, the action, the time and what the live policy did, but not the
destination or the task. Those are in the event (`events.jsonl`, the daemon's `--out`), joined on `event_id`. Rotated and
`.gz` files are fine, and so are several of each; `-` reads stdin. `--since` / `--until` take an ISO time (UTC if no offset).

**Worlds.** *Rehearse* (default) answers "what would **enforce** have done?": the adjudicator is assumed to be enforcing,
so a dry-run ISOLATE counts as done, and once a task is isolated its later events are dropped (an isolated task has no
egress, so a shadow log taken with a dry-running adjudicator holds events enforce would never have seen;
`--keep-isolated` keeps them). `--as-recorded` makes no assumptions: the recorded actions, the policy in shadow.
`--check` is `--as-recorded` plus a decision-by-decision comparison with the `dyn` record the live policy wrote, with exit
status 1 on any mismatch: it is how you know the harness reproduces your daemon, and how you notice drift after an
upgrade. In these two modes the policy flags are **not** a tweak; they tell the replay the settings your live daemon runs
with (`--check --dyn-task-cap` is `--check --task-cap`), because a log written under one setting cannot match a replay
under another.

**What it prints:** results by kind; the skip reasons; the three limits (write budget with its peak per minute and
denials, live elements, per-task cap with the busiest task); the **web ports** section (flow blocks, repeat-offense
refreshes, distinct targets, and promotions to a whole address, which must be 0); the targets that would have been
blocked longest, with exact blocked time; `--timeline` per hour; and with tweaks a diff of every decision that changed.
`--json` is the same data (`--outcomes` adds every decision).

**Kernel mode.** If root, nft and `unshare` are available, every write is also made in a private network namespace and a
throwaway table (never the host's), and at the end the real nft state is cross-checked against the policy's ledger.
Kernel timeouts run in real time, so elements are written with the longest timeout and removed at their *simulated*
expiry. The decisions are identical with or without it; it proves each write is accepted by nft and reports the cost.
`--kernel off` skips it. The replay never touches the live ledger or the live ruleset.

**Exit status.** 0 ok; 1 `--check` found a mismatch; 2 a self-check failed (a web port was promoted, which the replay
detects independently of the policy's own flag, or the sets disagree with the ledger) or the input was unusable.

**What it cannot do.** It does not re-run the model: verdicts and confidences are as recorded, so `--min-conf` filters them
but a different model or prompt cannot be rehearsed. The live allow list and protected addresses at the time are not
recoverable, so exemptions come from what the live policy recorded for each decision, plus `--allow` / `--protect`. Time has
one-second resolution (the decision log's), and history before the first logged decision is unknown, so the first
decisions after a log rotation may not match under `--check`. Releases (`cora-firewall release`) and manual unblocks are
not in the log and are not replayed. The escalation factor (x4, 24 h cap) and the web-port list are fixed in the code.
