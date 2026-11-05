# Keeping blocklists current: pinned and reviewed

`cora-blocklist` can pull lists from a URL (for example the `cora-security` repo) **without ever letting the
network change what the sentinel enforces on its own.** A list that blocks things is a list that can quarantine
your tasks, because a blocklist hit becomes `ISOLATE` by default. So an update is a *proposal* you approve.

## The rule

```
sources.json (you edit)           lock.json (pins; written ONLY by `accept`)
      │                                   │
pull ─┴─► fetch ─► validate ─► same sha256 as the pin?
          https,     size,        yes ─► unchanged   (active file restored if it was tampered with)
          limits     NULs         no  ─► STAGED, never active
diff   ─► what would change, and red flags
accept ─► you retype the first 12 hex of the staged file's sha256 ─► it becomes active, the pin moves
verify ─► every active file must hash to its pin;   cora-sentinel --blocklist-store refuses to start otherwise
```

## Commands

```bash
cora-blocklist --dir /var/lib/cora-sentinel/blocklists pull          # fetch every source; stage what changed
cora-blocklist diff [NAME]                                           # review: counts, +/- entries, FLAGS
cora-blocklist accept NAME --sha256 <first 12 hex> [--allow-large-change]
cora-blocklist status                                                # pinned / staged / stale
cora-blocklist verify                                                # exit 1 if anything is not what was approved
cora-sentinel --blocklist-store /var/lib/cora-sentinel/blocklists ...
```

`--dir` defaults to `$CORA_BLOCKLIST_DIR`, else `/var/lib/cora-sentinel/blocklists` as root, else
`~/.local/share/cora-sentinel/blocklists`. `pull` exits **0** (nothing to review), **10** (changes staged, review
them) or **1** (an error). `accept` activates a list; the running daemon picks it up on `kill -HUP` (below) or at its next start.

## What `diff` flags (and what blocks `accept`)

| Flag | Meaning | Blocks accept? |
|---|---|---|
| `NEW LIST` | first time you see it | no (review it: this is the trust-on-first-use moment) |
| `LARGE CHANGE` | more than 50% of the entries were added or removed | **yes** |
| `SHRINK` / `EMPTIED` | the list lost half its entries, or all of them (silently disables detection) | **yes** |
| `LAN` | a new entry covers your own network (RFC 1918, 100.64/10, link-local, ULA) | **yes** |
| `REJECTS UP` | many more malformed or over-broad lines than before (`0.0.0.0/0`, loopback, ...) | **yes** |
| `URL CHANGED` | the source URL moved, even if the bytes are identical | **yes** |

`--allow-large-change` overrides all of them, deliberately: you have to have read the diff to know why.

## Limits

| Limit | Value |
|---|---|
| Download size | 5 MiB per list by default; `max_bytes` per list, never above 50 MiB; aborted *at* the limit |
| Download time | 20 s per socket operation, 60 s for the whole download (a server that trickles cannot hold it open) |
| Redirects | at most 3, and **never to a non-https URL** |
| Content | UTF-8 text, no NUL bytes, at most 500,000 lines of at most 4,096 characters, 200,000 entries |
| Store | refused if it is a symlink, world-writable, or (as root) group-writable or not owned by root |

TLS is always verified against the system trust store; there is no way to turn that off.

## Set it up

1. Publish the lists in `cora-security` (see below), then note the commit: `git rev-parse HEAD`.
2. Write `sources.json`, with a **40-hex commit in each URL** (see `examples/sources.json`). A commit URL never
   changes under you, so "updating" is bumping the commit, which is itself a reviewed edit. A `main` URL works but
   `pull` warns that it is mutable.
3. `cora-blocklist pull`, then `diff`, then `accept` each list. Run `cora-sentinel --blocklist-store DIR`.

Run `pull` from cron or a timer; exit code 10 means "a human has something to review". An example (**not tested**):

```ini
# /etc/systemd/system/cora-blocklist-pull.service
[Service]
Type=oneshot
ExecStart=/opt/cora/venv/bin/cora-blocklist pull
SuccessExitStatus=10
# /etc/systemd/system/cora-blocklist-pull.timer: OnCalendar=weekly, Persistent=true
```

## What this does not do

- **No signatures.** The standard library has no ed25519 or GPG, so the trust is "TLS + a pinned hash + a human".
- **A reasonable-looking bad change passes** if you approve it. The flags catch the loud failures, not the subtle ones.
- **A malicious first fetch** is trusted if you approve it: read the first diff.
- **Root can edit the lock.** This protects against the network and against other users, not against root.
- **Staleness is only noticed at startup** (a list approved more than 30 days ago is warned about then).

## Applying an update without restarting: `SIGHUP`

```bash
cora-blocklist accept ads --sha256 <first 12 hex>
kill -HUP <cora-sentinel pid>          # systemd: ExecReload=/bin/kill -HUP $MAINPID, then `systemctl reload`
```

The daemon re-reads **the same `--blocklist`, `--blocklist-store` and `--blocklist-allow` arguments it started with**
(a store is verified exactly as at startup). **Only the lists change**: the tap rules (the very same nft rule
handles), the netlink sockets, cgroup tracking, firewall rules and the model are untouched, so no flow is missed
and no task is forgotten. Every other option needs a restart.

| Situation | What happens | Why |
|---|---|---|
| The new lists cannot be loaded (store fails verification, unreadable file) | `reload FAILED, keeping the previous lists` | a reload never leaves you with no list, or half of one |
| The new lists are **empty** and the current ones are not | `reload REFUSED`; restart if you really want none | deleted files or a missing mount must not silently disable detection |
| New domains | resolved **at once**, not at the next hourly cycle | otherwise their addresses go unmatched for up to an hour |
| Domains kept | their resolved addresses carry over **before** the swap | a plain swap would drop every CDN-address match until the next cycle |
| Domains removed | stop matching immediately | |
| Several HUPs in a row | one more reload, not a pile-up | |

Each reload logs a line such as `reloaded blocklists: domains 15 -> 16 (+1/-0), subnets/IPs 3 -> 3 (+0/-0), 58
resolved addresses carried over`.

**Behavior change:** `SIGHUP` used to terminate the daemon. Now it reloads (or, with no lists configured, is logged
and ignored). Closing the terminal of a foreground daemon therefore no longer stops it; run it under systemd, or
stop it with SIGINT/SIGTERM. A reload of a large list makes the resolver look up its new names straight away
(up to `--resolve-max`, through your system resolver).

## Publishing the starter lists to `cora-security`

This repo ships starter lists in `examples/blocklists/`. As of this writing the `cora-security` repo does **not**
contain them (its history has only `README.md`, `allow/exceptions.txt`, `examples/violation.example.json` and
`violation.schema.json`). To publish them:

```bash
cd cora-security
mkdir -p blocklists docs
cp /path/to/cora-sentinel/examples/blocklists/* blocklists/
cp /path/to/cora-sentinel/docs/violation-reports.md docs/
git add blocklists docs && git status --short            # expect 4 new files
git commit -m "Add starter blocklists and report docs" && git push
git ls-tree -r origin/main --name-only                   # confirm, then:  git rev-parse HEAD   (the commit to pin)
```
