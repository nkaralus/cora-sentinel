# Signed community lists: `cora-blocklist sync`

`cora-blocklist pull` / `accept` is for lists you review by hand. `sync` is for the community lists compiled in
[cora-security](https://github.com/nkaralus/cora-security): there, the **owner's offline minisign signature is the
approval**. It writes into the same store, pinned the same way, so `cora-sentinel --blocklist-store` verifies it
exactly like any other list, at start and on every reload.

## Trust chain

```
report issue ─► ingest.yml (schema, scrub, route) ─► owner labels `accepted` ─► compile.yml commits lists + MANIFEST.json
                                                                                        │   (unsigned: nodes wait, exit 11)
Dimgeon (offline key): tools/sign-manifest.sh ─► rebuilds the lists from submissions/accepted/, refuses on any byte
                       of difference ─► minisign ─► commits MANIFEST.json.minisig ─► you push
node: cora-sync.timer ─► sync ─► every check below ─► store ─► systemctl reload cora-sentinel (SIGHUP)
```

GitHub, Actions and the repo's secrets are **not** trusted: none of them can produce a signature. A compromised repo
can only stop updates (nodes keep their last applied set), not change what nodes enforce.

## What `sync` checks, in order (nothing is written until all pass)

| Check | On failure |
|---|---|
| ref resolved to one 40-hex commit; **every** URL pinned to it | error |
| `MANIFEST.json.minisig`: the current epoch's active key id, both Ed25519 signatures (prehashed `ED` or legacy `Ed`) | 11 if it is simply not signed yet / signs an older manifest; error otherwise |
| trusted comment is `cora-manifest repo:nkaralus/cora-security file:MANIFEST.json timestamp:<unix>` | error |
| timestamp **newer** than the last applied one, and not one you rolled back; `generated_from` not older | error (replay) |
| manifest shape; list file names `[a-z0-9][a-z0-9_-]*.txt` only | error |
| each list: sha256 equals the signed manifest, valid text, entry limits | error |
| no name clash with a list `cora-blocklist accept` pinned | error |
| key rotations at that commit (see Keys) | error |
| delta caps against what is active (overridden once after a declared compromise) | **10, held** |

Delta caps: `EMPTIED`, `REMOVED` (a list left the manifest), `LAN` (an entry covers RFC 1918 / CGNAT / link-local /
ULA), `REJECTS UP`, `BURST` (more than 500 entries added at once), and, once a list has 20+ entries, `LARGE CHANGE`
(>50%) and `SHRINK` (lost half). Below 20 entries the percentage rules are off, or every early update would be held.
A held update applies with `cora-blocklist sync --allow-large-change` after you have read why.

## Applying, crashing, rolling back

Apply order: journal ─► `last-good/` snapshot ─► active files ─► `lock.json` (**the commit point**, one rename) ─►
`verify` ─► reload. A crash before the commit leaves files that do not match their pins, so the daemon fails closed
(it refuses those lists, a running one keeps its old ones); the next `sync` sees the journal and restores
`last-good/` **before** fetching anything, so even with the network still down the store is consistent again.
If post-apply `verify` fails, last-good is restored at once.

`cora-blocklist sync-rollback` restores last-good and records that signature's timestamp as refused; only a newer
signature is applied after that. Pins written by `cora-blocklist accept` are never touched by either.

## Keys: two roles, a signed chain

| Key | Signs | Lives |
|---|---|---|
| **active** | manifests only | the signing machine (Dimgeon) |
| **standby** | key rotations only | an encrypted offline USB, plus a printed cold backup |

Nodes pin both at install (`/etc/cora-sentinel/cora-security.pub` and `cora-security.standby.pub`): the **genesis**
pair. The active key can never change keys, so stealing it from Dimgeon cannot lock you out or install the
thief's key. Each sync first looks for `keys/rotation-<epoch+1>.json` (+ `.minisig`) at the same pinned commit:

- it must verify against the **current standby** (signed by the active key: refused), and its trusted comment must
  be `cora-keyrotation repo:nkaralus/cora-security epoch:<n> timestamp:<unix>`, the next epoch exactly
- it must revoke the outgoing active key; the new active and standby must be distinct and never revoked
- the node then trusts `active := old standby`, `standby := the new key`; manifests signed by the standby, or by
  any revoked key, are refused by name. The chain lives in `lock.json` (`cora_keys`) and must start from the
  `/etc` pins; `sync-rollback` never rolls keys back
- a rotation is kept even if the manifest at that commit is not signed yet, and resets the replay counter

**Future skew:** any manifest or rotation signed more than 24 h ahead is refused. Without this, a thief could sign
a manifest dated far in the future and make every real update look like a replay, forever; with it, the worst is
24 h, and a rotation clears even that.

**Compromise:** a rotation with `compromised_after: T` marks any applied community list signed after `T` (by the
key it revokes) as **tainted**: those lists and `last-good/` are removed at once, and the next manifest signed by
the new active key applies **over the delta caps** (decision (a): your revocation is a deliberate override).

## Runbooks

**Planned rotation, or the active key is lost (not leaked)**
```bash
minisign -G -p /media/usb/next.pub -s /media/usb/next.key          # the NEXT standby, generated on the USB
tools/sign-rotation.sh --standby-key /media/usb/cora-security.standby.key --new-standby-pub /media/usb/next.pub
cp /media/usb/cora-security.standby.key ~/.minisign/cora-security.key  # old standby is the active key now
tools/sign-manifest.sh && git push                                  # rotation + manifest, pushed TOGETHER
```
Push them together: a node that sees the rotation alone refuses the old manifest as signed by a revoked key.

**Active key stolen**
```bash
git log -p --format= -- blocklists/MANIFEST.json.minisig | grep '^+trusted comment'   # find your last honest T
git revert <the thief's commits> && git push
# then the planned-rotation steps, adding:  --compromised-after T
```

**Both keys gone:** generate a new pair, and re-pin `/etc` on every node by hand; delete `cora_keys` from each
node's `lock.json` (`cora-blocklist sync` refuses a chain that does not start from the new pins, by design).

## Exit codes

`0` in sync (applied or unchanged) · `10` held by a delta cap · `11` awaiting a valid signature · `1` error.
The unit treats 10 and 11 as success; `journalctl -u cora-sync` says which.

## Set up

On the signing machine (once):

```bash
minisign -G -p keys/cora-security.pub -s ~/.minisign/cora-security.key   # keep the password; back the key up OFFLINE
git add keys/cora-security.pub && git commit -m "keys: minisign public key" && git push
tools/sign-manifest.sh && git push                                       # after every accepted report
```

Losing the secret key means re-pinning every node. Never put it in a repo secret: that is option A, rejected.

On each node:

```bash
sudo deploy/install-service.sh                         # installs cora-sync.service + .timer, enables nothing
sudo install -o root -g root -m 0644 cora-security.pub         /etc/cora-sentinel/cora-security.pub
sudo install -o root -g root -m 0644 cora-security.standby.pub /etc/cora-sentinel/cora-security.standby.pub
#   ^ copy it from the signing machine or check its key id against one you trust. Fetching it from the same
#     repo the lists come from would make the repo the root of trust again.
# add to CORA_ARGS in /etc/cora-sentinel/cora-sentinel.conf:  --blocklist-store /var/lib/cora-sentinel/blocklists
sudo systemctl restart cora-sentinel
sudo cora-blocklist --dir /var/lib/cora-sentinel/blocklists sync --dry-run
sudo systemctl enable --now cora-sync.timer
```

## Limits

- **Signing is the review.** The signer refuses lists that do not rebuild from `submissions/accepted/`, but a bad
  report you accepted rebuilds fine. Read what you sign; delta caps catch the loud mistakes only.
- **Freshness is not enforced**, only order: a node that cannot reach GitHub keeps enforcing its last set, and
  `cora-blocklist status` shows its age.
- The ed25519 code is RFC 8032 in plain integers (verify only, not constant-time; it handles only public data).
  It is checked against the RFC vectors and against real `minisign 0.11` output in `tests/fixtures/minisign/`.
- Two signatures in the same second share a timestamp; the second is refused as a replay. Sign once.
