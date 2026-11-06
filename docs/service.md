# Running cora-sentinel as a service

```bash
sudo ./venv/bin/pip install -e .                       # or your wheel; the binaries must exist first
sudo deploy/install-service.sh --bindir "$PWD/venv/bin"
sudoedit /etc/cora-sentinel/cora-sentinel.conf          # one CORA_ARGS line
sudo systemctl enable --now cora-sentinel
sudo cora-floor confirm                                 # inside the --floor-confirm window (first start only)
journalctl -u cora-sentinel -f
```

**From the `.deb`** (`sudo dpkg -i cora-sentinel_*_all.deb`, built by `packaging/build_release.sh`) there is no installer step:
the unit, the config and the log rotation are installed for you, and nothing is started. Everything below applies the
same way; see [packaging.md](packaging.md) for what install, upgrade, remove and purge do (removal takes the kernel floor
out, purge keeps the audit logs) and for running the model.

The installer writes the unit with your `--bindir`, installs the config only if you have none (a reinstall never
overwrites your edits), and does **not** enable or start anything. `deploy/install-service.sh --uninstall` removes the
unit and leaves your config and `/var/lib/cora-sentinel` alone.

## The first start, and not locking yourself out

The kernel floor is host-wide and outlives the daemon, so two safeguards stand between a bad list and a lost session.

**Pre-check.** Before installing the floor, and before applying every hot reload, the daemon finds the default
gateway(s) and the live SSH peers (established connections to port 22, plus the client and port in `$SSH_CONNECTION`,
read from `/proc`) and refuses if the lists would drop one of them:

```
refusing to install the floor, it would drop: 192.168.1.50 (established session to port 22) is inside 192.168.1.0/24.
Allow them (--floor-allow ADDR or --floor-allow-detected), fix the list, or pass --no-floor-precheck
```

A reload that would do this is refused and the previous sets stay. An address you allow always wins over the lists.
`--floor-allow-detected` allows the detected addresses automatically instead of refusing.
SSH on a non-standard port is only seen when the daemon was started from that session; under systemd, add
`--floor-allow` for your management network.

**Dead-man (`--floor-confirm SECONDS`).** The floor is installed with a rollback timer. Run `sudo cora-floor confirm`
within the window to keep it; otherwise it is removed and the daemon carries on without it, saying so loudly. The
timer is a separate, detached process that is started and seen to be running *before* the floor goes in, so a daemon
that crashes or is killed cannot leave an unconfirmed floor behind. If that process cannot start, the floor is not
installed.

You are asked **once per allow set**. A restart or a reboot with the same configured allow set (loopback,
`--floor-allow`, the blocklist allow list) does not ask again, so an unattended `Restart=on-failure` never removes
protection behind your back. Resolvers (they follow DHCP) and detected peers are not part of what you confirmed.
Change the allow set and the next start asks again; `cora-floor unconfirm` brings the prompt back on purpose.

If you are locked out anyway: wait for the window. The floor removes itself.

## If the service runs with the wrong arguments

The arguments come from `CORA_ARGS` in `/etc/cora-sentinel/cora-sentinel.conf`, and systemd's `EnvironmentFile` does **no shell
expansion and no quoting**: `$HOME`, `${VAR}`, `$(cmd)` and backticks reach the daemon as literal text, and `--model "/a b.gguf"`
reaches it as the tokens `"/a` and `b.gguf"` with the quote marks still on. The daemon used to run with whatever it got.

- **It says what it got.** The first line it prints is `[cora-sentinel] VERSION starting with: ARGS`, quoted so a value split at a
  space is visible: `journalctl -u cora-sentinel -b | grep "starting with"`. The same truth from the kernel's side:
  `tr '\0' ' ' < /proc/$(systemctl show -p MainPID --value cora-sentinel)/cmdline`.
- **It refuses the likely mistakes.** An argument containing `$VAR`, `${...}`, `$(...)` or a backtick, or with a quote mark stuck
  to it, makes it exit with status **2** before it opens any file, naming the argument. The packaged unit does not restart on status
  2 (`RestartPreventExitStatus=2`), so a bad config fails once, loudly, instead of looping into the start limit. A `~` is not
  refused (the daemon expands it itself). If a literal `$` or quote mark really is meant, pass `--allow-shell-chars`.
- Check a change before restarting: `cora-sentinel --out '$HOME/x'` shows the refusal in a terminal.

## What happens when

| Event | Confirmed floor | Unconfirmed floor |
|---|---|---|
| `systemctl stop` / `restart` | stays | removed by `ExecStopPost` (`cora-floor rollback`) |
| daemon crash | stays; restarts after 5 s | removed, then the restart asks again |
| daemon killed with `kill -9` outside systemd | stays | the watchdog removes it at the deadline |
| reboot | gone with the kernel state; reinstalled at start, no prompt if the allow set is unchanged | gone |
| `systemctl reload` (SIGHUP) | blocklist files re-read, sets updated in one transaction per set pair | same |
| 5 failed starts in 5 minutes | systemd stops retrying (`StartLimitBurst`); read the journal | |

Per-task `ISOLATE` rules and task cgroups also survive the daemon, as they do without systemd.

## Things to know

- **`nftables.service` and `flush ruleset`.** If you use it, `/etc/nftables.conf` usually starts with `flush ruleset`.
  The unit starts after `nftables.service` so it cannot wipe the floor at boot, but `systemctl reload nftables` later
  will. Restart `cora-sentinel` after reloading nftables (the confirmed allow set means no prompt).
- **Taking the floor out.** `sudo cora-floor remove` (floor only) or `sudo cora-firewall purge` (the whole table).
  `deploy/install-service.sh --uninstall --remove-floor` does the former. Nothing re-creates it behind your back.
- **State.** `/var/lib/cora-sentinel` (mode 0700): the confirmed allow-set fingerprint and any pending confirmation.
  `cora-floor status` shows whether a confirmation is pending and how long is left.
- **Hardening is light** (`NoNewPrivileges`, `ProtectSystem=full`): the daemon needs root powers over cgroups,
  nftables and netlink. It is not sandboxed further.
