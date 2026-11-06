#!/usr/bin/env bash
# Install or remove the cora-sentinel systemd unit. It never enables or starts the service for you.
#
#   sudo deploy/install-service.sh [--bindir DIR]       install (default DIR: where `cora-sentinel` is on PATH)
#   sudo deploy/install-service.sh --uninstall [--remove-floor]
#
# CORA_ROOT=/some/prefix installs under that prefix and skips systemctl (used by the tests).
set -euo pipefail

root="${CORA_ROOT:-}"
unit_dir="$root/etc/systemd/system"
conf_dir="$root/etc/cora-sentinel"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bindir="" mode=install remove_floor=no

while [ $# -gt 0 ]; do
  case "$1" in
    --bindir) bindir="${2:?--bindir needs a directory}"; shift 2 ;;
    --uninstall) mode=uninstall; shift ;;
    --remove-floor) remove_floor=yes; shift ;;
    -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
sc() { [ -n "$root" ] || systemctl "$@"; }

if [ "$mode" = uninstall ]; then
  sc disable --now cora-sentinel 2>/dev/null || true
  rm -f "$unit_dir/cora-sentinel.service" "$root/etc/logrotate.d/cora-sentinel"
  sc daemon-reload
  if [ "$remove_floor" = yes ]; then
    floor="$(command -v cora-floor || true)"
    [ -n "$bindir" ] && floor="$bindir/cora-floor"
    [ -n "$floor" ] && "$floor" remove || echo "cora-floor not found; remove the floor yourself" >&2
  else
    echo "The kernel floor is still in place if it was confirmed. Remove it with: cora-floor remove"
  fi
  echo "Unit removed. $conf_dir and /var/lib/cora-sentinel are left alone."
  exit 0
fi

[ -n "$bindir" ] || bindir="$(dirname "$(command -v cora-sentinel || true)")"
for exe in cora-sentinel cora-floor; do
  [ -x "$bindir/$exe" ] || { echo "$bindir/$exe not found: pip install the package first, or pass --bindir" >&2; exit 1; }
done
bindir="$(cd "$bindir" && pwd)"

install -d -m 0755 "$unit_dir" "$conf_dir"
sed "s|@BINDIR@|$bindir|g" "$here/cora-sentinel.service" > "$unit_dir/cora-sentinel.service"
chmod 0644 "$unit_dir/cora-sentinel.service"
install -d -m 0755 "$root/etc/logrotate.d"
install -m 0644 "$here/cora-sentinel.logrotate" "$root/etc/logrotate.d/cora-sentinel"
if [ -e "$conf_dir/cora-sentinel.conf" ]; then
  echo "kept your existing $conf_dir/cora-sentinel.conf"
else
  install -m 0640 "$here/cora-sentinel.conf" "$conf_dir/cora-sentinel.conf"
fi
# The directories the suggested --blocklist / --blocklist-allow flags point at. Without them the daemon exits at start with
# "[Errno 2] No such file or directory". Each gets an INERT template (it blocks and allows nothing) only if it holds no file yet.
for d in blocklists allow; do
  install -d -m 0755 "$conf_dir/$d"
  if [ -z "$(find "$conf_dir/$d" -maxdepth 1 -type f -print -quit)" ]; then
    install -m 0644 "$here/seed/$d/00-local.txt" "$conf_dir/$d/00-local.txt"
  fi
done
sc daemon-reload
cat <<MSG
Installed $unit_dir/cora-sentinel.service (binaries in $bindir) and the log rotation in $root/etc/logrotate.d/.
The list directories $conf_dir/blocklists and $conf_dir/allow exist (an inert template in each), for --blocklist and --blocklist-allow.
Next:
  1. Edit $conf_dir/cora-sentinel.conf
  2. systemctl enable --now cora-sentinel
  3. cora-floor confirm        # within the --floor-confirm window, the first time (and when the allow set changes)
  Logs: journalctl -u cora-sentinel -f
MSG
