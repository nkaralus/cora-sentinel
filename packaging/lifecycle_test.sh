#!/usr/bin/env bash
# Real install -> reinstall(upgrade) -> remove -> purge of the .deb, with assertions.
#
#   sudo CORA_LIFECYCLE_TEST=disposable-machine packaging/lifecycle_test.sh dist/cora-sentinel_X_all.deb
#
# DESTRUCTIVE: removing the package stops the cora-sentinel service and removes the kernel floor, which is exactly what it
# is meant to verify. Run it ONLY on a disposable VM or container. It refuses on a machine that looks like it is running
# cora-sentinel (package installed, service active, nft table, config or state present) and without the token above.
set -uo pipefail

deb="${1:-}"
die() { echo "REFUSING: $*" >&2; exit 2; }
[ -n "$deb" ] && [ -f "$deb" ] || die "usage: lifecycle_test.sh PACKAGE.deb"
[ "$(id -u)" = 0 ] || die "run as root"
[ "${CORA_LIFECYCLE_TEST:-}" = "disposable-machine" ] || die "set CORA_LIFECYCLE_TEST=disposable-machine (this removes a kernel floor and stops the service)"
command -v dpkg >/dev/null || die "needs dpkg"
dpkg -s cora-sentinel >/dev/null 2>&1 && die "cora-sentinel is already installed here"
command -v systemctl >/dev/null && systemctl is-active --quiet cora-sentinel 2>/dev/null && die "a cora-sentinel service is running here"
command -v nft >/dev/null && nft list table inet cora >/dev/null 2>&1 && die "an nft table 'inet cora' exists here"
for d in /etc/cora-sentinel /var/lib/cora-sentinel /var/log/cora-sentinel; do [ -e "$d" ] && die "$d exists"; done

export DEBIAN_FRONTEND=noninteractive
fail=0
ok()  { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; fail=$((fail + 1)); }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
floor_up() { nft list chain inet cora floor_in >/dev/null 2>&1; }
gone() { ! "$@" >/dev/null 2>&1; }

echo "== install"
out="$(dpkg -i "$deb" 2>&1)"; rc=$?
[ $rc = 0 ] && ok "dpkg -i" || { bad "dpkg -i: $out"; exit 1; }
grep -q "NOT started" <<<"$out" && ok "tells you it did not start the service" || bad "no 'NOT started' notice"
for f in /usr/bin/cora-sentinel /usr/bin/cora-floor /usr/lib/systemd/system/cora-sentinel.service /etc/cora-sentinel/cora-sentinel.conf \
         /etc/logrotate.d/cora-sentinel /usr/lib/python3/dist-packages/cora_sentinel/_vendor/subnetbus/VENDOR.lock \
         /usr/share/doc/cora-sentinel/copyright; do check "present: $f" test -e "$f"; done
where="$(cd / && python3 -c 'import cora_sentinel; print(cora_sentinel.__file__)' 2>&1)"
case "$where" in /usr/lib/python3/dist-packages/*) ok "python3 imports the packaged copy";; *) bad "python3 imports $where (something shadows the package)";; esac
sc="$(cd / && cora-selfcheck 2>&1)"          # captured, not piped into grep -q: SIGPIPE + pipefail would fake a failure
grep -q "ok .*vendored subnetbus .* verified" <<<"$sc" && ok "cora-selfcheck: vendored gate verified" || bad "cora-selfcheck did not verify the vendored gate"
for d in blocklists allow; do check "list directory and its template: /etc/cora-sentinel/$d" test -s "/etc/cora-sentinel/$d/00-local.txt"; done
lists="$(cd / && python3 -c 'from cora_sentinel.blocklist import Blocklist
b = Blocklist(); b.load("/etc/cora-sentinel/blocklists"); a = Blocklist(); a.load("/etc/cora-sentinel/allow"); print("loaded", b.entries(), a.entries())' 2>&1)"
grep -q "^loaded (set(), set()) (set(), set())" <<<"$lists" && ok "the --blocklist and --blocklist-allow directories load, and hold nothing" || bad "list directories: $lists"
# a minimal image may path-exclude /usr/share/doc and /usr/share/man (dpkg then reports them missing); nothing else may be reported
v="$(dpkg -V cora-sentinel | grep -vE ' /usr/share/(doc|man)/' || true)"
[ -z "$v" ] && ok "dpkg -V is clean (docs aside)" || bad "dpkg -V reports: $v"
if grep -qs "^path-exclude=/usr/share/man" /etc/dpkg/dpkg.cfg /etc/dpkg/dpkg.cfg.d/* 2>/dev/null; then
    echo "  skip  man pages (this image excludes /usr/share/man from packages)"
else
    for c in sentinel run cgroup firewall floor blocklist report demo selfcheck; do check "man page: cora-$c(1)" test -s "/usr/share/man/man1/cora-$c.1.gz"; done
    man -w cora-floor >/dev/null 2>&1 && ok "man finds cora-floor(1)" || bad "man cannot find cora-floor(1)"
fi
if [ -d /run/systemd/system ]; then
    gone systemctl is-active --quiet cora-sentinel && ok "service not started" || bad "service was started"
    gone systemctl is-enabled --quiet cora-sentinel && ok "service not enabled" || bad "service was enabled"
    check "systemd accepts the unit" bash -c '[ -z "$(systemd-analyze verify --man=no /usr/lib/systemd/system/cora-sentinel.service 2>&1)" ]'
fi

# postinst puts back a list directory an admin removed (the template is a conffile, and dpkg respects its deletion)
rm -rf /etc/cora-sentinel/allow
/var/lib/dpkg/info/cora-sentinel.postinst configure >/dev/null 2>&1
check "postinst restores a removed list directory" test -d /etc/cora-sentinel/allow
echo "== reinstall (an upgrade): the floor and the edited config must survive"
echo "# edited by lifecycle_test" >> /etc/cora-sentinel/cora-sentinel.conf
echo "# edited by lifecycle_test" >> /etc/cora-sentinel/blocklists/00-local.txt
cora-floor ensure >/dev/null 2>&1; floor_up && ok "floor installed" || bad "could not install a floor to test with"
dpkg -i --force-confold "$deb" >/dev/null 2>&1 && ok "dpkg -i (upgrade)" || bad "upgrade failed"
floor_up && ok "the floor survived the upgrade" || bad "the upgrade removed the floor"
grep -q "edited by lifecycle_test" /etc/cora-sentinel/cora-sentinel.conf && ok "the edited config survived" || bad "the edited config was overwritten"
grep -q "edited by lifecycle_test" /etc/cora-sentinel/blocklists/00-local.txt && ok "the edited list template survived (a conffile)" || bad "the edited list template was lost"

echo "== remove"
mkdir -p /var/lib/cora-sentinel /var/log/cora-sentinel
echo state > /var/lib/cora-sentinel/floor.confirmed.json; echo audit > /var/log/cora-sentinel/decisions.jsonl
out="$(dpkg -r cora-sentinel 2>&1)"; rc=$?
[ $rc = 0 ] && ok "dpkg -r" || bad "dpkg -r: $out"
grep -q "kernel floor removed" <<<"$out" && ok "reported removing the floor" || bad "no 'floor removed' message"
gone floor_up && ok "the floor is gone" || bad "the floor is STILL THERE after removal"
gone nft list table inet cora && ok "the empty nft table was tidied away" || bad "an empty nft table was left behind"
gone test -e /usr/bin/cora-floor && ok "binaries removed" || bad "binaries left behind"
check "config kept after remove" test -e /etc/cora-sentinel/cora-sentinel.conf
check "state kept after remove" test -e /var/lib/cora-sentinel/floor.confirmed.json

echo "== purge"
out="$(dpkg -P cora-sentinel 2>&1)"; rc=$?
[ $rc = 0 ] && ok "dpkg -P" || bad "dpkg -P: $out"
gone test -e /etc/cora-sentinel && ok "config and the list directories removed" || bad "config or list directories left behind"
gone test -e /etc/logrotate.d/cora-sentinel && ok "logrotate config removed" || bad "logrotate config left behind"
gone test -e /var/lib/cora-sentinel && ok "state removed" || bad "state left behind"
check "audit logs KEPT" test -e /var/log/cora-sentinel/decisions.jsonl
grep -q "kept the audit logs" <<<"$out" && ok "said so" || bad "no 'kept the audit logs' message"
gone test -e /usr/lib/python3/dist-packages/cora_sentinel && ok "no package files left" || bad "package files left behind"
gone test -e /usr/share/man/man1/cora-floor.1.gz && ok "man pages removed" || bad "man pages left behind"
rm -rf /var/log/cora-sentinel        # the test's own audit file

echo
[ "$fail" = 0 ] && echo "LIFECYCLE PASS" || { echo "LIFECYCLE FAIL ($fail)"; exit 1; }
