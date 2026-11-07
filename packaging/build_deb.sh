#!/usr/bin/env bash
# Build cora-sentinel_<version>-<rev>_all.deb with dpkg-deb only: no debhelper, no network, no compiler.
#
#   packaging/build_deb.sh [--wheel PATH] [--out DIR] [--revision N]
#
# The package is the wheel unpacked into /usr/lib/python3/dist-packages plus /usr/bin wrappers, the systemd units
# (cora-sentinel.service, cora-sync.service/.timer, @BINDIR@ = /usr/bin), cora-tray under /usr/share/cora-sentinel, the config and logrotate files as conffiles, docs, and the
# maintainer scripts in packaging/debian. It is Architecture: all with no Python dependencies: the safety gate is vendored.
#
# Reproducible: the same wheel and the same SOURCE_DATE_EPOCH give the same bytes. Default epoch: the last commit's time
# (git), else the mtime of pyproject.toml. DEB_MAINTAINER overrides the Maintainer field.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
wheel="" out="$repo/dist" rev="1"
while [ $# -gt 0 ]; do
    case "$1" in
        --wheel) wheel="${2:?--wheel needs a path}"; shift 2 ;;
        --out) out="${2:?--out needs a directory}"; shift 2 ;;
        --revision) rev="${2:?--revision needs a number}"; shift 2 ;;
        -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
command -v dpkg-deb >/dev/null || { echo "dpkg-deb not found (it is in the 'dpkg' package)" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- the wheel -------------------------------------------------------------------------------------------------------
if [ -z "$wheel" ]; then
    if python3 -c 'import setuptools' 2>/dev/null; then iso=(--no-build-isolation); else iso=(); fi   # offline when it can be
    python3 -m pip wheel "$repo" --no-deps -q "${iso[@]}" -w "$tmp/wheel"
    wheel="$(ls "$tmp"/wheel/*.whl)"
fi
[ -f "$wheel" ] || { echo "no such wheel: $wheel" >&2; exit 1; }
version="$(python3 - "$wheel" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
meta = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
print(next(l.split(":", 1)[1].strip() for l in z.read(meta).decode().splitlines() if l.startswith("Version:")))
PY
)"
sde="${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || stat -c %Y "$repo/pyproject.toml")}"
maint="${DEB_MAINTAINER:-Nick <nkaralus@users.noreply.github.com>}"

stage="$tmp/stage"
site="$stage/usr/lib/python3/dist-packages"
doc="$stage/usr/share/doc/cora-sentinel"
mkdir -p "$site" "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/systemd/system" "$stage/etc/cora-sentinel" \
         "$stage/etc/cora-sentinel/blocklists" "$stage/etc/cora-sentinel/allow" "$stage/etc/logrotate.d" "$doc" "$stage/usr/share/man/man1"

# ---- code: the wheel, minus RECORD (stale once modes change), marked as dpkg's so pip will not uninstall it ------------
python3 -m zipfile -e "$wheel" "$site"
distinfo="$(echo "$site"/*.dist-info)"
rm -f "$distinfo/RECORD"
echo dpkg > "$distinfo/INSTALLER"

# ---- /usr/bin wrappers from the wheel's console scripts -------------------------------------------------------------
python3 - "$distinfo/entry_points.txt" "$stage/usr/bin" <<'PY'
import configparser, os, sys
cp = configparser.ConfigParser()
cp.optionxform = str
cp.read(sys.argv[1])
for name, target in sorted(cp["console_scripts"].items()):
    mod, func = target.split(":")
    path = os.path.join(sys.argv[2], name)
    with open(path, "w") as f:
        f.write(f"#!/usr/bin/python3\nimport sys\nfrom {mod} import {func}\nif __name__ == '__main__':\n    sys.exit({func}())\n")
    os.chmod(path, 0o755)
PY

# ---- service, config (conffiles), logrotate (conffile), docs -------------------------------------------------------
sed 's|@BINDIR@|/usr/bin|g' "$repo/deploy/cora-sentinel.service" > "$stage/usr/lib/systemd/system/cora-sentinel.service"
# signed community lists: installed, never enabled (systemctl enable --now cora-sync.timer once the key is pinned)
sed 's|@BINDIR@|/usr/bin|g' "$repo/deploy/cora-sync.service" > "$stage/usr/lib/systemd/system/cora-sync.service"
cp "$repo/deploy/cora-sync.timer" "$stage/usr/lib/systemd/system/cora-sync.timer"

# ---- cora-tray: the GNOME indicator. Its GTK libraries are only Suggested, so a server never pulls in a desktop stack.
tray="$stage/usr/share/cora-sentinel/cora-tray"
mkdir -p "$tray/icons" "$stage/usr/share/applications" "$stage/etc/xdg/autostart" "$stage/usr/share/icons/hicolor/scalable/apps"
cp "$repo/deploy/cora-tray/cora-tray" "$tray/cora-tray"
cp "$repo"/deploy/cora-tray/icons/*.svg "$tray/icons/"
ln -s ../share/cora-sentinel/cora-tray/cora-tray "$stage/usr/bin/cora-tray"      # a symlink: the script finds its icons
cp "$repo/deploy/cora-tray/icons/cora-green.svg" "$stage/usr/share/icons/hicolor/scalable/apps/cora-tray.svg"
cp "$repo/deploy/cora-tray/cora-tray.desktop" "$stage/usr/share/applications/cora-tray.desktop"
# autostart for every user, but cora-tray --autostart exits quietly for anyone not in group cora (and without GTK)
sed 's|^Exec=cora-tray$|Exec=cora-tray --autostart|' "$repo/deploy/cora-tray/cora-tray.desktop" > "$stage/etc/xdg/autostart/cora-tray.desktop"
cp "$repo/deploy/cora-tray/README.md" "$doc/cora-tray.md"
cp "$repo/deploy/cora-sentinel.conf" "$stage/etc/cora-sentinel/cora-sentinel.conf"
cp "$repo/deploy/cora-sentinel.logrotate" "$stage/etc/logrotate.d/cora-sentinel"
# The directories the suggested --blocklist / --blocklist-allow flags point at, each with an INERT template (it blocks and allows
# nothing). Conffiles, so an upgrade keeps your edits, deleting one is respected, and purge removes them. Without the directories
# the daemon exits at start with "[Errno 2] No such file or directory".
cp "$repo/deploy/seed/blocklists/00-local.txt" "$stage/etc/cora-sentinel/blocklists/00-local.txt"
cp "$repo/deploy/seed/allow/00-local.txt" "$stage/etc/cora-sentinel/allow/00-local.txt"
cp "$repo/README.md" "$doc/README.md"
cp "$repo"/docs/*.md "$doc/"
gzip -9n -c "$repo/CHANGELOG.md" > "$doc/changelog.gz"
# the man pages are generated from the real argument parsers (tools/gen_man.py); nothing generated is kept in git
python3 "$repo/tools/gen_man.py" --out "$tmp/man" --date "$(date -u -d "@$sde" +%Y-%m-%d)" >/dev/null
for page in "$tmp"/man/*.1; do gzip -9n -c "$page" > "$stage/usr/share/man/man1/$(basename "$page").gz"; done
# Debian wants its own changelog format; the real history is upstream's CHANGELOG.md, shipped beside it
gzip -9n -c > "$doc/changelog.Debian.gz" <<CHG
cora-sentinel (${version}-${rev}) unstable; urgency=medium

  * Packaged from cora-sentinel ${version} with packaging/build_deb.sh.
  * The project's own history: /usr/share/doc/cora-sentinel/changelog.gz

 -- ${maint}  $(date -u -d "@$sde" '+%a, %d %b %Y %H:%M:%S +0000')
CHG

vend="$site/cora_sentinel/_vendor/subnetbus"
python3 - "$repo/LICENSE" "$vend/LICENSE" "$vend/VENDOR.lock" "$doc/copyright" <<'PY'
import json, re, sys
own, bus, lock, out = sys.argv[1:5]
own_t, bus_t, lk = open(own).read(), open(bus).read(), json.load(open(lock))
cr = lambda t: re.search(r"^Copyright.*$", t, re.M).group(0).replace("Copyright (c) ", "").replace("Copyright ", "")
body = "\n".join(" " + l if l.strip() else " ." for l in own_t.strip().splitlines()[2:])        # the MIT text, after its title
open(out, "w").write(f"""Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: cora-sentinel
Source: https://github.com/nkaralus/cora-sentinel

Files: *
Copyright: {cr(own_t)}
License: MIT

Files: usr/lib/python3/dist-packages/cora_sentinel/_vendor/subnetbus/*
Copyright: {cr(bus_t)}
Comment: Vendored verbatim from {lk['upstream']} at commit {lk['commit']}
 ({lk['distribution']} {lk['version']}); VENDOR.lock beside the code records the sha256 of every file.
License: MIT

License: MIT
{body}
""")
PY

# ---- control, maintainer scripts --------------------------------------------------------------------------------------
cp "$here/debian/conffiles" "$stage/DEBIAN/conffiles"
install -m 0755 "$here/debian/postinst" "$here/debian/prerm" "$here/debian/postrm" "$stage/DEBIAN/"
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f ! -path "$stage/DEBIAN/*" ! -path "$stage/usr/bin/*" -exec chmod 0644 {} +
chmod 0755 "$tray/cora-tray"
# md5sums for everything dpkg does not track as a conffile, so `dpkg -V cora-sentinel` can verify an install
( cd "$stage" && find . -type f ! -path './DEBIAN/*' | sed 's|^\./||' | LC_ALL=C sort \
    | grep -vxFf <(sed 's|^/||' "$here/debian/conffiles") | xargs -d '\n' md5sum > DEBIAN/md5sums )
size="$(du -sk --exclude=DEBIAN "$stage" | cut -f1)"
cat > "$stage/DEBIAN/control" <<CTRL
Package: cora-sentinel
Version: ${version}-${rev}
Architecture: all
Maintainer: ${maint}
Installed-Size: ${size}
Depends: python3 (>= 3.10), nftables
Recommends: logrotate
Suggests: systemd, python3-gi, gir1.2-gtk-3.0, gir1.2-ayatanaappindicator3-0.1, gnome-shell-extension-appindicator
Section: admin
Priority: optional
Homepage: https://github.com/nkaralus/cora-sentinel
Description: out-of-band security sentinel for Linux
 Per-task cgroups, nftables containment, connect-time attribution (NFLOG) for
 TCP/UDP/QUIC/DNS, a kernel-side blocklist floor with a dead-man lockout guard,
 and a grammar-constrained local LLM supervisor whose verdicts pass a vendored
 safety gate before anything is acted on.
 .
 Installing does NOT start the service: the kernel floor it can install is
 host-wide. Removing the package stops the service and removes the floor;
 purging deletes /var/lib/cora-sentinel and keeps /var/log/cora-sentinel.
 .
 Running the local model needs llama-cpp-python, which is not in the Ubuntu
 archive: see /usr/share/doc/cora-sentinel/packaging.md.
 .
 cora-tray, a GNOME indicator for the status feed with tighten-only breakers,
 runs for members of group cora (created on install; nobody is added) and
 needs the suggested GTK packages: see /usr/share/doc/cora-sentinel/cora-tray.md.
CTRL
chmod 0644 "$stage/DEBIAN/control" "$stage/DEBIAN/conffiles" "$stage/DEBIAN/md5sums"

# ---- build ---------------------------------------------------------------------------------------------------------
find "$stage" -exec touch -h -d "@$sde" {} +
mkdir -p "$out"
name="cora-sentinel_${version}-${rev}_all.deb"
SOURCE_DATE_EPOCH="$sde" dpkg-deb --root-owner-group -Zxz -z6 --build "$stage" "$out/$name" >/dev/null
echo "$out/$name"
