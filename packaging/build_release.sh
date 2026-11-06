#!/usr/bin/env bash
# sdist + wheel + .deb + SHA256SUMS into dist/, after checking that the vendored safety gate is untouched.
#
#   packaging/build_release.sh            (CORA_BUILD_NO_ISOLATION=1 builds offline with the installed setuptools)
#
# Needs: python3 with `build` (pip install build), dpkg-deb. SOURCE_DATE_EPOCH defaults to the last commit's time.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || stat -c %Y pyproject.toml)}"

python3 tools/vendor_bus.py check
python3 -c 'import build' 2>/dev/null || { echo "needs the 'build' package: pip install build" >&2; exit 1; }
rm -rf dist
mkdir -p dist
flags=(); [ "${CORA_BUILD_NO_ISOLATION:-}" = 1 ] && flags=(--no-isolation)
python3 -m build --outdir dist "${flags[@]}" >/dev/null
python3 "$here/normalize_sdist.py" dist/*.tar.gz                 # setuptools stamps build time into the sdist
"$here/build_deb.sh" --wheel "$(ls dist/*.whl)" --out dist >/dev/null
(cd dist && sha256sum -- * > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
cat dist/SHA256SUMS
