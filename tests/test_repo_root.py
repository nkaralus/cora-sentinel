"""The repository root holds what belongs there, and no delivery clutter. The 0.8.x zips used to carry their own patch and install notes
at their root, so unzipping over the checkout and `git add .` committed them; this is what stops that from happening again.
Skipped where there is no git checkout (an sdist). Run: pytest -q tests/test_repo_root.py"""
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = {".gitignore", "CHANGELOG.md", "LICENSE", "MANIFEST.in", "README.md", "pyproject.toml",
         "models",                                                       # a symlink to a local models directory (see the CHANGELOG, 0.8.5)
         "exceptions.txt", "rogue-subnets.txt", "trackers-starter.txt",  # loose starter lists that docs/ and examples/ still name
         "violation-reports.md", "violation.example.json", "violation.schema.json"}
DIRS = {".github", "deploy", "docs", "examples", "packaging", "schema", "src", "tests", "tools"}
LEGACY = {"cora-os", "cora-security-starter", "release-0.8.0", "superseded-flat"}   # old layouts nothing live uses: delete when you like
CLUTTER = (".patch", ".diff", ".zip", ".deb", ".whl", ".tar.gz", ".orig", ".rej")


def tracked():
    r = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("not a git checkout")
    return r.stdout.splitlines()


def test_the_root_holds_only_files_and_directories_that_belong_there():
    top = {f.split("/")[0] for f in tracked()}
    extra = sorted(top - FILES - DIRS - LEGACY)
    assert not extra, (f"unexpected at the repository root: {extra}. A patch, a zip or install notes? "
                       f"`git rm` them (or add the name to tests/test_repo_root.py on purpose)")


def test_no_patch_zip_or_built_package_is_tracked_outside_the_old_layouts():
    bad = [f for f in tracked() if f.split("/")[0] not in LEGACY and f.endswith(CLUTTER)]
    assert not bad, f"delivery files are tracked: {bad}"


def test_install_notes_are_not_tracked_at_the_root():
    assert not [f for f in tracked() if "/" not in f and "INSTALL" in f.upper() and f != "README.md"]


def test_the_old_layouts_are_not_in_the_sdist_allow_list():
    manifest = (ROOT / "MANIFEST.in").read_text()
    for name in LEGACY:
        assert name not in [w for l in manifest.splitlines() if l.startswith(("include", "recursive-include", "graft")) for w in l.split()], name


def test_every_tracked_test_data_file_is_in_the_sdist_allow_list():
    """0.9.0 nearly shipped without tests/fixtures/minisign/*: the allow-list took only tests/*.py, so the sdist's
    own suite would have failed its interop tests. Every git-tracked file under tests/ must match a MANIFEST.in rule."""
    import fnmatch
    import subprocess
    rules = []
    for line in (ROOT / "MANIFEST.in").read_text().splitlines():
        parts = line.split()
        if parts[:1] == ["recursive-include"]:
            rules.append((parts[1].rstrip("/") + "/", parts[2:]))
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "tests"], capture_output=True, text=True)
    if tracked.returncode:
        pytest.skip("not a git checkout")
    missing = [f for f in tracked.stdout.split() if "__pycache__" not in f and not any(
        f.startswith(d) and any(fnmatch.fnmatch(f.rsplit("/", 1)[-1], p) for p in pats) for d, pats in rules)]
    assert not missing, f"tracked under tests/ but not shipped in the sdist: {missing}"
