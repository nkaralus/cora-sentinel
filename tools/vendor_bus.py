#!/usr/bin/env python3
"""
vendor_bus - the ONLY thing that rewrites src/cora_sentinel/_vendor/subnetbus.

That directory is a verbatim copy of github.com/nkaralus/engine-telemetry-bus at one pinned commit (the bus is the safety
gate the verdict code asks before it acts, so the copy that ships must be the copy the tests ran against). VENDOR.lock
records the upstream URL, the full commit and the sha256 of every file.

  python tools/vendor_bus.py check                       verify the vendored files against VENDOR.lock (offline)
  python tools/vendor_bus.py update --commit SHA         re-vendor from upstream at exactly that commit
        [--src PATH | --url URL] [--run-upstream-tests]
  python tools/vendor_bus.py check-upstream              fetch the pinned commit and compare it with what is vendored
        [--src PATH | --url URL]

`update` exports the commit with `git archive` (so a dirty working tree in --src cannot leak in), refuses a short or
unknown ref, optionally runs the bus's own test-suite first, and only then replaces the tree. A moving branch is never
vendored: you must name a commit, and the lock keeps the full 40-character hash.

Exit status: 0 ok, 1 drift or mismatch, 2 could not do it (bad arguments, git or tests failed).
Stdlib only. `--root DIR` points the tool at another tree (the tests do this).
"""
from __future__ import annotations

import argparse
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
from cora_sentinel import _vendor  # noqa: E402

DEFAULT_ROOT = REPO / "src" / "cora_sentinel" / "_vendor" / "subnetbus"
DEFAULT_URL = "https://github.com/nkaralus/engine-telemetry-bus"
SHA_RE = re.compile(r"[0-9a-f]{7,40}")


class ToolError(Exception):
    pass


def git(*args: str, cwd=None, binary: bool = False):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=not binary)
    if r.returncode:
        raise ToolError(f"git {' '.join(args[:2])} failed: {(r.stderr if not binary else r.stderr.decode()).strip()[:300]}")
    return r.stdout


def export_commit(commit: str, src: str | None, url: str | None, paths=("subnetbus", "LICENSE"),
                  optional=()) -> tuple[Path, str, tempfile.TemporaryDirectory]:
    """Check `commit` out of upstream into a temp dir WITHOUT touching a working tree. `paths` must exist at the commit;
    `optional` ones are taken if they do. Returns (dir, full_sha, handle)."""
    if not SHA_RE.fullmatch(commit):
        raise ToolError(f"--commit must be a hex commit hash (7-40 chars), not {commit!r}: a branch or tag can move")
    tmp = tempfile.TemporaryDirectory(prefix="vendorbus")
    repo = src
    if not repo:
        repo = str(Path(tmp.name) / "clone")
        git("clone", "--quiet", "--no-checkout", url or DEFAULT_URL, repo)
    full = git("rev-parse", "--verify", f"{commit}^{{commit}}", cwd=repo).strip()
    if not full.startswith(commit):
        raise ToolError(f"{commit} resolved to {full}")
    top = set(git("ls-tree", "--name-only", full, cwd=repo).split("\n"))
    data = git("archive", "--format=tar", full, *paths, *[o for o in optional if o in top], cwd=repo, binary=True)
    out = Path(tmp.name) / "export"
    out.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        tf.extractall(out, filter="data") if hasattr(tarfile, "data_filter") else tf.extractall(out)
    return out, full, tmp


def tree_hashes(d: Path) -> dict:
    files = {p.relative_to(d).as_posix(): _vendor.sha256_file(p) for p in sorted(d.glob("*.py"))}
    if (d / "LICENSE").is_file():
        files["LICENSE"] = _vendor.sha256_file(d / "LICENSE")
    return files


def cmd_check(a) -> int:
    root = Path(a.root)
    problems = _vendor.verify(root)
    if problems:
        print(f"DRIFT in {root}:")
        for p in problems:
            print(f"  {p}")
        print("The vendored copy is not what VENDOR.lock says. Restore it (git checkout) or re-vendor on purpose "
              "(tools/vendor_bus.py update --commit SHA).")
        return 1
    lock = _vendor.read_lock(root)
    print(f"ok: {len(lock['files'])} files match VENDOR.lock ({lock['distribution']} {lock['version']} @ {lock['commit']})")
    return 0


def cmd_update(a) -> int:
    root = Path(a.root)
    out, full, tmp = export_commit(a.commit, a.src, a.url, optional=("tests", "pyproject.toml") if a.run_upstream_tests else ())
    with tmp:
        up = out / "subnetbus"
        if not up.is_dir() or not (out / "LICENSE").is_file():
            raise ToolError(f"{full} has no subnetbus/ package and LICENSE at its top level")
        if a.run_upstream_tests:
            r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=out,
                               capture_output=True, text=True, env={"PYTHONPATH": str(out), "PATH": "/usr/bin:/bin"})
            print("upstream tests:", (r.stdout.strip().splitlines() or ["(no output)"])[-1])
            if r.returncode:
                raise ToolError("the bus's own tests fail at that commit; not vendoring it")
        ver = re.search(r'__version__\s*=\s*"([^"]+)"', (up / "__init__.py").read_text())
        stage = Path(tmp.name) / "stage"
        stage.mkdir()
        for p in sorted(up.glob("*.py")):
            shutil.copy2(p, stage / p.name)
        shutil.copy2(out / "LICENSE", stage / "LICENSE")
        files = tree_hashes(stage)
        lock = {"schema": 1, "name": "subnetbus", "distribution": "engine-telemetry-bus", "upstream": a.url or DEFAULT_URL,
                "commit": full, "version": ver.group(1) if ver else "unknown", "license": "MIT", "files": files}
        root.mkdir(parents=True, exist_ok=True)
        for old in list(root.iterdir()):
            if old.is_file():
                old.unlink()
        for p in stage.iterdir():
            shutil.copy2(p, root / p.name)
        (root / _vendor.LOCK_NAME).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    print(f"vendored {len(files)} files from {lock['upstream']} @ {full} (version {lock['version']}) into {root}")
    return cmd_check(a)


def cmd_check_upstream(a) -> int:
    root = Path(a.root)
    lock = _vendor.read_lock(root)
    out, full, tmp = export_commit(lock["commit"], a.src, a.url or lock.get("upstream"))
    with tmp:
        up = tree_hashes(out / "subnetbus")
        up["LICENSE"] = _vendor.sha256_file(out / "LICENSE")
    bad = [f"{k}: {'missing upstream' if k not in up else 'differs from upstream'}" for k, v in lock["files"].items() if up.get(k) != v]
    bad += [f"{k}: upstream has it, the lock does not" for k in up if k not in lock["files"]]
    if bad:
        print(f"the lock does not match upstream @ {full}:")
        print("\n".join(f"  {b}" for b in bad))
        return 1
    print(f"ok: the lock matches upstream @ {full} ({len(up)} files)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(DEFAULT_ROOT), help="the vendored directory (default: the repo's)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    for name in ("update", "check-upstream"):
        p = sub.add_parser(name)
        p.add_argument("--src", help="a local clone of the upstream repo (default: clone --url)")
        p.add_argument("--url", help=f"upstream URL (default {DEFAULT_URL})")
        if name == "update":
            p.add_argument("--commit", required=True, help="the upstream commit to vendor (hex, not a branch or tag)")
            p.add_argument("--run-upstream-tests", action="store_true", help="run the bus's own tests at that commit first")
    a = ap.parse_args(argv)
    try:
        return {"check": cmd_check, "update": cmd_update, "check-upstream": cmd_check_upstream}[a.cmd](a)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
