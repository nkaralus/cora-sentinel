"""Wheel, sdist and the native .deb: what is in them, that they are standalone and reproducible, and what the maintainer
scripts do, run against STUBBED systemctl/nft/cora-floor in a temp dir. Nothing here installs a package, stops a service
or touches a real floor (the real install/remove/purge is packaging/lifecycle_test.sh, for a disposable machine).
Run: pytest -q tests/test_packaging_deb.py"""
import configparser
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
import zipfile
from pathlib import Path

import pytest

import cora_sentinel
from cora_sentinel import _vendor

ROOT = Path(__file__).resolve().parents[1]
DEB_DIR = ROOT / "packaging" / "debian"
BUILD = ROOT / "packaging" / "build_deb.sh"
SCRIPTS = {"cora-sentinel", "cora-run", "cora-demo", "cora-cgroup", "cora-firewall", "cora-floor", "cora-blocklist",
           "cora-report", "cora-selfcheck"}
EPOCH = "1800000000"

TOOLS_OK = bool(shutil.which("dpkg-deb") and shutil.which("bash") and (ROOT / "pyproject.toml").exists())
have_tools = pytest.mark.skipif(not TOOLS_OK, reason="needs dpkg-deb, bash and the source tree")


def sh(*cmd, cwd=None, env=None):
    return subprocess.run(list(cmd), cwd=cwd, env=env, capture_output=True, text=True)


# ---------------------------------------------------------------------------------------------------------------
# artifacts, built once
# ---------------------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def source(tmp_path_factory):
    """A scratch copy of the files that make the package. Building in the repo itself would write build/ and egg-info into
    the user's checkout (and fail on a read-only one)."""
    if not (ROOT / "pyproject.toml").exists():
        pytest.skip("no source tree here")
    dst = tmp_path_factory.mktemp("source")
    skip = shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info", "build", "dist")
    for d in ("src", "deploy", "packaging", "docs", "tools", "tests", "examples", "schema"):
        if (ROOT / d).is_dir():
            shutil.copytree(ROOT / d, dst / d, ignore=skip)
    for f in ("pyproject.toml", "MANIFEST.in", "LICENSE", "README.md", "CHANGELOG.md"):
        if (ROOT / f).exists():
            shutil.copy2(ROOT / f, dst / f)
    return dst


@pytest.fixture(scope="module")
def wheel(source, tmp_path_factory):
    out = tmp_path_factory.mktemp("wheel")
    for iso in (["--no-build-isolation"], []):                       # offline when setuptools is installed, else isolated
        r = sh(sys.executable, "-m", "pip", "wheel", str(source), "--no-deps", "-q", *iso, "-w", str(out))
        if r.returncode == 0:
            return next(out.glob("*.whl"))
    pytest.skip("cannot build a wheel here (no setuptools and no network)")


@pytest.fixture(scope="module")
def sdist(source, tmp_path_factory):
    out = tmp_path_factory.mktemp("sdist")
    env = dict(os.environ)
    if sh(sys.executable, "-c", "import setuptools").returncode:                 # a bare venv: fetch a build backend, like the wheel fixture
        tool = tmp_path_factory.mktemp("setuptools")
        if sh(sys.executable, "-m", "pip", "install", "-q", "--target", str(tool), "setuptools>=68").returncode:
            pytest.skip("setuptools is not available to build an sdist (no network either)")
        env["PYTHONPATH"] = str(tool)
    r = sh(sys.executable, "-c", f"from setuptools.build_meta import build_sdist; print(build_sdist({str(out)!r}))", cwd=source, env=env)
    assert r.returncode == 0, r.stderr[-400:]
    return out / r.stdout.strip().splitlines()[-1]


def build_deb(wheel, out, **env):
    r = sh("bash", str(BUILD), "--wheel", str(wheel), "--out", str(out), env=dict(os.environ, SOURCE_DATE_EPOCH=EPOCH, **env))
    assert r.returncode == 0, r.stdout + r.stderr
    return Path(r.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def deb(wheel, tmp_path_factory):
    if not TOOLS_OK:
        pytest.skip("needs dpkg-deb, bash and the source tree")
    return build_deb(wheel, tmp_path_factory.mktemp("deb"))


@pytest.fixture(scope="module")
def data(deb, tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    assert sh("dpkg-deb", "-x", str(deb), str(d)).returncode == 0
    return d


@pytest.fixture(scope="module")
def ctl(deb, tmp_path_factory):
    d = tmp_path_factory.mktemp("ctl")
    assert sh("dpkg-deb", "-e", str(deb), str(d)).returncode == 0
    return d


def control(ctl):
    out, key = {}, None
    for line in (ctl / "control").read_text().splitlines():
        if line.startswith(" "):
            out[key] += "\n" + line
        else:
            key, _, v = line.partition(": ")
            out[key] = v
    return out


# ---------------------------------------------------------------------------------------------------------------
# wheel and sdist: zero dependencies, the vendored gate and its license travel with them
# ---------------------------------------------------------------------------------------------------------------
def test_the_wheel_has_no_runtime_dependencies(wheel):
    meta = zipfile.ZipFile(wheel).read(next(n for n in zipfile.ZipFile(wheel).namelist() if n.endswith("/METADATA"))).decode()
    meta = meta.split("\n\n", 1)[0]                                 # the header fields; the README follows as the long description
    reqs = [l for l in meta.splitlines() if l.startswith("Requires-Dist:")]
    assert all("extra ==" in r for r in reqs), reqs                  # only the optional model/dev extras
    assert "Requires-Python: >=3.10" in meta and "git+" not in meta


def test_the_wheel_carries_the_vendored_gate_its_license_and_its_lock(wheel):
    z = zipfile.ZipFile(wheel)
    names = set(z.namelist())
    base = "cora_sentinel/_vendor/subnetbus/"
    assert {base + "LICENSE", base + "VENDOR.lock", base + "gates.py", base + "registry.py", "cora_sentinel/_vendor/__init__.py"} <= names
    assert any(n.endswith("dist-info/LICENSE") or n.endswith("dist-info/licenses/LICENSE") for n in names)
    assert z.read(base + "LICENSE").decode().startswith("MIT License")
    assert z.read(base + "VENDOR.lock") == (_vendor.HERE / "VENDOR.lock").read_bytes()
    assert not [n for n in names if n.startswith(("tests/", "deploy/", "tools/")) or n.endswith(".pyc")]


def test_the_wheel_builds_with_the_toolchain_ubuntu_ships(tmp_path):
    """setuptools 68 (Ubuntu 24.04) must be able to read pyproject.toml: the license is the table form."""
    text = (ROOT / "pyproject.toml").read_text()
    assert 'requires = ["setuptools>=68"]' in text and 'license = { text = "MIT" }' in text
    assert "license-files" not in text and "dependencies = []" in text


def test_the_sdist_is_an_allow_list_and_complete_enough_to_rebuild_the_wheel(sdist, wheel, tmp_path):
    with tarfile.open(sdist) as tf:
        names = [n.split("/", 1)[1] for n in tf.getnames() if "/" in n]
        tf.extractall(tmp_path / "x", filter="data") if hasattr(tarfile, "data_filter") else tf.extractall(tmp_path / "x")
    must = ["src/cora_sentinel/_vendor/subnetbus/VENDOR.lock", "src/cora_sentinel/_vendor/subnetbus/LICENSE", "LICENSE",
            "packaging/build_deb.sh", "packaging/debian/postinst", "deploy/cora-sentinel.service", "tools/vendor_bus.py",
            "tests/test_vendor.py", "docs/packaging.md", "schema/violation.schema.json", "pyproject.toml", "MANIFEST.in"]
    assert [m for m in must if m not in names] == []
    assert not [n for n in names if n.endswith((".patch", ".zip", ".pyc")) or n.startswith(("cora-os", "superseded-flat", "models"))]
    # and it really is enough: build a wheel from the unpacked sdist and get the same file list
    src = tmp_path / "x" / sdist.name[:-len(".tar.gz")]
    out = tmp_path / "w"
    r = sh(sys.executable, "-m", "pip", "wheel", str(src), "--no-deps", "-q", "--no-build-isolation", "-w", str(out))
    if r.returncode:
        r = sh(sys.executable, "-m", "pip", "wheel", str(src), "--no-deps", "-q", "-w", str(out))
    assert r.returncode == 0, r.stderr
    assert sorted(zipfile.ZipFile(next(out.glob("*.whl"))).namelist()) == sorted(zipfile.ZipFile(wheel).namelist())


def test_sdist_normalization_is_deterministic_and_loses_nothing(sdist, tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("normalize_sdist", ROOT / "packaging" / "normalize_sdist.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    a, b = tmp_path / "a.tar.gz", tmp_path / "b.tar.gz"
    shutil.copy(sdist, a)
    with tarfile.open(sdist) as src, tarfile.open(b, "w:gz") as dst:                 # the same tree, other mtimes and owners
        for m in src.getmembers():
            m.mtime, m.uid, m.uname = m.mtime + 12345, 1000, "someone"
            dst.addfile(m, src.extractfile(m) if m.isfile() else None)
    mod.normalize(str(a), 1800000000)
    mod.normalize(str(b), 1800000000)
    assert a.read_bytes() == b.read_bytes()
    with tarfile.open(a) as n, tarfile.open(sdist) as o:
        assert n.getnames() == sorted(o.getnames())
        assert all(m.mtime == 1800000000 and m.uid == 0 and m.gid == 0 for m in n.getmembers())
        for m in o.getmembers():
            if m.isfile():
                assert n.extractfile(m.name).read() == o.extractfile(m).read(), m.name
                assert bool(n.getmember(m.name).mode & 0o111) == bool(m.mode & 0o111), m.name        # the exec bit survives


# ---------------------------------------------------------------------------------------------------------------
# the .deb
# ---------------------------------------------------------------------------------------------------------------
@have_tools
def test_control_metadata(ctl):
    c = control(ctl)
    assert c["Package"] == "cora-sentinel" and c["Architecture"] == "all" and c["Version"] == f"{cora_sentinel.__version__}-1"
    assert c["Depends"] == "python3 (>= 3.10), nftables"            # nothing else: the gate is vendored
    assert c["Recommends"] == "logrotate" and c["Section"] == "admin" and c["Installed-Size"].isdigit()
    assert re.fullmatch(r".+ <[^@\s]+@[^@\s]+>", c["Maintainer"])
    assert "NOT start" in c["Description"] and "llama-cpp-python" in c["Description"]


@have_tools
def test_the_maintainer_email_can_be_overridden(wheel, tmp_path):
    d = build_deb(wheel, tmp_path, DEB_MAINTAINER="Someone Else <else@example.org>")
    assert "Maintainer: Someone Else <else@example.org>" in sh("dpkg-deb", "-f", str(d)).stdout


@have_tools
def test_conffiles_are_the_config_and_the_logrotate_file_and_nothing_else(ctl, data):
    listed = (ctl / "conffiles").read_text().split()
    assert listed == ["/etc/cora-sentinel/cora-sentinel.conf", "/etc/logrotate.d/cora-sentinel"]
    assert all((data / p.lstrip("/")).is_file() for p in listed)
    assert sorted(str(p.relative_to(data)) for p in (data / "etc").rglob("*") if p.is_file()) == [l.lstrip("/") for l in listed]


@have_tools
def test_the_binaries_the_unit_and_the_layout(data):
    ep = configparser.ConfigParser()
    ep.optionxform = str
    ep.read(next((data / "usr/lib/python3/dist-packages").glob("*.dist-info")) / "entry_points.txt")
    assert set(ep["console_scripts"]) == SCRIPTS
    for name in SCRIPTS:
        f = data / "usr/bin" / name
        mod, func = ep["console_scripts"][name].split(":")
        text = f.read_text()
        assert os.access(f, os.X_OK) and text.startswith("#!/usr/bin/python3\n") and f"from {mod} import {func}" in text
    unit = (data / "usr/lib/systemd/system/cora-sentinel.service").read_text()
    assert "ExecStart=/usr/bin/cora-sentinel $CORA_ARGS" in unit and "ExecStopPost=-/usr/bin/cora-floor rollback" in unit
    assert "Restart=on-failure" in unit and "@BINDIR@" not in unit
    assert sorted(p.name for p in data.iterdir()) == ["etc", "usr"]


@have_tools
def test_nothing_that_is_not_the_product_is_in_the_package(data):
    files = [p.relative_to(data).as_posix() for p in data.rglob("*") if p.is_file()]
    assert not [f for f in files if "__pycache__" in f or f.endswith((".pyc", ".patch", ".zip", ".sh")) or "/tests/" in f]
    assert not [f for f in files if f.startswith(("usr/lib/python3/dist-packages/tools", "usr/lib/python3/dist-packages/deploy"))]
    assert not any(f.endswith("RECORD") for f in files)
    assert (next((data / "usr/lib/python3/dist-packages").glob("*.dist-info")) / "INSTALLER").read_text().strip() == "dpkg"


@have_tools
def test_every_entry_is_owned_by_root_with_sane_modes(deb):
    for line in sh("dpkg-deb", "-c", str(deb)).stdout.splitlines():
        perm, owner, *_ , path = line.split()
        assert owner == "root/root", line
        if path.endswith("/"):
            assert perm == "drwxr-xr-x", line
        elif path.startswith("./usr/bin/"):
            assert perm == "-rwxr-xr-x", line
        else:
            assert perm == "-rw-r--r--", line


@have_tools
def test_the_packaged_code_is_self_contained_and_its_gate_verifies(data):
    site = data / "usr/lib/python3/dist-packages"
    code = "import cora_sentinel, sys; from cora_sentinel import _vendor; print(cora_sentinel.__file__); print(_vendor.verify()); print(_vendor.describe())"
    r = sh(sys.executable, "-B", "-c", code, cwd="/", env=dict(os.environ, PYTHONPATH=str(site), PYTHONDONTWRITEBYTECODE="1"))
    assert r.returncode == 0, r.stderr
    path, problems, desc = r.stdout.strip().splitlines()
    assert path.startswith(str(site)) and problems == "[]" and desc.endswith("@ ac3f126 verified")


@have_tools
def test_the_man_pages_are_installed_gzipped_with_the_build_date_and_the_version(data):
    man = data / "usr/share/man/man1"
    assert sorted(p.name for p in man.iterdir()) == sorted(f"{c}.1.gz" for c in SCRIPTS)
    for c in SCRIPTS:
        raw = (man / f"{c}.1.gz").read_bytes()
        page = gzip.decompress(raw).decode()
        assert page.startswith(f'.TH {c.upper().replace("-", chr(92) + "-")} 1 "2027-01-15" "cora-sentinel {cora_sentinel.__version__}"')
        assert raw[4:8] == b"\0\0\0\0"                                  # gzip -n: no timestamp in the header, so the .deb is reproducible
        if shutil.which("groff"):
            r = subprocess.run(["groff", "-man", "-ww", "-z"], input=page, capture_output=True, text=True)
            assert r.returncode == 0 and r.stderr == "", f"{c}: {r.stderr}"


@have_tools
def test_the_copyright_file_credits_both_licenses_and_names_the_vendored_commit(data):
    c = (data / "usr/share/doc/cora-sentinel/copyright").read_text()
    assert c.startswith("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/")
    assert c.count("License: MIT") >= 3 and "ac3f126946056b3b24eea9dbc15015b5a5639706" in c and "_vendor/subnetbus/*" in c
    assert "Copyright: 2026 Nick and contributors" in c and "Permission is hereby granted" in c
    doc = data / "usr/share/doc/cora-sentinel"
    assert gzip.decompress((doc / "changelog.gz").read_bytes()).decode().startswith("# Changelog")
    deb_log = gzip.decompress((doc / "changelog.Debian.gz").read_bytes()).decode()          # lintian insists on this format
    assert re.match(rf"cora-sentinel \({re.escape(cora_sentinel.__version__)}-1\) unstable; urgency=medium\n\n  \* ", deb_log)
    assert re.search(r"\n -- .+ <[^@\s]+@[^@\s]+>  \w{3}, \d\d \w{3} \d{4} \d\d:\d\d:\d\d \+0000\n$", deb_log)
    assert "Fri, 15 Jan 2027 08:00:00 +0000" in deb_log                                      # SOURCE_DATE_EPOCH=1800000000
    assert {"service.md", "packaging.md", "dyn-policy.md", "README.md"} <= {p.name for p in doc.iterdir()}


@have_tools
def test_md5sums_cover_every_file_except_the_conffiles_and_are_right(ctl, data):
    lines = (ctl / "md5sums").read_text().splitlines()
    got = {l.split("  ", 1)[1]: l.split("  ", 1)[0] for l in lines}
    files = {p.relative_to(data).as_posix() for p in data.rglob("*") if p.is_file()} - {"etc/cora-sentinel/cora-sentinel.conf", "etc/logrotate.d/cora-sentinel"}
    assert set(got) == files
    assert all(hashlib.md5((data / f).read_bytes()).hexdigest() == h for f, h in got.items())


@have_tools
def test_the_same_wheel_and_epoch_give_the_same_bytes(wheel, deb, tmp_path):
    again = build_deb(wheel, tmp_path)
    assert hashlib.sha256(again.read_bytes()).hexdigest() == hashlib.sha256(deb.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------------------------------------------
# the maintainer scripts, against stubs
# ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["postinst", "prerm", "postrm"])
def test_the_scripts_are_posix_sh_and_parse(name):
    p = DEB_DIR / name
    assert p.read_text().startswith("#!/bin/sh\n") and os.access(p, os.X_OK)
    assert sh("sh", "-n", str(p)).returncode == 0
    code = re.sub(r"<<'(\w+)'\n.*?\n\1\n", "", p.read_text(), flags=re.S)             # drop the text it prints (heredocs)
    code = "\n".join(l for l in code.splitlines() if not l.lstrip().startswith(("#", "echo ")))
    assert not re.search(r"systemctl\s+(enable|start|restart|reload-or-restart)\b|--now", code), \
        f"{name} must never enable or start the service"
    assert name != "postinst" or "try-restart" in code                                    # the only start it may do: an upgrade of a running one


class Box:
    """A scratch root for one script run: stub commands that log their calls, and the script's absolute paths redirected."""

    def __init__(self, tmp, systemd=True, active=False, table=None):
        self.tmp, self.log = tmp, tmp / "calls.log"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for sub in ("run/systemd/system" if systemd else "run", "var/lib/cora-sentinel", "var/log/cora-sentinel", "etc/cora-sentinel", "usr/bin"):
            (tmp / sub).mkdir(parents=True, exist_ok=True)
        stub = lambda name, body: self._write(self.bin / name, f'#!/bin/sh\necho "{name} $*" >> "{self.log}"\n{body}\n')   # noqa: E731
        stub("systemctl", 'case "$1" in is-active) [ -n "$STUB_ACTIVE" ] ;; esac')
        stub("py3compile", "exit 0")
        stub("py3clean", "exit 0")
        stub("nft", 'case "$*" in "list table inet cora") '
                    '[ "$STUB_TABLE" = chains ] && printf "table inet cora {\\n\\tchain egress {\\n\\t}\\n}\\n" && exit 0; '
                    '[ "$STUB_TABLE" = empty ] && printf "table inet cora {\\n}\\n" && exit 0; exit 1 ;; esac')
        stub("cora-floor", "exit 0")
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", STUB_ACTIVE="1" if active else "", STUB_TABLE=table or "")

    @staticmethod
    def _write(p, text):
        p.write_text(text)
        p.chmod(0o755)

    def run(self, script, *args):
        text = (DEB_DIR / script).read_text()
        for real, fake in (("/run/systemd/system", "run/systemd/system"),
                           ("/var/lib/cora-sentinel", "var/lib/cora-sentinel"), ("/var/log/cora-sentinel", "var/log/cora-sentinel"),
                           ("/etc/cora-sentinel", "etc/cora-sentinel")):
            text = text.replace(real, str(self.tmp / fake))
        s = self.tmp / script
        self._write(s, text)
        r = subprocess.run(["sh", str(s), *args], capture_output=True, text=True, env=self.env)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return r.returncode, r.stdout + r.stderr, calls


def test_a_fresh_install_prints_how_to_start_it_and_never_starts_or_enables_it(tmp_path):
    rc, out, calls = Box(tmp_path).run("postinst", "configure")
    assert rc == 0 and "NOT started" in out and "cora-floor confirm" in out and "llama-cpp-python" in out
    assert "py3compile -p cora-sentinel" in calls and "systemctl daemon-reload" in calls
    assert not [c for c in calls if re.search(r"enable|start|restart|try-restart", c)]


def test_an_upgrade_restarts_a_running_service_and_only_a_running_one(tmp_path):
    rc, out, calls = Box(tmp_path, active=True).run("postinst", "configure", "0.7.0-1")
    assert rc == 0 and "systemctl try-restart cora-sentinel" in calls and "NOT started" not in out
    (tmp_path / "again").mkdir()
    rc, out, calls = Box(tmp_path / "again", active=False).run("postinst", "configure", "0.7.0-1")
    assert not [c for c in calls if "restart" in c]


def test_no_systemd_means_no_systemctl_calls(tmp_path):
    rc, out, calls = Box(tmp_path, systemd=False, active=True).run("postinst", "configure", "0.7.0-1")
    assert rc == 0 and not [c for c in calls if c.startswith("systemctl")]


def test_remove_stops_the_service_removes_the_floor_and_tidies_an_empty_table(tmp_path):
    rc, out, calls = Box(tmp_path, table="empty").run("prerm", "remove")
    assert rc == 0 and "kernel floor removed" in out
    order = [c for c in calls if c.startswith(("systemctl stop", "systemctl disable", "cora-floor", "nft delete", "py3clean"))]
    assert order == ["systemctl stop cora-sentinel", "systemctl disable cora-sentinel", "cora-floor remove",
                     "nft delete table inet cora", "py3clean -p cora-sentinel"]


def test_remove_leaves_per_task_isolation_rules_alone_and_says_so(tmp_path):
    rc, out, calls = Box(tmp_path, table="chains").run("prerm", "remove")
    assert rc == 0 and "kept on purpose" in out and "cora-firewall purge" in out
    assert "cora-floor remove" in calls and not [c for c in calls if c.startswith("nft delete")]


def test_an_upgrade_never_touches_the_service_or_the_floor(tmp_path):
    for arg in ("upgrade", "failed-upgrade"):
        d = tmp_path / arg
        d.mkdir()
        rc, out, calls = Box(d, table="chains", active=True).run("prerm", arg, "0.8.0-1")
        assert rc == 0 and calls == [], (arg, calls)


def test_deconfigure_stops_the_service_but_does_not_remove_the_floor(tmp_path):
    rc, out, calls = Box(tmp_path, table="chains").run("prerm", "deconfigure")
    assert rc == 0 and "systemctl stop cora-sentinel" in calls and not [c for c in calls if "cora-floor" in c]


def test_remove_does_not_need_the_binary_or_nft_to_exist(tmp_path):
    b = Box(tmp_path)
    (b.bin / "cora-floor").unlink()
    (b.bin / "nft").unlink()
    rc, out, calls = b.run("prerm", "remove")
    assert rc == 0                                                   # a half-removed package must still remove cleanly


def test_remove_keeps_everything_and_purge_cleans_state_but_keeps_the_audit_logs(tmp_path):
    b = Box(tmp_path)
    for f in ("var/lib/cora-sentinel/floor.confirmed.json", "var/log/cora-sentinel/decisions.jsonl", "etc/cora-sentinel/extra"):
        (tmp_path / f).write_text("x")
    rc, out, calls = b.run("postrm", "remove")
    assert rc == 0 and (tmp_path / "var/lib/cora-sentinel/floor.confirmed.json").exists() and "systemctl daemon-reload" in calls
    rc, out, calls = b.run("postrm", "purge")
    assert rc == 0
    assert not (tmp_path / "var/lib/cora-sentinel").exists(), "purge must clean the state directory"
    assert (tmp_path / "var/log/cora-sentinel/decisions.jsonl").read_text() == "x", "purge must KEEP the audit logs"
    assert (tmp_path / "etc/cora-sentinel/extra").exists()           # a file dpkg does not own is not ours to delete
    assert "kept the audit logs" in out


def test_purge_removes_an_empty_config_directory(tmp_path):
    b = Box(tmp_path)
    shutil.rmtree(tmp_path / "var/log/cora-sentinel")
    rc, out, calls = b.run("postrm", "purge")
    assert rc == 0 and not (tmp_path / "etc/cora-sentinel").exists() and "kept the audit logs" not in out


@pytest.mark.parametrize("script,args", [("postinst", ("bogus",)), ("prerm", ("bogus",)), ("postrm", ("bogus",))])
def test_an_unknown_argument_is_an_error(tmp_path, script, args):
    rc, out, calls = Box(tmp_path).run(script, *args)
    assert rc == 1 and "unknown argument" in out


@pytest.mark.parametrize("script,args", [("postrm", ("upgrade", "0.8.0-1")), ("postrm", ("abort-install",)), ("postinst", ("abort-upgrade", "0.7.0-1"))])
def test_the_other_dpkg_states_do_nothing(tmp_path, script, args):
    rc, out, calls = Box(tmp_path, table="chains", active=True).run(script, *args)
    assert rc == 0 and calls == []
