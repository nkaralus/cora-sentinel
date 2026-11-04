"""Packaging contract: console scripts resolve, the version agrees, nothing still imports the old flat layout."""
import re
from importlib import metadata
from pathlib import Path

import cora_sentinel

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {"cora-sentinel", "cora-run", "cora-demo", "cora-cgroup", "cora-firewall",
           "cora-blocklist", "cora-report", "cora-selfcheck"}


def test_every_console_script_resolves_to_a_callable():
    eps = {e.name: e for e in metadata.entry_points(group="console_scripts") if e.value.startswith("cora_sentinel.")}
    assert set(eps) == SCRIPTS
    for e in eps.values():
        assert callable(e.load()), e.name


def test_version_matches_the_installed_metadata():
    assert cora_sentinel.__version__ == metadata.version("cora-sentinel")


def test_nothing_imports_the_old_flat_module_names():
    bad = re.compile(r"^\s*(from|import) cora_(?!sentinel\b)\w+", re.M)
    offenders = [str(p.relative_to(ROOT)) for p in list((ROOT / "src").rglob("*.py")) + list((ROOT / "tests").rglob("*.py"))
                 if bad.search(p.read_text())]
    assert offenders == []


def test_the_readme_documents_every_console_script():
    readme = (ROOT / "README.md").read_text()
    assert [s for s in SCRIPTS if s not in readme] == []
