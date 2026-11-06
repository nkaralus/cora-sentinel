"""The man pages for the nine commands: generated from the real parsers, so a new option, subcommand or environment variable
that is not documented fails here. Run: pytest -q tests/test_man.py"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
pytestmark = pytest.mark.skipif(not (TOOLS / "gen_man.py").exists(), reason="no tools/ in this tree")
if (TOOLS / "gen_man.py").exists():
    sys.path.insert(0, str(TOOLS))
    import gen_man

SRC = ROOT / "src" / "cora_sentinel"


@pytest.fixture(scope="module")
def pages(tmp_path_factory):
    out = tmp_path_factory.mktemp("man")
    assert gen_man.main(["--out", str(out), "--date", "2026-01-01"]) == 0
    return {p.stem: p.read_text() for p in out.glob("*.1")} | {"_dir": out}


def only_pages(pages):
    return {k: v for k, v in pages.items() if k != "_dir"}


def scripts():
    text = (ROOT / "pyproject.toml").read_text().split("[project.scripts]", 1)[1].split("\n[", 1)[0]
    return set(re.findall(r"^(cora-[\w-]+)\s*=", text, re.M))


def test_every_console_script_has_a_page_and_no_page_is_for_nothing(pages):
    assert set(only_pages(pages)) == scripts() == set(gen_man.ORDER) == set(gen_man.PAGES)


@pytest.mark.skipif(not shutil.which("groff"), reason="needs groff")
def test_every_page_is_clean_roff(pages):
    for name in only_pages(pages):
        r = subprocess.run(["groff", "-man", "-ww", "-z", str(pages["_dir"] / f"{name}.1")], capture_output=True, text=True)
        assert r.returncode == 0 and r.stderr == "", f"{name}: {r.stderr}"


@pytest.mark.skipif(not shutil.which("groff"), reason="needs groff")
def test_a_page_renders_with_its_sections(pages):
    """Rendered with groff itself, so it does not depend on man-db (a minimized image has only a stub `man`)."""
    r = subprocess.run(["groff", "-man", "-Tascii", str(pages["_dir"] / "cora-floor.1")], capture_output=True, text=True)
    assert r.returncode == 0
    out = re.sub(r".\x08", "", r.stdout)
    for head in ("NAME", "SYNOPSIS", "DESCRIPTION", "OPTIONS", "COMMANDS", "DYN-REPLAY OPTIONS", "EXIT STATUS", "EXAMPLES", "SEE ALSO"):
        assert head in out, head


def test_each_page_has_the_standard_skeleton(pages):
    for name, t in only_pages(pages).items():
        first = t.splitlines()[0]
        assert first.startswith(f".TH {name.upper().replace('-', chr(92) + '-')} 1 ")
        assert '"2026-01-01"' in first and "cora-sentinel " in first
        for sec in ("NAME", "SYNOPSIS", "DESCRIPTION", "SEE ALSO", "REPORTING BUGS"):
            assert f".SH {sec}\n" in t, (name, sec)
        assert re.search(rf"\.SH NAME\n{re.escape(name.replace('-', chr(92) + '-'))} \\\-\s+\S", t), name
        assert ".SH EXIT STATUS" in t, f"{name} must say what its exit status means"
        assert t.isascii()


def test_no_option_or_command_is_listed_without_a_description(pages):
    for name, t in only_pages(pages).items():
        L = t.splitlines()
        empty = [L[i + 1] for i, l in enumerate(L) if l == ".TP" and i + 2 < len(L) and L[i + 2].startswith(".")]
        assert not empty, f"{name}: no description for {empty}: give the option a help= in the code"


def _documented(page: str, flag: str) -> bool:
    return flag.replace("-", "\\-") in page


PARSERS = {"cora-sentinel": ("cora_sentinel.daemon", "main"), "cora-floor": ("cora_sentinel.nftsets", "main"),
           "cora-blocklist": ("cora_sentinel.blocklist_store", "main"), "cora-report": ("cora_sentinel.report", "main"),
           "cora-demo": ("cora_sentinel.demo", "main")}


@pytest.mark.parametrize("name", sorted(PARSERS))
def test_every_option_and_subcommand_the_parser_accepts_is_in_the_page(pages, name):
    import argparse
    parsers = [gen_man.capture(*PARSERS[name], prog=name)]
    if name == "cora-floor":
        parsers.append(importlib_dynreplay().build_parser())
    page = pages[name]
    for p in parsers:
        for act in p._actions:
            if act.help == argparse.SUPPRESS or isinstance(act, argparse._HelpAction):
                continue
            if isinstance(act, argparse._SubParsersAction):
                shown = {a.dest for a in act._choices_actions if a.help != argparse.SUPPRESS}
                for sub, sp in act.choices.items():
                    if sub in shown:
                        assert f"\\fB{sub.replace('-', chr(92) + '-')}\\fR" in page, f"{name}: subcommand {sub}"
                        for a in sp._actions:
                            for o in a.option_strings:
                                if a.help != argparse.SUPPRESS and not isinstance(a, argparse._HelpAction):
                                    assert _documented(page, o), f"{name} {sub}: {o}"
                continue
            for o in act.option_strings:
                assert _documented(page, o), f"{name}: {o}"


def importlib_dynreplay():
    import importlib
    return importlib.import_module("cora_sentinel.dynreplay")


def test_the_hand_parsed_tools_document_every_subcommand_in_their_usage_text(pages):
    import importlib
    for name, mod in (("cora-cgroup", "cora_sentinel.cgroup"), ("cora-firewall", "cora_sentinel.firewall")):
        doc = importlib.import_module(mod).__doc__
        usage = next(l for l in doc.splitlines() if l.strip().startswith(name + " "))
        words = {chunk.strip().split()[0] for chunk in usage.strip()[len(name):].split("|")}
        assert len(words) >= 3, (name, words)
        for w in words:
            assert f"\\fB{w}\\fR" in pages[name], f"{name}: subcommand {w} is in its usage text but not in its page"


@pytest.mark.parametrize("name,module", [("cora-run", "run"), ("cora-cgroup", "cgroup"), ("cora-firewall", "firewall"),
                                         ("cora-floor", "nftsets"), ("cora-blocklist", "blocklist_store")])
def test_every_environment_variable_a_tool_reads_is_documented(pages, name, module):
    src = (SRC / f"{module}.py").read_text()
    for var in sorted(set(re.findall(r'os\.environ\.get\("(CORA_[A-Z_]+)"', src))):
        assert var.replace("_", "\\_") in pages[name] or var in pages[name], f"{name} reads {var} but its page does not say so"


def test_see_also_points_only_at_pages_that_exist(pages):
    for name, t in only_pages(pages).items():
        refs = re.findall(r"\\fB([\w\\-]+)\\fR\(1\)", t.split(".SH SEE ALSO", 1)[1])
        assert refs, name
        for r in refs:
            assert r.replace("\\-", "-") in only_pages(pages), f"{name} points at {r}(1), which does not exist"


def test_the_pages_are_reproducible(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    gen_man.main(["--out", str(a), "--date", "2026-01-01"])
    gen_man.main(["--out", str(b), "--date", "2026-01-01"])
    assert {p.name: p.read_bytes() for p in a.iterdir()} == {p.name: p.read_bytes() for p in b.iterdir()}


def test_escaping_keeps_roff_safe():
    assert gen_man.esc("--flag a\\b") == "\\-\\-flag a\\eb"
    assert gen_man.esc("a \u2192 b \u00e9") == "a \\-> b \\[u00E9]".replace("\\->", "\\->")
    assert gen_man.guard(".TH injected").startswith("\\&.") and gen_man.guard("'quote").startswith("\\&'")
    assert gen_man.text("use **--out** and //FILE//") == "use \\fB\\-\\-out\\fR and \\fIFILE\\fR"
