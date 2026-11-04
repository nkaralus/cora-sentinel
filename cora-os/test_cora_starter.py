"""Keeps the files you commit to cora-security in lockstep with the code. Run: pytest -q test_cora_starter.py"""
import json
from pathlib import Path

import pytest

from cora_blocklist import Blocklist
from cora_report import JSON_SCHEMA, validate_report

S = Path(__file__).parent / "cora-security-starter"
pytestmark = pytest.mark.skipif(not S.exists(), reason="cora-security-starter/ folder not present (flat download); unzip the archive to run these")


def test_committed_schema_is_exactly_what_the_code_validates_against():
    assert json.loads((S / "violation.schema.json").read_text()) == JSON_SCHEMA


def test_example_report_is_valid_two_ways():
    ex = json.loads((S / "examples" / "violation.example.json").read_text())
    validate_report(ex)
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(JSON_SCHEMA)
    jsonschema.validate(ex, JSON_SCHEMA)


def test_starter_blocklists_load_clean():
    b = Blocklist()
    assert b.load(S / "blocklists") == 18          # 15 domains + 3 placeholder nets
    assert not b.rejects and len(b.domains) == 15 and b.n_nets == 3
    assert b.match_domain("x.doubleclick.net").list == "trackers-starter"
    assert b.match_net("198.51.100.9").list == "rogue-subnets"


def test_allow_dir_ships_with_no_active_entries():
    a = Blocklist()
    assert a.load(S / "allow") == 0 and not a.rejects


def test_starter_has_no_fake_threat_intel():
    # the only network entries are RFC 5737 documentation ranges
    import ipaddress
    docs = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for line in (S / "blocklists" / "rogue-subnets.txt").read_text().splitlines():
        tok = line.split(";")[0].split("#")[0].strip()
        if tok:
            assert any(ipaddress.ip_network(tok, strict=False).subnet_of(d) for d in docs), tok
