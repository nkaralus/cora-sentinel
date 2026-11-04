"""Keeps schema/ and examples/ in lockstep with the code. Run: pytest -q tests/test_examples.py"""
import ipaddress
import json
from pathlib import Path

import pytest

from cora_sentinel.blocklist import Blocklist
from cora_sentinel.report import JSON_SCHEMA, validate_report

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples"


def test_committed_schema_is_exactly_what_the_code_validates_against():
    assert json.loads((ROOT / "schema" / "violation.schema.json").read_text()) == JSON_SCHEMA


def test_example_report_is_valid_two_ways():
    ex = json.loads((EX / "violation.example.json").read_text())
    validate_report(ex)
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(JSON_SCHEMA)
    jsonschema.validate(ex, JSON_SCHEMA)


def test_starter_blocklists_load_clean():
    b = Blocklist()
    assert b.load(EX / "blocklists") == 18          # 15 domains + 3 placeholder nets
    assert not b.rejects and len(b.domains) == 15 and b.n_nets == 3
    assert b.match_domain("x.doubleclick.net").list == "trackers-starter"
    assert b.match_net("198.51.100.9").list == "rogue-subnets"


def test_allow_dir_ships_with_no_active_entries():
    a = Blocklist()
    assert a.load(EX / "allow") == 0 and not a.rejects


def test_starter_has_no_fake_threat_intel():
    docs = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]   # RFC 5737
    for line in (EX / "blocklists" / "rogue-subnets.txt").read_text().splitlines():
        tok = line.split(";")[0].split("#")[0].strip()
        if tok:
            assert any(ipaddress.ip_network(tok, strict=False).subnet_of(d) for d in docs), tok
