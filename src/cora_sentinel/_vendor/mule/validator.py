"""Strict, stdlib-only validator for Mule Task Blocks.

Contract
  validate_raw(raw) -> (ok, block, errors)
  `block` is {} unless ok is True, so unvalidated data never leaves this module.

Scope
  Syntactic checks only. Registry existence and subnet isolation belong to the
  bus (GI_1 / GI_2), not here. The one cross-field check (ref inside subnet) is
  pure IP arithmetic and needs no registry.

Raw-text policy (all rejected before JSON parsing)
  non-ASCII, control characters (incl. newline/tab/BOM), backslashes, markdown
  fences, anything not starting with '{' and ending with '}', oversize input.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["MuleValidator"]

_RULE_KEYS = {
    "type", "pattern", "enum", "format", "minLength", "maxLength",
    "minItems", "maxItems", "uniqueItems", "items", "minimum", "maximum",
    "description",
}
_TYPES = {"string", "integer", "boolean", "array"}
_DEFAULT_MAX_STR = 128
_DEFAULT_MAX_ITEMS = 16
_MAX_ERRORS = 20
_TEN = ipaddress.ip_network("10.0.0.0/8")
_SLOT_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}", re.ASCII)


class _Reject(ValueError):
    pass


def _show(v: Any) -> str:
    """Safe, bounded, ASCII-only rendering of untrusted values for error text."""
    s = ascii(v)
    return s if len(s) <= 40 else s[:37] + "..."


def _no_dupes(pairs):
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _Reject(f"duplicate key {_show(k)}")
        out[k] = v
    return out


def _no_const(name: str):
    raise _Reject(f"non-finite constant {name} not allowed")


def _no_float(text: str):
    raise _Reject(f"float {_show(text)} not allowed")


def _fmt_net24(v: str) -> None:
    n = ipaddress.ip_network(v, strict=True)
    if n.version != 4 or n.prefixlen != 24 or not n.subnet_of(_TEN):
        raise ValueError(v)


def _fmt_host(v: str) -> None:
    a = ipaddress.ip_address(v)
    if a.version != 4 or a not in _TEN:
        raise ValueError(v)


_FORMATS = {"ipv4_net24": _fmt_net24, "ipv4_host": _fmt_host}
_CROSS = {"ref_in_subnet"}


class MuleValidator:
    def __init__(
        self,
        spec: Optional[Dict[str, Any]] = None,
        *,
        extensions: Optional[Dict[str, Dict[str, Any]]] = None,
        allowed_ops: Optional[set] = None,
        require_standard_exclusions: bool = False,
        tolerate_edge_whitespace: bool = False,
    ):
        if spec is None:
            from . import load_spec
            spec = load_spec()
        if spec.get("additionalProperties", False) is not False:
            raise ValueError("spec must set additionalProperties to false")
        self.spec = spec
        slots = dict(spec["slots"])
        for name, rules in (extensions or {}).items():
            if name in slots:
                raise ValueError(f"extension slot '{name}' collides with a core slot")
            slots[name] = rules
        self.slots = slots
        self._re: Dict[str, "re.Pattern[str]"] = {}
        for name, rules in slots.items():
            if not _SLOT_NAME.fullmatch(name):
                raise ValueError(f"bad slot name {name!r}")
            self._prepare(name, rules)
        self.cross = list(spec.get("cross_checks", []))
        for c in self.cross:
            if c not in _CROSS:
                raise ValueError(f"unknown cross_check {c!r}")
        self.max_raw = int(spec.get("limits", {}).get("max_raw_bytes", 2048))
        self.allowed_ops = set(allowed_ops) if allowed_ops else None
        self.require_std = require_standard_exclusions
        self.tolerate = tolerate_edge_whitespace

    # ---- spec compilation -------------------------------------------------
    def _prepare(self, path: str, rules: Dict[str, Any]) -> None:
        unknown = set(rules) - _RULE_KEYS
        if unknown:
            raise ValueError(f"{path}: unknown rule keys {sorted(unknown)}")
        t = rules.get("type")
        if t not in _TYPES:
            raise ValueError(f"{path}: unsupported type {t!r}")
        if "pattern" in rules:
            if t != "string":
                raise ValueError(f"{path}: pattern needs type string")
            self._re.setdefault(rules["pattern"], re.compile(rules["pattern"], re.ASCII))
        if "enum" in rules:
            e = rules["enum"]
            if t != "string" or not e or not all(type(x) is str for x in e):
                raise ValueError(f"{path}: enum must be a non-empty list of strings")
        if "format" in rules and rules["format"] not in _FORMATS:
            raise ValueError(f"{path}: unknown format {rules['format']!r}")
        if t == "array":
            if "items" not in rules:
                raise ValueError(f"{path}: array needs items")
            self._prepare(path + "[]", rules["items"])

    # ---- public API -------------------------------------------------------
    def validate_raw(
        self, raw_output: str, expect: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Dict[str, Any], List[str]]:
        block, errs = self._parse(raw_output)
        if block is None:
            return False, {}, errs
        ok, errs = self._validate(block, expect)
        return ok, (block if ok else {}), errs

    def validate_block(
        self, block: Any, expect: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Dict[str, Any], List[str]]:
        """For already-parsed dicts. Cannot detect duplicate keys; prefer validate_raw."""
        ok, errs = self._validate(block, expect)
        return ok, (block if ok else {}), errs

    # ---- raw text -> dict -------------------------------------------------
    def _parse(self, raw: Any) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        if type(raw) is not str:
            return None, ["raw output must be str"]
        if self.tolerate:
            raw = raw.strip(" \t\r\n")
        if not raw:
            return None, ["empty output"]
        if len(raw) > self.max_raw:
            return None, [f"output longer than {self.max_raw} characters"]
        if not raw.isascii():
            return None, ["non-ASCII character in raw output"]
        for ch in raw:
            if ord(ch) < 0x20 or ord(ch) == 0x7F:
                return None, [f"control character U+{ord(ch):04X}: block must be one line, no tabs"]
        if "```" in raw:
            return None, ["markdown fence not allowed"]
        if "\\" in raw:
            return None, ["backslash escapes not allowed"]
        if raw[0] != "{" or raw[-1] != "}":
            return None, ["must start with '{' and end with '}': no preamble, think-block, or trailing text"]
        try:
            block = json.loads(
                raw,
                object_pairs_hook=_no_dupes,
                parse_constant=_no_const,
                parse_float=_no_float,
            )
        except _Reject as e:
            return None, [f"JSON rejected: {e}"]
        except json.JSONDecodeError as e:
            return None, [f"JSON parse failure: {e.msg} at col {e.colno}"]
        except (RecursionError, ValueError) as e:
            return None, [f"JSON rejected: {type(e).__name__}"]
        if type(block) is not dict:
            return None, ["output must be a JSON object"]
        return block, []

    # ---- dict -> verdict --------------------------------------------------
    def _validate(self, block: Any, expect: Optional[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        errs: List[str] = []
        if type(block) is not dict:
            return False, ["block must be a dict"]
        for k in sorted(_show(k) for k in block if k not in self.slots):
            errs.append(f"unexpected key {k}")
        for name, rules in self.slots.items():
            if name not in block:
                errs.append(f"missing slot '{name}'")
            else:
                self._check(name, block[name], rules, errs)

        if not errs and self.allowed_ops is not None and block["op"] not in self.allowed_ops:
            errs.append(f"op {_show(block['op'])} not in allowed_ops")

        if not errs and "ref_in_subnet" in self.cross:
            net = ipaddress.ip_network(block["subnet"])
            host = ipaddress.ip_address(block["ref"])
            if host not in net:
                errs.append(f"ref {_show(block['ref'])} is outside subnet {_show(block['subnet'])}")
            elif host in (net.network_address, net.broadcast_address):
                errs.append("ref must be a host address, not network or broadcast")

        if not errs and self.require_std:
            missing = [e for e in self.spec.get("standard_exclusions", []) if e not in block["exclude"]]
            if missing:
                errs.append(f"exclude is missing standard exclusions: {missing}")

        for k, want in (expect or {}).items():
            if k not in self.slots:
                raise ValueError(f"expect names unknown slot {k!r}")
            got = block.get(k)
            if type(got) is not type(want) or got != want:
                errs.append(f"slot '{k}' must equal harness value {_show(want)}, got {_show(got)}")

        return not errs, errs[:_MAX_ERRORS]

    def _check(self, path: str, v: Any, rules: Dict[str, Any], errs: List[str]) -> None:
        t = rules["type"]
        if t == "string":
            if type(v) is not str:
                errs.append(f"{path}: must be string, got {type(v).__name__}")
                return
            if not v.isascii() or not v.isprintable():
                errs.append(f"{path}: must be printable ASCII")
                return
            if len(v) > rules.get("maxLength", _DEFAULT_MAX_STR):
                errs.append(f"{path}: too long")
            if len(v) < rules.get("minLength", 0):
                errs.append(f"{path}: too short")
            if "enum" in rules and v not in rules["enum"]:
                errs.append(f"{path}: {_show(v)} not in enum")
            if "pattern" in rules and not self._re[rules["pattern"]].fullmatch(v):
                errs.append(f"{path}: {_show(v)} violates pattern")
            fmt = rules.get("format")
            if fmt:
                try:
                    _FORMATS[fmt](v)
                except (ValueError, TypeError):
                    errs.append(f"{path}: {_show(v)} is not a valid {fmt}")
        elif t == "integer":
            if type(v) is not int:
                errs.append(f"{path}: must be integer, got {type(v).__name__}")
                return
            if "minimum" in rules and v < rules["minimum"]:
                errs.append(f"{path}: below minimum")
            if "maximum" in rules and v > rules["maximum"]:
                errs.append(f"{path}: above maximum")
        elif t == "boolean":
            if type(v) is not bool:
                errs.append(f"{path}: must be boolean, got {type(v).__name__}")
        elif t == "array":
            if type(v) is not list:
                errs.append(f"{path}: must be array, got {type(v).__name__}")
                return
            if len(v) > rules.get("maxItems", _DEFAULT_MAX_ITEMS):
                errs.append(f"{path}: too many items")
            if len(v) < rules.get("minItems", 0):
                errs.append(f"{path}: too few items")
            for i, item in enumerate(v):
                self._check(f"{path}[{i}]", item, rules["items"], errs)
            if rules.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in v}) != len(v):
                errs.append(f"{path}: items must be unique")
