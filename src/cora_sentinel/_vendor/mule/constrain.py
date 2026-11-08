"""Generate constrained-decoding artifacts from the spec (single source of truth).

  to_json_schema(spec)  -> dict   for Ollama `format`, vLLM / LM Studio /
                                   llama-server `response_format`
  to_gbnf(spec)         -> str    for llama.cpp `grammar`

Both force one-line, fixed key order, no whitespace, no escapes. Constrained
decoding is layer 1. MuleValidator is layer 2 and is the authority: the grammar
cannot express uniqueItems, IP octet ranges, or ref-in-subnet.

Spec patterns must stay inside a small regex subset: literals, escaped
punctuation, [classes], and ? * + {m} {m,n}. No groups, alternation, '.',
or \\d-style shorthands. regex_to_gbnf raises on anything else.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, Optional

from . import load_spec
from .validator import _DEFAULT_MAX_ITEMS, _DEFAULT_MAX_STR

__all__ = ["to_json_schema", "to_gbnf", "regex_to_gbnf"]

_DQ = r'"\""'
_PRINTABLE = r"[\x20\x21\x23-\x5b\x5d-\x7e]"  # printable ASCII minus " and \
_ESCAPABLE = set(".+*?(){}[]|^$/\\-%")


def _merge_slots(spec: Dict[str, Any], extensions: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    slots = dict(spec["slots"])
    slots.update(extensions or {})
    return slots


# ---- JSON Schema -----------------------------------------------------------
def _rule_to_schema(rules: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in ("type", "enum", "minLength", "maxLength", "minItems", "maxItems",
              "uniqueItems", "minimum", "maximum"):
        if k in rules:
            out[k] = copy.deepcopy(rules[k])
    if "pattern" in rules:
        out["pattern"] = "^" + rules["pattern"] + "$"
    if rules["type"] == "string":
        out.setdefault("maxLength", _DEFAULT_MAX_STR)
    if rules["type"] == "array":
        out.setdefault("maxItems", _DEFAULT_MAX_ITEMS)
        out["items"] = _rule_to_schema(rules["items"])
    return out


def to_json_schema(spec: Optional[Dict[str, Any]] = None, extensions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    spec = spec or load_spec()
    slots = _merge_slots(spec, extensions)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": spec.get("title", "MuleTaskBlock"),
        "type": "object",
        "properties": {name: _rule_to_schema(r) for name, r in slots.items()},
        "required": list(slots),
        "additionalProperties": False,
    }


# ---- regex subset -> GBNF --------------------------------------------------
def _lit(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def regex_to_gbnf(pattern: str) -> str:
    parts, lit = [], []

    def flush():
        if lit:
            parts.append(_lit("".join(lit)))
            lit.clear()

    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                raise ValueError(f"unterminated class in {pattern!r}")
            atom, is_lit = pattern[i:j + 1], False
            if "\\" in atom:
                raise ValueError(f"escapes inside classes unsupported: {pattern!r}")
            i = j + 1
        elif c == "\\":
            if i + 1 >= n or pattern[i + 1] not in _ESCAPABLE:
                raise ValueError(f"unsupported escape in {pattern!r}")
            atom, is_lit = pattern[i + 1], True
            i += 2
        elif c in "()|^$.":
            raise ValueError(f"unsupported regex syntax {c!r} in {pattern!r}")
        else:
            atom, is_lit = c, True
            i += 1
        q = ""
        if i < n and pattern[i] in "?*+":
            q, i = pattern[i], i + 1
        elif i < n and pattern[i] == "{":
            j = pattern.find("}", i)
            if j == -1:
                raise ValueError(f"unterminated quantifier in {pattern!r}")
            q, i = pattern[i:j + 1], j + 1
        if is_lit and not q:
            lit.append(atom)
        else:
            flush()
            parts.append((_lit(atom) if is_lit else atom) + q)
    flush()
    return " ".join(parts)


# ---- GBNF ------------------------------------------------------------------
def _rn(name: str) -> str:
    return name.replace("_", "-")


def _value(name: str, rules: Dict[str, Any], out: Dict[str, str]) -> str:
    t = rules["type"]
    if t == "string":
        if "enum" in rules:
            body = "(" + " | ".join(_lit(e) for e in rules["enum"]) + ")"
        elif "pattern" in rules:
            body = regex_to_gbnf(rules["pattern"])
        else:
            body = f"{_PRINTABLE}{{{rules.get('minLength', 0)},{rules.get('maxLength', _DEFAULT_MAX_STR)}}}"
        return f"{_DQ} {body} {_DQ}"
    if t == "integer":
        return '"-"? [0-9]{1,18}'
    if t == "boolean":
        return '("true" | "false")'
    if t == "array":
        item = _rn(name) + "-item"
        out[item] = _value(item, rules["items"], out)
        mn, mx = rules.get("minItems", 0), rules.get("maxItems", _DEFAULT_MAX_ITEMS)
        if mx == 0:
            return '"[" "]"'
        rest = f' ("," {item}){{{max(mn - 1, 0)},{mx - 1}}}' if mx > 1 else ""
        return f'"[" {item}{rest} "]"' if mn >= 1 else f'"[" ({item}{rest})? "]"'
    raise NotImplementedError(t)


def to_gbnf(spec: Optional[Dict[str, Any]] = None, extensions: Optional[Dict[str, Any]] = None) -> str:
    spec = spec or load_spec()
    slots = _merge_slots(spec, extensions)
    rules_out: Dict[str, str] = {}
    keys = []
    for name, rules in slots.items():
        rules_out[_rn(name)] = _value(name, rules, rules_out)
        keys.append(f'"\\"{name}\\":" {_rn(name)}')
    root = 'root ::= "{" ' + ' "," '.join(keys) + ' "}"'
    return "\n".join([root] + [f"{k} ::= {v}" for k, v in rules_out.items()]) + "\n"
