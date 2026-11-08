"""Prompt builders for Mule models. Generated from the spec so they cannot drift."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from . import load_spec

__all__ = ["build_system_prompt", "build_state", "build_messages", "RECOMMENDED_SAMPLING", "EXAMPLE"]

# Deterministic decoding. stop=["\n"] enforces single-line even without a grammar.
RECOMMENDED_SAMPLING = {"temperature": 0, "max_tokens": 256, "stop": ["\n"]}

MAX_INTENT_CHARS = 500

EXAMPLE = {
    "intent": "bind arrow-key movement to the player",
    "frame_id": "0x0001",
    "subnet": "10.1.1.0/24",
    "op": "bind_move",
    "target": "%Player",
    "ref": "10.1.1.10",
}


def _compact(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))  # ensure_ascii=True: non-ASCII becomes \uXXXX


def build_system_prompt(spec: Optional[Dict[str, Any]] = None) -> str:
    spec = spec or load_spec()
    keys = ", ".join(spec["slots"])
    return (
        "You are a slot-filling component, not an assistant.\n"
        "Reply with exactly one JSON object on one line. Nothing before it. Nothing after it.\n"
        f"Keys, in this order: {keys}.\n"
        "Rules:\n"
        "1. Copy frame_id, subnet, op, target and ref exactly from STATE.\n"
        "2. time_slot is one of TIME_SLOTS from STATE.\n"
        "3. exclude is a JSON array of strings. Include every item of STANDARD_EXCLUSIONS.\n"
        "4. No other keys. No markdown. No code fences. No thinking tags. No comments. No line breaks.\n"
        "5. Unsure? Still output the block, copying STATE. Never ask questions."
    )


def build_state(
    intent: str, *, frame_id: str, subnet: str, op: str, target: str, ref: str,
    spec: Optional[Dict[str, Any]] = None,
) -> str:
    """User turn. All values should come from the registry; `intent` is untrusted text."""
    spec = spec or load_spec()
    if len(intent) > MAX_INTENT_CHARS:
        raise ValueError(f"intent longer than {MAX_INTENT_CHARS} characters")
    state = {
        "intent": intent, "frame_id": frame_id, "subnet": subnet, "op": op,
        "target": target, "ref": ref,
        "TIME_SLOTS": spec["slots"]["time_slot"]["enum"],
        "STANDARD_EXCLUSIONS": spec["standard_exclusions"],
    }
    return "STATE: " + _compact(state) + "\nOUTPUT:"


def _example_block(spec: Dict[str, Any]) -> str:
    block = {
        "frame_id": EXAMPLE["frame_id"], "time_slot": "SLOT_3_EXECUTE",
        "subnet": EXAMPLE["subnet"], "op": EXAMPLE["op"], "target": EXAMPLE["target"],
        "ref": EXAMPLE["ref"], "exclude": list(spec["standard_exclusions"]),
    }
    return _compact(block)


def build_messages(
    intent: str, *, frame_id: str, subnet: str, op: str, target: str, ref: str,
    few_shot: bool = True, fold_system: bool = False, spec: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Chat messages. fold_system=True merges the system prompt into the first user
    turn, for templates with no system role (Gemma)."""
    spec = spec or load_spec()
    system = build_system_prompt(spec)
    turns: List[Dict[str, str]] = []
    if few_shot:
        ex = {k: v for k, v in EXAMPLE.items()}
        turns.append({"role": "user", "content": build_state(
            ex.pop("intent"), spec=spec, **ex)})
        turns.append({"role": "assistant", "content": _example_block(spec)})
    turns.append({"role": "user", "content": build_state(
        intent, frame_id=frame_id, subnet=subnet, op=op, target=target, ref=ref, spec=spec)})
    if fold_system:
        turns[0] = {"role": "user", "content": system + "\n\n" + turns[0]["content"]}
        return turns
    return [{"role": "system", "content": system}] + turns
