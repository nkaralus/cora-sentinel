"""Zero-GPU self-test and adversarial corpus.  Run: python -m mule.selftest"""
from __future__ import annotations

import json
import sys

from . import MuleValidator

_DROP = object()


def good_block(**over):
    b = {
        "frame_id": "0x00ff", "time_slot": "SLOT_3_EXECUTE", "subnet": "10.1.1.0/24",
        "op": "bind_move", "target": "%Player", "ref": "10.1.1.10",
        "exclude": ["untyped_variables", "relative_paths_up_tree"],
    }
    for k, v in over.items():
        if v is _DROP:
            b.pop(k, None)
        else:
            b[k] = v
    return b


def dumps(b, ascii_only=True):
    return json.dumps(b, separators=(",", ":"), ensure_ascii=ascii_only)


def _o(**kw):
    return dumps(good_block(**kw))


def _u(**kw):  # raw non-ASCII, unescaped
    return dumps(good_block(**kw), ascii_only=False)


G = dumps(good_block())
GOOD_RAW = G

BAD = [
    # --- framing / text-level ---
    ("fence_block", "```json\n" + G + "\n```"),
    ("fence_inline", "```" + G + "```"),
    ("preamble", "Sure! " + G),
    ("trailing_prose", G + " Hope that helps"),
    ("think_block", "<think>hmm</think>" + G),
    ("two_objects", G + G),
    ("trailing_newline", G + "\n"),
    ("leading_space", " " + G),
    ("embedded_newline", G.replace(",", ",\n", 1)),
    ("crlf", G + "\r\n"),
    ("tab", G.replace(":", ":\t", 1)),
    ("bom", "\ufeff" + G),
    ("line_separator_u2028", G.replace(",", ",\u2028", 1)),
    ("nul_byte", G.replace("op", "o\x00p", 1)),
    ("empty", ""),
    ("whitespace_only", "   "),
    ("not_object_array", "[" + G + "]"),
    ("not_object_null", "null"),
    ("not_object_string", '"hello"'),
    ("empty_object", "{}"),
    ("oversize", '{"a":"' + "x" * 3000 + '"}'),
    ("deep_nesting", '{"a":' * 200 + "1" + "}" * 200),
    ("deep_arrays_oversize", "{" + "[" * 5000),
    # --- JSON parser quirks ---
    ("dup_key", G[:-1] + ',"op":"other_op"}'),
    ("dup_key_unicode_escape", G[:-1] + ',"\\u006fp":"x"}'),
    ("nan", G.replace('"bind_move"', "NaN")),
    ("infinity", G.replace('"bind_move"', "Infinity")),
    ("neg_infinity", G.replace('"bind_move"', "-Infinity")),
    ("float_literal", G.replace('"0x00ff"', "1.0")),
    ("float_overflow", G.replace('"0x00ff"', "1e999")),
    ("huge_int", G.replace('"0x00ff"', "9" * 1500)),
    # --- escapes / unicode ---
    ("escaped_nul", _o(op="a\u0000b")),
    ("escaped_bidi_override", _o(target="%Pl\u202eayer")),
    ("escaped_newline_in_value", _o(frame_id="0x00ff\n")),
    ("raw_cyrillic_homoglyph", _u(target="%\u0420layer")),
    ("raw_zero_width_space", _u(target="%Pla\u200byer")),
    ("raw_fullwidth_digits_ref", _u(ref="\uff11\uff10.1.1.10")),
    ("raw_non_ascii_key", _u(**{"fr\u0430me_id": "0x0001"})),
    ("raw_emoji_in_exclude", _u(exclude=["untyped_variables", "\U0001F600"])),
    # --- keys ---
    ("extra_key", _o(note="hi")),
    ("extra_key_proto", _o(__proto__="x")),
    ("missing_exclude", _o(exclude=_DROP)),
    ("missing_target", _o(target=_DROP)),
    ("renamed_key_case", G.replace('"op"', '"Op"')),
    # --- types ---
    ("frame_id_int", _o(frame_id=1)),
    ("frame_id_bool", _o(frame_id=True)),
    ("time_slot_int", _o(time_slot=1)),
    ("time_slot_true", _o(time_slot=True)),
    ("target_null", _o(target=None)),
    ("target_list", _o(target=["%Player"])),
    ("exclude_string", _o(exclude="untyped_variables")),
    ("exclude_null", _o(exclude=None)),
    ("exclude_nested", _o(exclude=[["a"]])),
    ("exclude_int_item", _o(exclude=[1])),
    ("exclude_bool_item", _o(exclude=[True])),
    ("exclude_dupes", _o(exclude=["a_b", "a_b"])),
    ("exclude_too_many", _o(exclude=[f"e{i}" for i in range(17)])),
    ("exclude_upper_item", _o(exclude=["Untyped"])),
    ("exclude_empty_item", _o(exclude=[""])),
    ("exclude_long_item", _o(exclude=["a" * 49])),
    # --- values ---
    ("frame_id_short", _o(frame_id="0x00f")),
    ("frame_id_long", _o(frame_id="0x00fff")),
    ("frame_id_nohex", _o(frame_id="0x00gg")),
    ("frame_id_no_prefix", _o(frame_id="00ff")),
    ("time_slot_unknown", _o(time_slot="SLOT_6_FLY")),
    ("time_slot_lower", _o(time_slot="slot_3_execute")),
    ("op_upper", _o(op="BindMove")),
    ("op_space", _o(op="bind move")),
    ("op_too_long", _o(op="a" * 33)),
    ("op_empty", _o(op="")),
    ("target_no_percent", _o(target="Player")),
    ("target_lower_first", _o(target="%player")),
    ("target_traversal", _o(target="%../Player")),
    ("target_slash", _o(target="%Pl/ayer")),
    ("target_too_long", _o(target="%P" + "a" * 64)),
    ("subnet_octet_300", _o(subnet="10.300.1.0/24", ref="10.300.1.10")),
    ("subnet_not_24", _o(subnet="10.1.1.0/16")),
    ("subnet_not_ten", _o(subnet="192.168.1.0/24", ref="192.168.1.10")),
    ("subnet_host_bits", _o(subnet="10.1.1.5/24")),
    ("subnet_leading_zero", _o(subnet="10.01.1.0/24")),
    ("ref_octet_256", _o(ref="10.1.1.256")),
    ("ref_leading_zero", _o(ref="10.1.01.10")),
    ("ref_outside_subnet", _o(ref="10.1.2.10")),
    ("ref_is_network_addr", _o(ref="10.1.1.0")),
    ("ref_is_broadcast", _o(ref="10.1.1.255")),
    ("ref_ipv6", _o(ref="::1")),
    ("ref_with_port", _o(ref="10.1.1.10:80")),
    ("ref_trailing_dot", _o(ref="10.1.1.10.")),
]


def run(verbose: bool = True) -> int:
    v = MuleValidator()
    fails = 0
    ok, block, errs = v.validate_raw(GOOD_RAW)
    if not ok or block != good_block():
        fails += 1
        print("FAIL  good block rejected:", errs)
    elif verbose:
        print("PASS  good block accepted")
    for name, raw in BAD:
        ok, block, errs = v.validate_raw(raw)
        if ok or block != {} or not errs:
            fails += 1
            print(f"FAIL  {name}: accepted")
        elif verbose:
            print(f"PASS  {name:<28} -> {errs[0][:70]}")
    print(f"\n{len(BAD) + 1 - fails}/{len(BAD) + 1} checks passed")
    return 1 if fails else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
