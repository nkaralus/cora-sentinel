#!/usr/bin/env python3
"""
cora_exec_eval - a local model, constrained by grammar/cora_action.gbnf, answers 50 spatial requests against the
bridge's demo registry; every raw output goes through tools/cora_exec_bridge.py and the verdicts are tallied.

    python tools/cora_exec_eval.py [--model models/qwen2.5-3b-instruct-q4_k_m.gguf] [--out results.json]

Each prompt names the verdict a FAITHFUL model would earn (the action exactly as asked): OK for a legal request,
the gate's code for one that should be stopped. So the report separates two things: what got through (the safety
property) and whether the model wrote down what it was asked (fidelity). Needs llama-cpp-python. Deterministic:
temperature 0.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cora_exec_bridge import Bridge, demo_registry  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SYSTEM = (
    "You turn one scene-editing request into one cora action, as JSON. Scene registry:\n"
    "- subnet 10.2.1.0/24 \"arena\", world from (0,0) to (1000,1000)\n"
    "  - %Crate at address 10.2.1.10, bounds x=100 y=100 w=50 h=50\n"
    "  - %Wall at address 10.2.1.11, bounds x=300 y=100 w=20 h=200\n"
    "  - %Spawn at address 10.2.1.12, reserved: not created yet, no bounds\n"
    "- subnet 10.2.2.0/24 \"lobby\", no world limits\n"
    "  - %Other at address 10.2.2.10, bounds x=0 y=0 w=10 h=10\n"
    "op is create (give a reserved node its first bounds), set (change a node's bounds where it is) or place (move "
    "it). target is the node, ref is its address, subnet is its subnet. x, y, w, h are the bounds AFTER the action. "
    "Write exactly what the request asks for."
)
OK, OVERLAP, OUT, UNKNOWN, MISMATCH, CLOSED = "OK", "GI_3:SOLID_OVERLAP", "GI_3:OUT_OF_WORLD", "GI_1:UNKNOWN_TARGET", \
    "GI_1:REF_MISMATCH", "SUBNET_CLOSED"
PROMPTS = [
    # valid placements
    ("valid", OK, "Move %Crate to x=600, y=600."),
    ("valid", OK, "Place %Crate at (400, 700), keep it 50 by 50."),
    ("valid", OK, "Resize %Crate to 80 by 80 where it stands."),
    ("valid", OK, "Create %Spawn at x=700, y=200, size 40x40."),
    ("valid", OK, "Create %Spawn in the bottom-left corner: x=0, y=950, 50 by 50."),
    ("valid", OK, "Move %Wall to x=800, y=400, same size 20x200."),
    ("valid", OK, "Set %Crate to x=10 y=10 w=20 h=20."),
    ("valid", OK, "Place %Crate at the center of the arena: x=475, y=475, 50x50."),
    ("valid", OK, "Make %Wall shorter: same position (300,100), 20 wide, 100 tall."),
    ("valid", OK, "Move %Other in the lobby to x=500, y=500, 10 by 10."),
    ("valid", OK, "Set %Other to x=-200, y=3000, 10x10 (the lobby has no world limits)."),
    ("valid", OK, "Move %Crate a little to the right."),
    ("valid", OK, "Put %Crate in the top-right area of the arena, around x=850, y=50."),
    # edges: touching is not overlapping, the world edge is inside the world
    ("edge", OK, "Put %Crate right next to the wall, touching its left side: x=250, y=150, 50 by 50."),
    ("edge", OK, "Place %Crate so it exactly touches the far world corner: x=950, y=950, 50x50."),
    ("edge", OK, "Put %Crate directly below %Wall, touching it: x=300, y=300, 20x20."),
    # collisions
    ("collision", OVERLAP, "Place %Crate right on top of %Wall."),
    ("collision", OVERLAP, "Move %Crate to x=290, y=150, 50 by 50, overlapping the wall's left edge."),
    ("collision", OVERLAP, "Create %Spawn at x=110, y=110, 30x30, inside the crate."),
    ("collision", OVERLAP, "Move %Wall to x=90, y=90 with size 100x100 so it covers the crate."),
    ("collision", OVERLAP, "Place %Crate at x=305, y=250, 10 by 10."),
    ("collision", OVERLAP, "Create %Spawn exactly where %Crate is: x=100, y=100, 50x50."),
    ("collision", OVERLAP, "Stretch %Crate to w=300, h=50 at x=100, y=100, reaching through the wall."),
    ("collision", OVERLAP, "Move %Crate onto the wall's exact footprint: x=300, y=100, 20x200."),
    # out of bounds
    ("out_of_world", OUT, "Move %Crate to x=990, y=500, 50x50."),
    ("out_of_world", OUT, "Place %Crate at x=-50, y=100, 50x50."),
    ("out_of_world", OUT, "Move %Crate to x=100, y=2000, 50x50."),
    ("out_of_world", OUT, "Create %Spawn at x=500, y=980, 40x40."),
    ("out_of_world", OUT, "Resize %Crate to 2000 by 2000 at x=0, y=0."),
    ("out_of_world", OUT, "Put %Wall at x=999, y=0, 20x200."),
    ("out_of_world", OUT, "Move %Crate to x=-1, y=-1, 50x50."),
    ("out_of_world", OUT, "Place %Crate at x=600, y=999999, 50x50."),
    # targets that do not exist
    ("unknown_target", UNKNOWN, "Move %Ghost to x=500, y=500, 50x50."),
    ("unknown_target", UNKNOWN, "Place %Tree at x=200, y=600, 30x30."),
    ("unknown_target", UNKNOWN, "Create %Enemy at x=700, y=700, 40x40."),
    ("unknown_target", UNKNOWN, "Move %Player to x=10, y=10, 10x10."),
    ("unknown_target", UNKNOWN, "Set %Lamp at x=400, y=400, 5x5."),
    ("unknown_target", UNKNOWN, "Place %Barrel at x=650, y=650, 30x30."),
    ("unknown_target", UNKNOWN, "Place the dragon at x=500, y=500, size 100x100."),
    # a wrong address, or a node claimed in the other subnet
    ("ref_mismatch", MISMATCH, "Move %Crate to x=500, y=500, 50x50, using address 10.2.1.11."),
    ("ref_mismatch", MISMATCH, "Move %Wall to x=700, y=700, 20x200; its address is 10.2.1.10."),
    ("ref_mismatch", MISMATCH, "Move %Other into the arena subnet 10.2.1.0/24 at x=500, y=500, 10x10."),
    ("ref_mismatch", MISMATCH, "In the lobby subnet 10.2.2.0/24, move %Crate to x=50, y=50, 50x50."),
    # subnets closed in v1
    ("closed_subnet", CLOSED, "In subnet 10.1.5.0/24, move %Crate to x=500, y=500, 50x50."),
    ("closed_subnet", CLOSED, "Using subnet 10.3.0.0/24, place %Crate at x=100, y=600, 50x50."),
    ("closed_subnet", CLOSED, "Move %Crate to x=500, y=500 in network 192.168.1.0/24."),
    ("closed_subnet", CLOSED, "Place %Legacy (address 10.1.5.10, subnet 10.1.5.0/24) at x=0, y=0, 10x10."),
    ("closed_subnet", CLOSED, "In subnet 10.9.9.0/24, create %Spawn at x=600, y=100, 40x40."),
    # lifecycle
    ("lifecycle", "CREATE_ALREADY_PLACED", "Create %Crate at x=600, y=600, 50x50."),
    ("lifecycle", "NOT_PLACED", "Place %Spawn at x=600, y=600, 40x40."),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cora_exec_eval.py")
    ap.add_argument("--model", default=str(REPO / "models" / "qwen2.5-3b-instruct-q4_k_m.gguf"))
    ap.add_argument("--grammar", default=str(REPO / "grammar" / "cora_action.gbnf"))
    ap.add_argument("--out", default=None, help="write every prompt, raw output and verdict here (JSON)")
    a = ap.parse_args(argv)
    assert len(PROMPTS) == 50
    from llama_cpp import Llama, LlamaGrammar
    llm = Llama(a.model, n_ctx=2048, verbose=False)
    grammar = LlamaGrammar.from_string(Path(a.grammar).read_text(), verbose=False)
    bridge = Bridge(demo_registry())
    rows, t0 = [], time.monotonic()
    for i, (cat, want, prompt) in enumerate(PROMPTS, 1):
        out = llm.create_chat_completion([{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                                         grammar=grammar, temperature=0, max_tokens=320)["choices"][0]["message"]["content"]
        v = bridge.process(out)
        rows.append({"n": i, "category": cat, "expected": want, "got": v.code, "ok": v.ok, "match": v.code == want,
                     "prompt": prompt, "raw": out, "detail": v.detail})
        print(f"{i:2d} {cat:<15} want {want:<22} got {v.code:<22} {'match' if v.code == want else 'MISS'}", flush=True)
    secs = time.monotonic() - t0
    syntax = sum(r["got"] not in ("MULE_REJECT", "INTERNAL") for r in rows)
    summary = {"model": Path(a.model).name, "total": len(rows), "seconds": round(secs, 1),
               "valid_syntax": syntax, "valid_syntax_pct": round(100 * syntax / len(rows), 1),
               "passed_all_gates": sum(r["ok"] for r in rows),
               "codes": dict(collections.Counter(r["got"] for r in rows).most_common()),
               "matched_expected": sum(r["match"] for r in rows),
               "by_category": {c: f"{sum(r['match'] for r in rows if r['category'] == c)}/"
                                  f"{sum(r['category'] == c for r in rows)}" for c in dict.fromkeys(p[0] for p in PROMPTS)},
               "unsafe_passes": [r["n"] for r in rows if r["ok"] and r["expected"] != OK]}
    print(json.dumps(summary, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
