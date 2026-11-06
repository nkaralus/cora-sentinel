"""The dynamic policy through the REAL daemon, end to end: a stub model (always ISOLATE, confidence 0.95), real cora-run
tasks, a real connection to a public address, real nft. Everything else in the dyn tests drives the policy directly; this
is the one that proves the daemon wires it up (flags, exemptions, the adjudicator hook, the decision log, the ledger).

It runs the daemon with `nsenter` (see test_floor_confirm.enter: `ip netns exec` would hide the cgroup mount), needs
root, nft, ip netns, nsenter and a cgroup v2 mount (CORA_TEST_CGROUP_MOUNT), and skips otherwise.
Run: sudo -E $(which python) -m pytest -q tests/test_daemon_dyn.py
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from cora_sentinel import dynreplay
from cora_sentinel.nftsets import NftSets

from test_floor_confirm import CG, daemon_kernel, enter
from test_floor_gate import PORT, S_IP, TABLE, Lab, kernel, ns_runner, sh

G, GPORT = "45.33.32.156", 8080
STUB = '''
class Llama:
    def __init__(self, **kw): pass
    def create_chat_completion(self, **kw):
        return {"choices": [{"message": {"content": '{"verdict":"ISOLATE","confidence":0.95,"reason":"stub"}'}}]}
class LlamaGrammar:
    @staticmethod
    def from_string(s): return object()
'''
HOLDER = f"""
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", {GPORT})); s.listen(64)
held = []
print("listening", flush=True)
while True:
    c, _ = s.accept(); held.append(c)
"""
TASK = f"""
import socket, sys, time
s = socket.socket(); s.settimeout(2.5)
try:
    s.connect(("{G}", {GPORT})); r = "ok"
except OSError:
    r = "fail"
open(sys.argv[1], "w").write(r)
time.sleep(float(sys.argv[2]))
"""


def until(cond, timeout=25.0, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(step)
    return None


@pytest.fixture
def world(tmp_path):
    lab = Lab(tmp_path, ports=(PORT,))
    sh("ip", "-n", lab.s, "addr", "add", f"{G}/32", "dev", lab.vs)
    sh("ip", "-n", lab.c, "route", "add", f"{G}/32", "via", S_IP)
    holder = subprocess.Popen([*enter(lab.s), sys.executable, "-c", HOLDER], stdout=subprocess.PIPE, text=True)
    assert holder.stdout.readline().strip() == "listening"
    stub = tmp_path / "stub"
    (stub / "llama_cpp").mkdir(parents=True)
    (stub / "llama_cpp" / "__init__.py").write_text(STUB)
    (tmp_path / "model.gguf").write_text("")
    w = type("W", (), {})()
    w.lab, w.tmp, w.holder, w.procs = lab, tmp_path, holder, []
    w.root = f"{CG}/cfdyn-{os.getpid()}-{time.monotonic_ns() % 100000}"
    w.env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(stub)] + [p for p in sys.path if p]),
                 CORA_CGROUP_ROOT=w.root, CORA_CGROUP_MOUNT=CG, CORA_NFT_TABLE=TABLE)
    w.dec, w.state = tmp_path / "decisions.jsonl", str(tmp_path / "st")
    w.sets = NftSets(table=TABLE, run=ns_runner(lab.c))
    yield w
    for p in w.procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(8)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
    holder.kill()
    holder.wait()
    lab.close()
    for d in sorted(Path(w.root).glob("*")) if Path(w.root).exists() else []:
        try:
            os.rmdir(d)
        except OSError:
            pass
    try:
        os.rmdir(w.root)
    except OSError:
        pass


def daemon(w, *extra):
    p = subprocess.Popen(
        [*enter(w.lab.c), sys.executable, "-m", "cora_sentinel.daemon", "--cgroup-root", w.root, "--cgroup-mount", CG,
         "--nft", "--nft-table", TABLE, "--model", str(w.tmp / "model.gguf"), "--decisions", str(w.dec),
         "--out", str(w.tmp / "events.jsonl"), "--report-dir", str(w.tmp / "reports"), "--state-dir", w.state,
         "--net-source", "proc", "--net-interval", "0.1", "--interval", "0.5", "--no-resolve", *extra],
        env=w.env, stderr=subprocess.PIPE, text=True)
    w.procs.append(p)
    w.err = []
    threading.Thread(target=lambda: [w.err.append(l) for l in p.stderr], daemon=True).start()
    return p


def saw(w, text, timeout=20):
    return until(lambda: any(text in l for l in w.err), timeout)


def task(w, name, hold=6.0):
    out = Path(f"/tmp/{name}-{os.getpid()}.result")
    out.unlink(missing_ok=True)
    p = subprocess.Popen([*enter(w.lab.c), sys.executable, "-m", "cora_sentinel.run", name, sys.executable, "-c", TASK,
                          str(out), str(hold)], env=w.env, stderr=None)
    w.procs.append(p)
    return out


def decisions(w):
    try:
        return [json.loads(l) for l in w.dec.read_text().splitlines() if l.strip()]
    except OSError:
        return []


def dyn_decision(w, result=None):
    return until(lambda: next((d for d in decisions(w) if d.get("dyn") and (result is None or d["dyn"]["result"] == result)), None))


@kernel
@daemon_kernel
def test_shadow_through_the_daemon_records_what_it_would_block_and_touches_nothing(world):
    w = world
    daemon(w)                                                            # shadow is the default; dry-run adjudicator
    assert saw(w, "dyn policy: shadow"), w.err
    r = task(w, "shadowtask")
    assert until(lambda: r.exists() and r.read_text() == "ok"), "the task could not reach the lab's public address"
    d = dyn_decision(w)
    assert d, (decisions(w), w.err)
    assert d["final"] == "ISOLATE" and d["action"].startswith("dry-run:")
    assert d["dyn"]["result"] == "would_block" and d["dyn"]["mode"] == "shadow"
    assert d["dyn"]["key"] == f"{G}|tcp|{GPORT}" and d["dyn"]["ttl_s"] == 600
    assert w.sets.status()["dynflow4"] < 0, "shadow created kernel sets"        # no floor, no dyn sets: nothing was written
    out = subprocess.run([*enter(w.lab.c), sys.executable, "-m", "cora_sentinel.nftsets", "--state-dir", w.state,
                          "dyn", "--mode", "shadow"], env=w.env, capture_output=True, text=True).stdout
    assert f"{G}|tcp|{GPORT}" in out and "[shadow] 1 active" in out
    # the replay harness must reproduce what this REAL daemon recorded, from the two logs it wrote
    rc = dynreplay.main([str(w.dec), "--events", str(w.tmp / "events.jsonl"), "--check", "--kernel", "off", "--json"])
    assert rc == 0, "the replay does not reproduce the daemon's own shadow decision"


@kernel
@daemon_kernel
def test_enforce_through_the_daemon_closes_the_first_packet_gap_for_the_next_task(world):
    """The point of the whole feature: task A is isolated for talking to a public address; task B, which has done
    nothing wrong yet, cannot get its FIRST packet to that address out."""
    w = world
    daemon(w, "--enforce", "--floor", "--dyn-policy", "enforce")
    assert saw(w, "kernel floor on") and saw(w, "dyn policy: enforce"), w.err
    a = task(w, "taska")
    assert until(lambda: a.exists() and a.read_text() == "ok")           # A reaches it once (it is what gets A isolated)
    d = dyn_decision(w, "blocked")
    assert d and d["action"].startswith("done:ISOLATE") and d["dyn"]["mode"] == "enforce", (decisions(w), w.err)
    assert w.sets.live_flows() == {f"{G}|tcp|{GPORT}"}                   # in the kernel, in the ledger's key format
    b = task(w, "taskb")                                                 # a brand-new task, never judged
    assert until(lambda: b.exists()) and b.read_text() == "fail", "B's first packet got out"
    assert w.sets.drop_counts()["out"] >= 1                              # dropped by the floor, not by B being isolated
    rc = dynreplay.main([str(w.dec), "--events", str(w.tmp / "events.jsonl"), "--check", "--kernel", "off", "--json"])
    assert rc == 0, "the replay does not reproduce the daemon's enforce decision"
