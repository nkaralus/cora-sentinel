"""The replay harness's kernel mode on a real kernel: every write is made in a private network namespace (`unshare -n`)
and a throwaway table, the real nft state is cross-checked against the policy's ledger, and the host is never touched.
Skips without root, nft and unshare. Run: sudo -E $(which python) -m pytest -q tests/test_dynreplay_kernel.py"""
import json
import re
import shutil
import subprocess
import sys

import pytest

from test_dynreplay import make_log
from test_floor_gate import kernel

needs_unshare = pytest.mark.skipif(not shutil.which("unshare"), reason="needs unshare")

# long enough for expiries, refreshes, a promotion and a throttled task to all happen
STEPS = ([(0, {"task": "w1", "port": 443}), (400, {"task": "w2", "port": 443}), (400, {"task": "w3", "port": 443}),
          (50, {"task": "s1", "ip": "45.33.33.7", "port": 8080}), (30, {"task": "s2", "ip": "45.33.33.7", "port": 9090}),
          (3000, {"task": "w4", "port": 443}), (20, {"task": "u1", "ip": "2606:4700::1", "port": 8443})]
         + [(5, {"task": "x%d" % i, "ip": f"45.34.0.{i}", "port": 7000 + i}) for i in range(10)] + [(4000, {"task": "late", "port": 443})])


def replay(dec, evp, *flags, stdin=None):
    return subprocess.run([sys.executable, "-m", "cora_sentinel.dynreplay", str(dec), "--events", str(evp), *flags],
                          capture_output=True, text=True, input=stdin)


def normalize_ruleset(text):
    """The host ruleset without its live state. Other traffic on the machine moves counters while the test runs (CI
    run #46: 'packets 521 bytes 231809' became 'packets 540 bytes 236688') and set timeouts count down; neither is a
    change to the ruleset. A rule added or removed still differs."""
    text = re.sub(r"packets \d+ bytes \d+", "packets N bytes N", text)
    return re.sub(r"expires \S+", "expires T", text)


def host_nft():
    return normalize_ruleset(subprocess.run(["nft", "-s", "list", "ruleset"], capture_output=True, text=True).stdout)


def test_the_ruleset_comparison_ignores_live_counters_but_not_rules():
    a = "table ip x {\n\tchain c {\n\t\tcounter packets 521 bytes 231809 accept\n\t}\n}\n"
    b = a.replace("packets 521 bytes 231809", "packets 540 bytes 236688")
    assert normalize_ruleset(a) == normalize_ruleset(b)
    assert normalize_ruleset("elements = { 1.2.3.4 expires 59s }") == normalize_ruleset("elements = { 1.2.3.4 expires 3s }")
    assert normalize_ruleset(a) != normalize_ruleset(a.replace("accept", "drop"))
    assert normalize_ruleset(a) != normalize_ruleset(a.replace("}\n}", "}\n\tchain d {\n\t}\n}"))


def test_the_normalizer_keeps_set_elements_and_everything_but_counters_and_timers():
    base = ("table inet cora {\n\tset floor4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\ttimeout 30s\n"
            "\t\telements = { 1.2.3.4 timeout 30s expires 12s, 5.6.7.8 timeout 30s expires 3s }\n\t}\n"
            "\tchain out {\n\t\ttype filter hook output priority 0; policy accept;\n"
            "\t\tip daddr @floor4 tcp dport 443 counter packets 9 bytes 540 drop\n\t}\n}\n")
    n = normalize_ruleset(base)
    assert n != normalize_ruleset(base.replace(", 5.6.7.8 timeout 30s expires 3s", ""))          # an element removed
    assert n != normalize_ruleset(base.replace("5.6.7.8", "5.6.7.8, 9.9.9.9"))                    # an element added
    assert n != normalize_ruleset(base.replace("counter packets 9 bytes 540 drop", "counter packets 9 bytes 540 accept"))
    for kept in ("timeout 30s", "dport 443", "priority 0", "1.2.3.4", "5.6.7.8", "counter", "@floor4", "policy accept"):
        assert kept in n, kept                                                                     # only state goes
    assert "expires 12s" not in n and "packets 9" not in n and n.count("expires T") == 2


@kernel
@needs_unshare
def test_kernel_mode_writes_to_a_private_namespace_and_agrees_with_the_ledger(tmp_path):
    dec, evp = make_log(tmp_path, STEPS)
    before = host_nft()
    r = replay(dec, evp, "--kernel", "on")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "private netns" in r.stdout and "real nft vs simulated sets: agree" in r.stdout
    assert "ledger vs simulated sets: agree" in r.stdout and "simulated expiries removed" in r.stdout
    assert host_nft() == before, "the replay changed the HOST ruleset"
    assert subprocess.run(["nft", "list", "table", "inet", "cora_replay"], capture_output=True).returncode != 0


@kernel
@needs_unshare
def test_kernel_and_simulation_decide_identically_and_expiries_really_happened(tmp_path):
    dec, evp = make_log(tmp_path, STEPS)
    sim = json.loads(replay(dec, evp, "--kernel", "off", "--json", "--outcomes").stdout)
    ker = json.loads(replay(dec, evp, "--kernel", "on", "--json", "--outcomes").stdout)
    assert ker["worlds"]["A"]["outcomes"] == sim["worlds"]["A"]["outcomes"]
    k = ker["kernel"]
    acts = sum(1 for o in sim["worlds"]["A"]["outcomes"] if o["result"] in ("blocked", "refreshed", "promoted"))
    assert k["writes"] == acts and k["deletes"] >= 3 and k["p50_ms"] > 0       # blocks timed out in SIMULATED time and were removed
    assert ker["worlds"]["A"]["summary"]["consistent"] == {"ledger_vs_sets": True, "kernel_vs_sets": True}
    assert sim["kernel"] is None and ker["problems"] == []


@kernel
@needs_unshare
def test_kernel_mode_keeps_stdin_and_skips_the_kernel_when_verifying(tmp_path):
    dec, evp = make_log(tmp_path, STEPS[:6])
    r = replay("-", evp, "--kernel", "on", stdin=dec.read_text())              # the exec into the namespace must keep stdin
    assert r.returncode == 0 and "private netns" in r.stdout, r.stdout + r.stderr
    c = replay(dec, evp, "--check", "--kernel", "on")                          # verifying never writes: no namespace needed
    assert c.returncode == 0 and "kernel: not used" in c.stdout and "match 6   mismatch 0" in c.stdout


@kernel
@needs_unshare
def test_a_tweak_in_kernel_mode_mirrors_world_b_and_still_agrees(tmp_path):
    dec, evp = make_log(tmp_path, STEPS)
    r = replay(dec, evp, "--kernel", "on", "--keep-isolated", "--write-budget", "4", "--task-cap", "3")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "== B vs A" in r.stdout and "real nft vs simulated sets: agree" in r.stdout
