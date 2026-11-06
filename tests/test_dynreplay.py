"""The replay harness without a kernel. The logs are produced by running the LIVE policy over synthetic scenarios and
writing both files exactly as the daemon does, so what the replay reads is what the daemon writes.
Run: pytest -q tests/test_dynreplay.py"""
import gzip
import io
import json
import random
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cora_sentinel import dynpolicy, dynreplay, nftsets
from cora_sentinel.dynpolicy import DynConfig, DynPolicy

from test_dynpolicy import Clock, mk

T0 = 1_800_000_000.0
DRY = "dry-run:ISOLATE@cgroup:x"


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")


def make_log(tmp_path, steps, mode="shadow", cfg=None, exempt=None, name=""):
    """steps: [(seconds_since_previous, mk-kwargs)]. Returns (decisions_path, events_path) like the daemon's two logs."""
    dec, evp = tmp_path / f"decisions{name}.jsonl", tmp_path / f"events{name}.jsonl"
    clock = Clock(T0)
    pol = DynPolicy(mode, state_dir=None, clock=clock, cfg=cfg or DynConfig(), log=lambda m: None, exempt=exempt)
    with open(dec, "w") as df, open(evp, "w") as ef:
        for dt, kw in steps:
            clock.advance(dt)
            kw = {"action": DRY, **kw}
            ev, d = mk(**kw)
            ev["event_id"], ev["ts"] = uuid.uuid4().hex, iso(clock.t)
            d.update({"ts": iso(clock.t), "event_id": ev["event_id"], "pid": 1, "vip": "10.0.0.2",
                      "kind": "unauthorized_connection", "mode": "dry-run"})
            rec = pol.consider(ev, d)
            if rec:
                d["dyn"] = rec
            ef.write(json.dumps(ev) + "\n")
            df.write(json.dumps(d) + "\n")
    return dec, evp


def run(tmp_path, capsys, *argv, steps=None, **mk_kw):
    """Run the CLI on a fresh log (or an existing one) and return (exit, parsed JSON or text)."""
    if steps is not None:
        dec, evp = make_log(tmp_path, steps, **mk_kw)
        argv = (str(dec), "--events", str(evp)) + argv
    rc = dynreplay.main(["--kernel", "off", *argv])
    out = capsys.readouterr().out
    try:
        return rc, json.loads(out)
    except ValueError:
        return rc, out


WEB = (0, {"task": "a", "ip": "45.33.32.156", "port": 443})


# ================= reading the logs =================
def test_decisions_are_joined_with_events_by_event_id_and_only_isolate_counts(tmp_path):
    dec, evp = make_log(tmp_path, [(0, {"task": "a"}), (5, {"task": "b", "ip": "45.33.33.9"}),
                                   (5, {"task": "c", "ip": "45.33.34.9", "final": "ESCALATE", "action": "needs-human"})])
    lines = evp.read_text().splitlines()
    evp.write_text("\n".join(lines[:2]) + "\n")                       # the third event is not in the log; the 2nd decision stays
    recs, st = dynreplay.load([str(dec)], [str(evp)])
    assert st == {"decisions": 3, "isolate": 2, "joined": 2, "no_event": 0, "malformed": 0}
    dec.write_text(dec.read_text().replace(json.loads(dec.read_text().splitlines()[1])["event_id"], "gone"))
    recs, st = dynreplay.load([str(dec)], [str(evp)])
    assert st["joined"] == 1 and st["no_event"] == 1 and recs[0].task == "a"


def test_duplicates_malformed_lines_and_shuffled_order_are_handled(tmp_path):
    dec, evp = make_log(tmp_path, [(0, {"task": "a"}), (10, {"task": "b", "ip": "45.33.33.9"}), (10, {"task": "c", "ip": "45.33.34.9"})])
    lines = dec.read_text().splitlines()
    dec.write_text("\n".join([lines[2], "not json", lines[0], lines[0], "", lines[1]]) + "\n")
    recs, st = dynreplay.load([str(dec)], [str(evp)])
    assert [r.task for r in recs] == ["a", "b", "c"] and st["malformed"] == 1 and st["isolate"] == 3   # time order, deduplicated


def test_rotated_gz_files_several_files_and_stdin(tmp_path, monkeypatch):
    dec, evp = make_log(tmp_path, [(0, {"task": "a"}), (10, {"task": "b", "ip": "45.33.33.9"}), (10, {"task": "c", "ip": "45.33.34.9"})])
    dl, el = dec.read_text().splitlines(), evp.read_text().splitlines()
    (tmp_path / "decisions.jsonl.1.gz").write_bytes(gzip.compress(("\n".join(dl[:2]) + "\n").encode()))
    (tmp_path / "events.jsonl.1.gz").write_bytes(gzip.compress(("\n".join(el[:2]) + "\n").encode()))
    dec.write_text(dl[2] + "\n")
    evp.write_text(el[2] + "\n")
    recs, st = dynreplay.load([str(dec), str(tmp_path / "decisions.jsonl.1.gz")], [str(evp), str(tmp_path / "events.jsonl.1.gz")])
    assert [r.task for r in recs] == ["a", "b", "c"]
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(dl) + "\n"))
    recs, st = dynreplay.load(["-"], [str(tmp_path / "events.jsonl.1.gz"), str(evp)])
    assert len(recs) == 3


def test_since_and_until_select_a_window(tmp_path):
    dec, evp = make_log(tmp_path, [(0, {"task": "a"}), (3600, {"task": "b", "ip": "45.33.33.9"}), (3600, {"task": "c", "ip": "45.33.34.9"})])
    recs, _ = dynreplay.load([str(dec)], [str(evp)], since=dynreplay.parse_ts(iso(T0 + 3600)), until=dynreplay.parse_ts(iso(T0 + 7200)))
    assert [r.task for r in recs] == ["b"]


def test_the_event_log_defaults_to_the_one_next_to_the_decisions_and_is_required_otherwise(tmp_path, capsys):
    dec, evp = make_log(tmp_path, [WEB])
    evp.rename(tmp_path / "events.jsonl")
    assert dynreplay.main(["--kernel", "off", str(dec)]) == 0
    capsys.readouterr()
    (tmp_path / "events.jsonl").unlink()
    assert dynreplay.main(["--kernel", "off", str(dec)]) == 2
    assert "--events" in capsys.readouterr().err


def test_an_empty_log_says_so_and_is_not_an_error(tmp_path, capsys):
    (tmp_path / "d.jsonl").write_text("")
    (tmp_path / "e.jsonl").write_text("")
    rc, out = run(tmp_path, capsys, str(tmp_path / "d.jsonl"), "--events", str(tmp_path / "e.jsonl"))
    assert rc == 0 and "nothing to replay" in out


# ================= the clock, the worlds =================
def outcomes(tmp_path, capsys, *argv, steps, **kw):
    rc, doc = run(tmp_path, capsys, "--json", "--outcomes", *argv, steps=steps, **kw)
    return rc, doc, doc["worlds"]["A"]["outcomes"]


def test_the_policy_clock_follows_the_recorded_time(tmp_path, capsys):
    steps = [(0, {"task": "a", "port": 443}), (601, {"task": "b", "port": 443}), (30, {"task": "c", "port": 443})]
    rc, doc, oc = outcomes(tmp_path, capsys, steps=steps)
    assert [o["result"] for o in oc] == ["blocked", "blocked", "refreshed"]
    assert [o["ttl_s"] for o in oc] == [600, 2400, 9600]               # expired at +600, so +601 is a fresh block at offense 2


def test_rehearse_treats_a_dry_run_isolate_as_done_and_as_recorded_does_not(tmp_path, capsys):
    steps = [(0, {"task": "a"})]
    assert outcomes(tmp_path, capsys, steps=steps)[2][0]["result"] == "blocked"
    assert outcomes(tmp_path, capsys, "--as-recorded", steps=steps)[2][0]["result"] == "would_block"


def test_an_isolated_task_stops_emitting_events_in_the_rehearse_world(tmp_path, capsys):
    steps = [(0, {"task": "a"}), (20, {"task": "a"}), (20, {"task": "a", "ip": "45.33.33.9"})]
    _, doc, oc = outcomes(tmp_path, capsys, steps=steps)
    assert [o["result"] for o in oc] == ["blocked", "suppressed", "suppressed"]
    _, doc, oc = outcomes(tmp_path, capsys, "--keep-isolated", steps=steps)
    assert [o["result"] for o in oc] == ["blocked", "dedupe", "blocked"]


def test_exemptions_recorded_live_are_honoured_and_allow_protect_add_more(tmp_path, capsys):
    exempt = lambda ip: "allowed:45.33.33.0/24" if ip.startswith("45.33.33.") else None        # noqa: E731
    steps = [(0, {"task": "a", "ip": "45.33.33.9"}), (10, {"task": "b", "ip": "45.33.34.9"}), (10, {"task": "c", "ip": "45.33.35.9"})]
    dec, evp = make_log(tmp_path, steps, exempt=exempt)
    rc, doc = run(tmp_path, capsys, str(dec), "--events", str(evp), "--json", "--outcomes")
    assert [o["result"] for o in doc["worlds"]["A"]["outcomes"]] == ["skipped", "blocked", "blocked"]      # from the record
    assert doc["worlds"]["A"]["outcomes"][0]["reason"].startswith("allowed:")
    rc, doc = run(tmp_path, capsys, str(dec), "--events", str(evp), "--json", "--outcomes", "--allow", "45.33.34.0/24", "--protect", "45.33.35.9")
    b = doc["worlds"]["B"]["outcomes"]
    assert [o["result"] for o in b] == ["skipped", "skipped", "skipped"] and doc["diff"]["changed"] == 2


# ================= does it reproduce the daemon? =================
SCENARIO = ([(0, {"task": "t1", "port": 443}), (30, {"task": "t2", "port": 443}), (20, {"task": "t3", "ip": "45.33.33.7", "port": 8080}),
             (20, {"task": "t4", "ip": "45.33.33.7", "port": 9090}), (20, {"task": "t5", "ip": "45.33.34.1", "port": 22, "conf": 0.8}),
             (20, {"task": "t6", "ip": "45.33.34.2", "port": 53}), (700, {"task": "t7", "port": 443}),
             (5, {"task": "t8", "ip": "45.33.34.3", "port": 80, "blocklist": True})]
            + [(2, {"task": "noisy", "ip": f"45.34.0.{i}", "port": 7000 + i}) for i in range(12)])


def test_check_reproduces_exactly_what_the_live_policy_recorded(tmp_path, capsys):
    rc, doc = run(tmp_path, capsys, "--check", "--json", steps=SCENARIO)
    assert rc == 0 and doc["check"]["mismatch"] == 0 and doc["check"]["compared"] == len(SCENARIO), doc["check"]


def test_check_needs_the_live_settings_and_detects_drift_without_them(tmp_path, capsys):
    cfg = DynConfig(task_cap=5, write_per_min=50)
    dec, evp = make_log(tmp_path, SCENARIO, cfg=cfg)
    base = (str(dec), "--events", str(evp), "--check", "--json")
    rc, doc = run(tmp_path, capsys, *base, "--task-cap", "5", "--write-budget", "50")
    assert rc == 0 and doc["check"]["mismatch"] == 0
    rc, doc = run(tmp_path, capsys, *base)                                         # replayed with different settings
    assert rc == 1 and doc["check"]["mismatch"] >= 1 and doc["check"]["first"][0]["recorded"]["reason"] == "task_cap"


def test_check_detects_a_policy_that_changed_since_the_log_was_written(tmp_path, capsys, monkeypatch):
    dec, evp = make_log(tmp_path, SCENARIO)
    monkeypatch.setattr(dynpolicy, "FLOW_BASE_S", 300)
    monkeypatch.setattr(dynpolicy.DynConfig, "flow_base_s", 300, raising=False)
    rc, doc = run(tmp_path, capsys, str(dec), "--events", str(evp), "--check", "--json", "--flow-ttl", "300")
    assert rc == 1 and any(m["recorded"]["ttl_s"] == 600 for m in doc["check"]["first"])


def test_diff_recorded_is_informational_and_a_log_without_dyn_records_is_counted(tmp_path, capsys):
    dec, evp = make_log(tmp_path, [WEB])
    d = json.loads(dec.read_text())
    d.pop("dyn")
    dec.write_text(json.dumps(d) + "\n")
    rc, doc = run(tmp_path, capsys, str(dec), "--events", str(evp), "--diff-recorded", "--json")
    assert rc == 0 and doc["check"]["no_record"] == 1 and doc["check"]["compared"] == 0


# ================= tweaks and the diff =================
def test_a_tweak_runs_b_against_the_defaults_and_reports_what_changed(tmp_path, capsys):
    rc, doc = run(tmp_path, capsys, "--json", "--keep-isolated", "--write-budget", "2", steps=SCENARIO)
    assert set(doc["worlds"]) == {"A", "B"}
    d = doc["diff"]
    assert d["changed"] >= 1 and d["delta"]["throttled"] > 0 and d["delta"]["blocks"] < 0 and d["first"][0]["b"]["reason"] == "budget"
    assert doc["worlds"]["B"]["summary"]["limits"]["write_per_min"]["limit"] == 2


def test_promote_tasks_changes_whether_the_whole_address_is_blocked(tmp_path, capsys):
    steps = [(0, {"task": "x", "ip": "45.33.33.7", "port": 8080}), (10, {"task": "y", "ip": "45.33.33.7", "port": 9090})]
    rc, doc = run(tmp_path, capsys, "--json", "--promote-tasks", "3", steps=steps)
    assert doc["worlds"]["A"]["summary"]["results"].get("promoted") == 1 and "promoted" not in doc["worlds"]["B"]["summary"]["results"]


def test_a_single_world_has_no_diff_and_the_text_report_has_its_sections(tmp_path, capsys):
    rc, out = run(tmp_path, capsys, "--timeline", "--top", "3", steps=SCENARIO)
    for head in ("== replay", "results", "limits", "write budget", "live elements", "per-task cap", "web ports 80/443",
                 "promoted to a whole address: 0", "targets ", "self-check", "timeline (hour, UTC)", "kernel: not used"):
        assert head in out, head
    assert "== B vs A" not in out


# ================= the report's numbers =================
def test_blocked_time_is_exact_across_a_refresh_and_a_gap(tmp_path, capsys):
    steps = [(0, {"task": "a", "port": 443}), (300, {"task": "b", "port": 443}), (5000, {"task": "c", "port": 443})]
    rc, doc = run(tmp_path, capsys, "--json", steps=steps)
    top = doc["worlds"]["A"]["summary"]["web"]["top"][0]
    # 0-300 (first ttl 600, cut short by the refresh) + 300-2700 (ttl 2400) + 5300: a fresh block at offense 3 (ttl 9600)
    assert top["blocked_s"] == 300 + 2400 + 9600 and top["offenses"] == 3 and top["tasks"] == 3


def test_limits_report_denials_peaks_and_the_lowest_bucket(tmp_path, capsys):
    steps = [(1, {"task": f"t{i}", "ip": f"45.34.0.{i}", "port": 7000 + i}) for i in range(8)]
    rc, doc = run(tmp_path, capsys, "--json", "--write-budget", "3", steps=steps)
    s = doc["worlds"]["B"]["summary"]
    assert s["throttled"]["budget"] == 5 and s["limits"]["write_per_min"]["peak"] == 3 and s["limits"]["live"]["peak"] == 3
    assert s["limits"]["bucket_min_tokens"] < 1.0
    steps = [(1, {"task": "one", "ip": f"45.34.0.{i}", "port": 7000 + i}) for i in range(4)]
    rc, doc = run(tmp_path, capsys, "--json", "--keep-isolated", "--task-cap", "2", steps=steps)
    s = doc["worlds"]["B"]["summary"]
    assert s["throttled"]["task_cap"] == 2 and s["limits"]["task_targets_per_hour"]["max"] == 2
    assert s["throttled"]["task_cap_by_task"] == {"one": 2}


def test_web_traffic_is_reported_and_a_web_hit_covered_by_a_whole_address_block_is_noticed(tmp_path, capsys):
    steps = [(0, {"task": "x", "ip": "45.33.33.7", "port": 8080}), (10, {"task": "y", "ip": "45.33.33.7", "port": 9090}),
             (10, {"task": "z", "ip": "45.33.33.7", "port": 443})]
    rc, doc = run(tmp_path, capsys, "--json", steps=steps)
    w = doc["worlds"]["A"]["summary"]["web"]
    assert w["promotions"] == 0 and w["covered_by_whole_address"] == 1


# ================= the self-checks =================
def test_a_web_port_promotion_is_a_self_check_failure_even_if_the_policy_lies_about_it(tmp_path, capsys, monkeypatch):
    dec, evp = make_log(tmp_path, [(0, {"task": "a", "port": 443}), (10, {"task": "b", "port": 443})])
    monkeypatch.setattr(dynpolicy, "WEB_PORTS", frozenset())          # a broken policy that treats 443 as an ordinary port
    rc = dynreplay.main(["--kernel", "off", str(dec), "--events", str(evp)])
    cap = capsys.readouterr()
    assert rc == 2 and "SELF-CHECK FAILED" in cap.err and "MUST BE 0" in cap.out


def test_the_ledger_and_the_simulated_sets_agree_over_a_random_history(tmp_path, capsys):
    rnd = random.Random(7)
    steps = [(rnd.choice([0, 1, 5, 30, 200, 900, 4000]),
              {"task": f"t{rnd.randrange(9)}", "ip": f"45.33.{rnd.randrange(3)}.{rnd.randrange(6)}",
               "port": rnd.choice([443, 80, 8080, 9090, 22, 8443, 7777]), "proto": rnd.choice(["tcp", "udp"]),
               "conf": rnd.choice([0.95, 0.99, 0.5])}) for _ in range(300)]
    for flags in ((), ("--keep-isolated",), ("--keep-isolated", "--task-cap", "3", "--write-budget", "5", "--max-live", "6")):
        rc, doc = run(tmp_path, capsys, "--json", *flags, steps=steps)
        assert rc == 0 and doc["problems"] == []
        for w in doc["worlds"].values():
            assert w["summary"]["consistent"] == {"ledger_vs_sets": True}, flags


def test_a_policy_that_raises_is_reported_not_fatal(tmp_path, capsys, monkeypatch):
    dec, evp = make_log(tmp_path, [WEB, (5, {"task": "b", "ip": "45.33.33.9"})])
    real = DynPolicy.consider
    monkeypatch.setattr(DynPolicy, "consider", lambda self, ev, d: (_ for _ in ()).throw(RuntimeError("boom")))
    rc, doc = run(tmp_path, capsys, str(dec), "--events", str(evp), "--json")
    assert rc == 0 and doc["worlds"]["A"]["summary"]["results"] == {"error": 2}


def test_the_live_ledger_is_never_touched(tmp_path, capsys, monkeypatch):
    state = tmp_path / "st"
    state.mkdir()
    ledger = state / "dyn-ledger-enforce.json"
    ledger.write_text(json.dumps({"v": 1, "flows": {}, "ips": {}, "watch": {}, "targets": {}, "marker": "live"}))
    before = ledger.read_bytes()
    monkeypatch.setenv("CORA_STATE_DIR", str(state))
    rc, doc = run(tmp_path, capsys, "--json", steps=SCENARIO)
    assert rc == 0 and ledger.read_bytes() == before and sorted(p.name for p in state.iterdir()) == ["dyn-ledger-enforce.json"]


def test_kernel_on_without_privileges_is_a_clean_error(tmp_path, capsys, monkeypatch):
    dec, evp = make_log(tmp_path, [WEB])
    monkeypatch.setattr(dynreplay, "can_kernel", lambda: False)
    assert dynreplay.main(["--kernel", "on", str(dec), "--events", str(evp)]) == 2
    assert "needs root, nft and unshare" in capsys.readouterr().err


# ================= the entry points =================
def test_cora_floor_dyn_replay_and_the_tools_shim_run_the_same_thing(tmp_path, capsys):
    dec, evp = make_log(tmp_path, [WEB])
    assert nftsets.main(["dyn-replay", str(dec), "--events", str(evp), "--kernel", "off", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["inputs"]["joined"] == 1
    shim = Path(__file__).resolve().parents[1] / "tools" / "dyn_replay.py"
    r = subprocess.run([sys.executable, str(shim), str(dec), "--events", str(evp), "--kernel", "off"], capture_output=True, text=True)
    assert r.returncode == 0 and "web ports 80/443" in r.stdout
    h = subprocess.run([sys.executable, "-m", "cora_sentinel.nftsets", "dyn-replay", "--help"], capture_output=True, text=True)
    assert h.returncode == 0 and "--check" in h.stdout
