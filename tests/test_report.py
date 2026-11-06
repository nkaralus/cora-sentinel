"""Part 1 runs anywhere. Part 2 (real kernel chain) needs root + nft + cgroup v2.
Run: sudo -E $(which python) -m pytest -q tests/test_report.py"""
import json
import os
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cora_sentinel import report as cora_report
from cora_sentinel.blocklist import Blocklist
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.firewall import Firewall
from cora_sentinel.report import JSON_SCHEMA, Reporter, validate_report
from cora_sentinel.daemon import Sentinel, VirtualNet, build_payload, read_starttime
from cora_sentinel.verdict import Adjudicator, Executor

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = "93.184.216.34"


def clock(h=14):
    return lambda: datetime(2026, 11, 4, h, 37, 12, tzinfo=timezone.utc)


def event(ip=PUBLIC, cls="public", cgroup="payroll", cmd="/home/nick/bin/secret-tool --token=SEKRET", pid=4242,
          entry="tracker.example.com", kind="tracker_domain"):
    ev = build_payload(pid, "10.1.1.57", cmd, "unauthorized_connection", "high",
                       {"remote_ip": ip, "remote_port": 443, "local_port": 51514, "dest_class": cls,
                        "blocklist": {"list": "ads", "kind": kind, "entry": entry}},
                       123456, cgroup=cgroup)
    return ev


def decision(final="ISOLATE", action="done:ISOLATE@cgroup:payroll[nft-drop-egress]", conf=0.93, policy=None):
    return {"final": final, "action": action, "policy": policy,
            "model": {"verdict": final, "confidence": conf, "reason": "free text SEKRET /home/nick"}}


@pytest.fixture
def rep(tmp_path):
    return Reporter(str(tmp_path / "reports"), str(tmp_path / "cfg" / "salt"), clock=clock())


# ---- anonymization --------------------------------------------------------
def test_nothing_identifying_leaks(rep):
    blob = json.dumps(rep.build(event(), decision())) + cora_report.Reporter.issue_markdown(rep.build(event(), decision()))
    for secret in ["SEKRET", "nick", "payroll", "4242", "10.1.1.57", "secret-tool", "51514",
                   socket.gethostname(), "123456", "free text", "/home"]:
        assert secret not in blob, secret


def test_private_destination_is_withheld_public_is_kept(rep):
    pub = rep.build(event(), decision())["violation"]["destination"]
    priv = rep.build(event(ip="192.168.1.50", cls="private"), decision())["violation"]["destination"]
    assert pub == {"ip": PUBLIC, "port": 443, "ip_class": "public"}
    assert priv == {"ip": None, "port": 443, "ip_class": "private"}


def test_time_is_truncated_to_the_hour(rep):
    assert rep.build(event(), decision())["observed_hour"] == "2026-11-04T14:00:00Z"


def test_task_ref_is_stable_salted_and_opaque(tmp_path):
    a = Reporter(str(tmp_path / "o"), str(tmp_path / "s1"), clock=clock())
    a2 = Reporter(str(tmp_path / "o"), str(tmp_path / "s1"), clock=clock())
    b = Reporter(str(tmp_path / "o"), str(tmp_path / "s2"), clock=clock())
    r = a.build(event(), decision())["task_ref"]
    assert r == a2.build(event(), decision())["task_ref"] != b.build(event(), decision())["task_ref"]
    assert len(r) == 12 and "payroll" not in r
    assert r != a.build(event(cgroup="other"), decision())["task_ref"]


def test_process_name_only_when_opted_in_and_only_the_basename(tmp_path):
    off = Reporter(str(tmp_path / "o"), str(tmp_path / "s"), clock=clock())
    on = Reporter(str(tmp_path / "o"), str(tmp_path / "s"), include_process=True, clock=clock())
    assert off.build(event(), decision())["process"] is None
    p = on.build(event(), decision())["process"]
    assert p == "secret-tool" and "/" not in p and "SEKRET" not in p


def test_salt_is_private_and_outside_the_report_dir(tmp_path):
    r = Reporter(str(tmp_path / "reports"), str(tmp_path / "cfg" / "salt"), clock=clock())
    salt = tmp_path / "cfg" / "salt"
    assert stat.S_IMODE(salt.stat().st_mode) == 0o600
    r.report(event(), decision())
    assert not any("salt" in f.name for f in (tmp_path / "reports").iterdir())


def test_enforced_flag_reflects_reality(rep):
    assert rep.build(event(), decision())["response"]["enforced"] is True
    d = decision(action="dry-run:ISOLATE@cgroup:payroll")
    assert rep.build(event(), d)["response"]["enforced"] is False
    assert rep.build(event(), decision(action="blocked"))["response"]["enforced"] is False


# ---- schema ---------------------------------------------------------------
def test_validator_rejects_malformed(rep):
    good = rep.build(event(), decision())
    for mutate in (lambda d: d.update(extra=1), lambda d: d.pop("task_ref"),
                   lambda d: d["violation"]["destination"].update(port=0),
                   lambda d: d["response"].update(verdict="NUKE"),
                   lambda d: d["violation"].update(type="other"),
                   lambda d: d.update(observed_hour="2026-11-04T14:37:12Z")):
        bad = json.loads(json.dumps(good))
        mutate(bad)
        with pytest.raises((ValueError, KeyError)):
            validate_report(bad)


def test_python_validator_agrees_with_the_published_json_schema(rep):
    jsonschema = pytest.importorskip("jsonschema")
    good = rep.build(event(), decision())
    jsonschema.validate(good, JSON_SCHEMA)
    for mutate in (lambda d: d.update(extra=1), lambda d: d["violation"]["destination"].update(port=70000),
                   lambda d: d["response"].update(verdict="NUKE"), lambda d: d.update(report_id="short"),
                   lambda d: d.update(observed_hour="2026-11-04T14:37:12Z")):
        bad = json.loads(json.dumps(good))
        mutate(bad)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, JSON_SCHEMA)
        with pytest.raises((ValueError, KeyError)):
            validate_report(bad)
    p = json.loads((ROOT / "schema" / "violation.schema.json").read_text())      # committed file == code
    assert p == JSON_SCHEMA


# ---- writing --------------------------------------------------------------
def test_writes_json_and_issue_body_and_dedupes_within_the_hour(tmp_path):
    t = {"h": 14}
    r = Reporter(str(tmp_path / "o"), str(tmp_path / "s"), clock=lambda: clock(t["h"])())
    p = r.report(event(), decision())
    assert p.exists() and p.with_suffix(".md").exists()
    md = p.with_suffix(".md").read_text()
    assert "[violation] tracker_domain: tracker.example.com" in md and "```json" in md
    assert r.report(event(), decision()) is None                  # same task/entry/hour
    t["h"] = 15
    assert r.report(event(), decision()) is not None              # next hour: new report


# ---- the floor (pure logic) ---------------------------------------------------------------
class M:
    def __init__(self, v): self.v = v
    def judge(self, ev): return self.v if self.v.startswith("{") else json.dumps(
        {"verdict": self.v, "confidence": 0.9, "reason": "t"})


class FakeFW:
    def block(self, n): return True


def adj(verdict, floor=True, fw=True, reporter=None):
    net = VirtualNet()
    cg = CgroupRoot("/nonexistent/cora", "/nonexistent")
    a = Adjudicator(net, M(verdict), Executor(False, cg, FakeFW() if fw else None), None, 0.6,
                    reporter=reporter, blocklist_floor=floor)
    return net, a


def ev_for(net, blocklisted=True):
    pid = os.getpid()
    e = build_payload(pid, net.ensure(pid), "x", "unauthorized_connection", "high",
                      {"remote_ip": PUBLIC, "remote_port": 443, "dest_class": "public"},
                      read_starttime(pid), cgroup="task")
    if blocklisted:
        e["anomaly"]["evidence"]["blocklist"] = {"list": "ads", "kind": "tracker_domain", "entry": "t.example.com"}
    return e


@pytest.mark.parametrize("said", ["ALLOW", "THROTTLE", "ESCALATE"])
def test_floor_raises_weak_verdicts_to_isolate(said):
    net, a = adj(said)
    d = a.handle(ev_for(net))
    assert d["final"] == "ISOLATE" and d["policy"] == "blocklist_floor" and d["blocklist"]["list"] == "ads"


@pytest.mark.parametrize("said", ["SUSPEND", "TERMINATE", "ISOLATE"])
def test_floor_never_lowers_a_stronger_verdict(said):
    net, a = adj(said)
    assert a.handle(ev_for(net))["final"] == said


def test_unusable_model_output_still_contains_a_listed_hit():
    net, a = adj("garbage not json")
    d = a.handle(ev_for(net))
    assert "model_error" in d and d["final"] == "ISOLATE"


def test_floor_can_be_disabled():
    net, a = adj("ALLOW", floor=False)
    assert a.handle(ev_for(net))["final"] == "ALLOW"


def test_without_firewall_the_floor_hands_it_to_a_human():
    net, a = adj("ALLOW", fw=False)
    d = a.handle(ev_for(net))
    assert d["final"] == "ESCALATE" and d["policy"] == "blocklist_floor_no_isolate"


def test_unlisted_events_are_untouched_by_the_floor():
    net, a = adj("ALLOW")
    d = a.handle(ev_for(net, blocklisted=False))
    assert d["final"] == "ALLOW" and "blocklist" not in d


def test_reporter_failure_never_breaks_adjudication():
    class Boom:
        def report(self, ev, d): raise RuntimeError("disk full")
    net, a = adj("ALLOW", reporter=Boom())
    assert a.handle(ev_for(net))["final"] == "ISOLATE"


# =========================== part 2: real kernel ==============================
import shutil


def _mount():
    for m in ("/sys/fs/cgroup", "/sys/fs/cgroup/unified"):
        p = Path(m) / f"coraprobe-{os.getpid()}"
        try:
            p.mkdir(); p.rmdir()
            if (Path(m) / "cgroup.controllers").exists():
                return m
        except OSError:
            continue


def _nft_ok():
    if not shutil.which("nft"):
        return False
    t = f"coraprobe{os.getpid()}"
    if subprocess.run(["nft", "add", "table", "inet", t], capture_output=True).returncode:
        return False
    subprocess.run(["nft", "delete", "table", "inet", t], capture_output=True)
    return True


def _local_ip():
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                gw = socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
                s = socket.socket(2, 2); s.connect((gw, 9)); ip = s.getsockname()[0]; s.close()
                return ip, gw
    except OSError:
        pass
    return None, None


MOUNT = _mount()
LOCAL, GW = _local_ip()
real = pytest.mark.skipif(not (MOUNT and LOCAL and _nft_ok()), reason="needs root, nft, cgroup v2, a real address")


@real
def test_full_chain_listed_address_to_isolation_and_report(tmp_path):
    cg = CgroupRoot(f"{MOUNT}/coranft-bl-{os.getpid()}", MOUNT)
    cg.ensure()
    fw = Firewall(cg, table=f"coratest{os.getpid()}")
    lis = socket.socket(); lis.bind((LOCAL, 0)); lis.listen(1)
    port = lis.getsockname()[1]
    code = (f"import socket,time;c=socket.create_connection(('{LOCAL}',{port}));time.sleep(4);"
            f"u=socket.socket(2,2);e=0\nfor _ in range(3):\n    try: u.sendto(b'x',('{GW}',9))\n"
            f"    except OSError: e+=1\nprint(e)")
    env = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT}
    p = subprocess.Popen([sys.executable, "-m", "cora_sentinel.run", "adtask", sys.executable, "-c", code],
                         env=env, stdout=subprocess.PIPE, text=True)
    try:
        bl = Blocklist(); bl.add_line(f"{LOCAL}/32", "rogue")
        events = []
        s = Sentinel("UNUSED", ["/tmp"], spike_mb=10**6, window_s=5, emit=events.append,
                     net_allow=["0.0.0.0/0"], cgroups=cg, blocklist=bl)
        end = time.monotonic() + 3
        while time.monotonic() < end and not events:
            s.tick(); time.sleep(0.1)
        ev = next(e for e in events if e["anomaly"]["evidence"].get("blocklist"))
        reporter = Reporter(str(tmp_path / "reports"), str(tmp_path / "salt"))
        d = Adjudicator(s.net, M("ALLOW"), Executor(True, cg, fw), None, 0.6, reporter=reporter).handle(ev)
        # the model said ALLOW; the floor made it ISOLATE; the kernel enforced it
        assert d["final"] == "ISOLATE" and d["policy"] == "blocklist_floor"
        assert d["action"].startswith("done:ISOLATE@cgroup:adtask") and fw.is_blocked("adtask")
        assert int(p.communicate(timeout=20)[0].strip()) == 3            # its later egress is dropped
        rep = json.loads(next((tmp_path / "reports").glob("*.json")).read_text())
        validate_report(rep)
        assert rep["response"] == {"verdict": "ISOLATE", "enforced": True, "policy": "blocklist_floor",
                                   "model_confidence": 0.9}
        assert rep["violation"]["destination"]["ip"] is None             # local address withheld
        assert "adtask" not in json.dumps(rep)
    finally:
        p.kill(); p.wait(); lis.close(); fw.purge()
        for n in cg.names():
            try: cg.kill(n)
            except Exception: pass
        for _ in range(40):
            try:
                for n in cg.names(): (cg.root / n).rmdir()
                cg.root.rmdir(); break
            except OSError:
                time.sleep(0.1)


# ---- proto and via: optional fields of a report, recorded by every connection detector (0.8.6) -----------------------
import re as _re                                                    # noqa: E402
from types import SimpleNamespace as _NS                            # noqa: E402

from cora_sentinel.report import PROTOS, VIAS, protocol_of, validate_report as _validate   # noqa: E402


def tap_event(proto=None, l7=None, via="syn_tap", detection=None, **kw):
    ev = event(**kw)
    evi = ev["anomaly"]["evidence"]
    for k, v in (("proto", proto), ("l7", l7), ("via", via)):
        if v:
            evi[k] = v
    if detection:
        ev["detection"] = detection
    return ev


@pytest.mark.parametrize("evidence,want_proto,want_via", [
    (dict(via="syn_tap"), "tcp", "syn_tap"),
    (dict(proto="udp", via="udp_tap"), "udp", "udp_tap"),
    (dict(proto="udp", l7="quic", via="udp_tap"), "quic", "udp_tap"),
    (dict(proto="udp", l7="dns", via="udp_tap"), "dns", "udp_tap"),
    (dict(proto="udp", l7="something-else", via="udp_tap"), "udp", "udp_tap"),
])
def test_a_report_carries_proto_and_via_and_both_validators_accept_it(rep, evidence, want_proto, want_via):
    jsonschema = pytest.importorskip("jsonschema")
    r = rep.build(tap_event(**evidence), decision())
    assert r["violation"]["proto"] == want_proto and r["violation"]["via"] == want_via
    _validate(r)
    jsonschema.validate(r, JSON_SCHEMA)                              # the published schema agrees with the Python validator


def test_the_detection_field_wins_over_the_evidence(rep):
    r = rep.build(tap_event(via="syn_tap", detection={"proto": "quic", "via": "sock_diag"}), decision())
    assert (r["violation"]["proto"], r["violation"]["via"]) == ("quic", "sock_diag")


def test_an_event_with_no_provenance_reports_tcp_and_unknown(rep):
    ev = event()                                                     # how every event looked before 0.8.6
    assert "via" not in ev["anomaly"]["evidence"] and "detection" not in ev
    r = rep.build(ev, decision())
    assert (r["violation"]["proto"], r["violation"]["via"]) == ("tcp", "unknown")


def test_an_unrecognised_value_degrades_to_something_valid_never_to_an_invalid_report(rep):
    r = rep.build(tap_event(via=None, detection={"proto": "icmp", "via": "carrier-pigeon"}), decision())
    assert r["violation"]["via"] == "unknown" and r["violation"]["proto"] == "tcp", "an invalid proto falls back to the evidence"
    _validate(r)
    r2 = rep.build(tap_event(proto="sctp", via=None), decision())
    assert r2["violation"]["proto"] == "unknown"
    _validate(r2)


def test_the_two_fields_are_optional_so_a_report_from_before_them_is_still_valid(rep):
    jsonschema = pytest.importorskip("jsonschema")
    r = rep.build(tap_event(), decision())
    del r["violation"]["proto"], r["violation"]["via"]
    _validate(r)
    jsonschema.validate(r, JSON_SCHEMA)
    only_one = rep.build(tap_event(), decision())
    del only_one["violation"]["via"]
    _validate(only_one)
    jsonschema.validate(only_one, JSON_SCHEMA)
    assert "proto" not in JSON_SCHEMA["properties"]["violation"]["required"] and "via" not in JSON_SCHEMA["properties"]["violation"]["required"]


@pytest.mark.parametrize("field,bad", [("proto", "icmp"), ("proto", ""), ("proto", None), ("proto", 6), ("via", "magic"), ("via", "SYN_TAP"), ("via", None)])
def test_values_outside_the_enums_are_rejected_by_both_validators(rep, field, bad):
    jsonschema = pytest.importorskip("jsonschema")
    r = rep.build(tap_event(), decision())
    r["violation"][field] = bad
    with pytest.raises(ValueError):
        _validate(r)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(r, JSON_SCHEMA)


def test_other_extra_keys_in_the_violation_are_still_rejected(rep):
    jsonschema = pytest.importorskip("jsonschema")
    r = rep.build(tap_event(), decision())
    r["violation"]["transport"] = "tcp"
    with pytest.raises(ValueError):
        _validate(r)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(r, JSON_SCHEMA)


def test_the_enums_are_exactly_the_documented_ones():
    assert PROTOS == ["tcp", "udp", "quic", "dns", "unknown"]
    assert VIAS == ["syn_tap", "udp_tap", "dns_tap", "sock_diag", "proc_tcp", "unknown"]
    props = JSON_SCHEMA["properties"]["violation"]["properties"]
    assert props["proto"] == {"enum": PROTOS} and props["via"] == {"enum": VIAS}


def test_every_via_the_code_can_emit_is_in_the_enum_and_none_of_them_is_left_unused():
    src = "".join((ROOT / "src" / "cora_sentinel" / f).read_text() for f in ("netmon.py", "daemon.py"))
    emitted = set(_re.findall(r'"(syn_tap|udp_tap|dns_tap|sock_diag|proc_tcp)"', src))
    assert emitted <= set(VIAS)
    assert set(VIAS) - emitted == {"dns_tap", "unknown"}, "dns_tap is reserved (DNS goes through the UDP tap); unknown is the fallback"


def test_the_example_report_carries_the_fields_and_validates():
    ex = json.loads((ROOT / "examples" / "violation.example.json").read_text())
    assert ex["violation"]["proto"] in PROTOS and ex["violation"]["via"] in VIAS
    _validate(ex)


@pytest.mark.parametrize("copy,canonical", [("violation.schema.json", "schema/violation.schema.json"),
                                            ("violation.example.json", "examples/violation.example.json")])
def test_a_root_copy_of_the_schema_or_example_is_never_stale(copy, canonical):
    if not (ROOT / copy).exists():
        pytest.skip(f"{copy} is gone from the repository root")
    assert (ROOT / copy).read_text() == (ROOT / canonical).read_text(), f"{copy} drifted from {canonical}"


@pytest.mark.parametrize("evidence,want", [({}, "tcp"), ({"proto": "tcp"}, "tcp"), ({"proto": "udp"}, "udp"), ({"proto": "udp", "l7": "quic"}, "quic"),
                                           ({"proto": "udp", "l7": "dns"}, "dns"), ({"proto": "udp", "l7": "x"}, "udp"), ({"proto": "icmp"}, "unknown")])
def test_protocol_of_maps_what_conndetector_judge_produces(evidence, want):
    assert protocol_of(evidence) == want


# ---- every connection detector records them -------------------------------------------------------------------------
def test_build_payload_adds_detection_only_when_it_is_given_and_the_model_never_sees_it():
    from cora_sentinel.verdict import Qwen3B
    plain = build_payload(1, "10.1.1.10", "x", "path_violation", "high", {}, 5)
    assert "detection" not in plain, "path and memory events are unchanged"
    ev = build_payload(1, "10.1.1.10", "x", "unauthorized_connection", "high", {"remote_ip": "1.2.3.4"}, 5,
                       detection={"proto": "tcp", "via": "syn_tap"})
    assert ev["detection"] == {"proto": "tcp", "via": "syn_tap"}
    assert "syn_tap" not in Qwen3B.render(ev) and "detection" not in Qwen3B.render(ev)


def test_the_proc_path_records_proc_tcp_and_only_for_connections():
    s = Sentinel("CORA_TASK", ["/tmp"], 150, 10.0, lambda p: None)
    conn = s._payload(7, "10.1.1.10", "x", "unauthorized_connection", "high", {"remote_ip": "1.2.3.4", "remote_port": 80}, 5)
    assert conn["detection"] == {"proto": "tcp", "via": "proc_tcp"}
    udp = s._payload(7, "10.1.1.10", "x", "unauthorized_connection", "high", {"remote_ip": "1.2.3.4", "proto": "udp", "l7": "dns"}, 5)
    assert udp["detection"] == {"proto": "dns", "via": "proc_tcp"}
    assert "detection" not in s._payload(7, "10.1.1.10", "x", "path_violation", "high", {"path": "/etc/shadow"}, 5)
    assert "detection" not in s._payload(7, "10.1.1.10", "x", "memory_spike", "medium", {}, 5)


def deliver(ev):
    """Run netmon's _deliver on a bare object: no kernel, just what it builds and hands to the Sentinel."""
    from cora_sentinel import netmon
    cls = next(c for c in vars(netmon).values() if isinstance(c, type) and hasattr(c, "_deliver"))
    sent = []
    obj = object.__new__(cls)
    obj.s = _NS(net=VirtualNet(), cgroup_id_of=lambda name: 99, _fire=lambda key, now, payload: sent.append(payload))
    obj._deliver(("task-a", 4242, ["curl", "x"], 123, "high", ev, 1000.0))
    return sent[0]


def test_the_tap_and_the_live_scan_record_their_own_via_and_the_protocol():
    base = {"remote_ip": "203.0.113.9", "remote_port": 443, "local_port": 50000, "dest_class": "public"}
    assert deliver({**base, "via": "syn_tap"})["detection"] == {"proto": "tcp", "via": "syn_tap"}
    assert deliver({**base, "proto": "udp", "l7": "quic", "via": "udp_tap"})["detection"] == {"proto": "quic", "via": "udp_tap"}
    assert deliver({**base, "proto": "udp", "l7": "dns", "qname": "x.example", "via": "udp_tap"})["detection"] == {"proto": "dns", "via": "udp_tap"}
    assert deliver(dict(base))["detection"] == {"proto": "tcp", "via": "sock_diag"}, "no via = the live sock_diag scan"
    assert deliver({**base, "via": "syn_tap"})["subject"]["cgroup_id"] == 99, "and the 0.8.5 identity is still recorded"
