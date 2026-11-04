"""Part 1 runs anywhere. Part 2 (real kernel chain) needs root + nft + cgroup v2.
Run: sudo -E $(which python) -m pytest -q test_cora_report.py"""
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

import cora_report
from cora_blocklist import Blocklist
from cora_cgroup import CgroupRoot
from cora_firewall import Firewall
from cora_report import JSON_SCHEMA, Reporter, validate_report
from cora_sentinel import Sentinel, VirtualNet, build_payload, read_starttime
from cora_verdict import Adjudicator, Executor

HERE = Path(__file__).parent
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
    p = json.loads((HERE / "violation.schema.json").read_text())      # committed file == code
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
    p = subprocess.Popen([sys.executable, str(HERE / "cora_run.py"), "adtask", sys.executable, "-c", code],
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
