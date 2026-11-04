"""Part 1 runs anywhere (fake nft). Part 2 needs root + nft + a writable cgroup v2 mount.
Run: sudo -E $(which python) -m pytest -q test_cora_firewall.py"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from cora_cgroup import CgroupRoot
from cora_firewall import Firewall, FirewallError, release_task
from cora_sentinel import Sentinel, VirtualNet, build_payload, read_starttime
from cora_verdict import Adjudicator, Executor

HERE = Path(__file__).parent


# =========================== part 1: fake nft ===============================
class FakeNft:
    def __init__(self):
        self.rules, self.next, self.chain = [], 1, False

    def __call__(self, args, stdin):
        if args[:2] == ["-j", "list"]:
            if not self.chain:
                return 1, "", "Error: No such file or directory"
            items = [{"metainfo": {}}, {"chain": {}}] + [{"rule": r} for r in self.rules]
            return 0, json.dumps({"nftables": items}), ""
        if args == ["-f", "-"]:
            for line in stdin.splitlines():
                if line.startswith("add chain"):
                    self.chain = True
                elif line.startswith("add rule"):
                    c = re.search(r'comment "([^"]+)"', line).group(1)
                    self.rules.append({"handle": self.next, "comment": c, "text": line,
                                       "expr": [{"counter": {"packets": 0, "bytes": 0}}]})
                    self.next += 1
                elif line.startswith("delete rule"):
                    h = int(line.split()[-1])
                    self.rules = [r for r in self.rules if r["handle"] != h]
            return 0, "", ""
        if args[:3] == ["delete", "table", "inet"]:
            self.rules, self.chain = [], False
            return 0, "", ""
        return 1, "", "unexpected"


@pytest.fixture
def fake(tmp_path):
    base = tmp_path / "cgroup"
    root = base / "cora"
    root.mkdir(parents=True)
    n = FakeNft()
    return Firewall(CgroupRoot(str(root), str(base)), nft_base=str(base), run=n), n


def test_rule_text_pure_v2(fake):
    fw, _ = fake
    t = fw.rule_text("etl")
    assert 'level 2 "cora/etl"' in t and 'oifname != "lo"' in t and 'comment "cora:etl:' in t and "drop" in t


def test_rule_text_hybrid_layout(tmp_path):
    base = tmp_path / "cgroup"
    mount = base / "unified"
    root = mount / "cora"
    root.mkdir(parents=True)
    fw = Firewall(CgroupRoot(str(root), str(mount)), nft_base=str(base), run=FakeNft())
    # level = depth inside the v2 tree; path = what nft looks up from /sys/fs/cgroup
    assert 'level 2 "unified/cora/etl"' in fw.rule_text("etl")


@pytest.mark.parametrize("bad", ['a"b', "../x", "A", "", 'x; drop', "a b"])
def test_hostile_names_never_reach_nft(fake, bad):
    fw, n = fake
    with pytest.raises(Exception):
        fw.block(bad)
    assert n.rules == []


def test_hostile_root_path_refused(tmp_path):
    base = tmp_path / "cgroup"
    root = base / 'co"ra'
    root.mkdir(parents=True)
    fw = Firewall(CgroupRoot(str(root), str(base)), nft_base=str(base), run=FakeNft())
    with pytest.raises(FirewallError):
        fw.rule_text("etl")


def test_block_is_idempotent_and_per_task(fake):
    fw, n = fake
    assert fw.block("etl") is True and fw.block("etl") is False
    assert fw.block("web") is True
    assert sorted(fw.rules()) == ["etl", "web"] and len(n.rules) == 2


def test_unblock_touches_only_its_task(fake):
    fw, n = fake
    fw.block("etl"); fw.block("web")
    assert fw.unblock("etl") is True and fw.unblock("etl") is False
    assert list(fw.rules()) == ["web"]


def test_gc_removes_dead_tasks_only(fake):
    fw, _ = fake
    fw.block("etl"); fw.block("web")
    assert fw.gc({"web"}) == ["etl"] and list(fw.rules()) == ["web"]


def test_foreign_rules_are_ignored(fake):
    fw, n = fake
    n.chain = True
    n.rules.append({"handle": 99, "comment": "someone-else", "expr": []})
    fw.block("etl")
    assert list(fw.rules()) == ["etl"] and fw.gc(set()) == ["etl"]
    assert [r["handle"] for r in n.rules] == [99]       # never deleted


def test_purge_and_empty_state(fake):
    fw, n = fake
    assert fw.rules() == {}
    fw.block("etl"); fw.purge()
    assert fw.rules() == {}


def test_missing_nft_binary_is_a_clear_error(tmp_path):
    root = tmp_path / "c"; root.mkdir()
    fw = Firewall(CgroupRoot(str(root), str(tmp_path)), nft="/nonexistent/nft")
    with pytest.raises(FirewallError, match="not found"):
        fw.rules()


# ---- verdict-side policy (no kernel needed) -----------------------------
class Fake1:
    def __init__(self, v): self.v = v
    def judge(self, ev): return json.dumps({"verdict": self.v, "confidence": 0.9, "reason": "t"})


def _ev(net, cgroup):
    pid = os.getpid()
    return build_payload(pid, net.ensure(pid), "x", "unauthorized_connection", "high",
                         {"remote_ip": "8.8.8.8"}, read_starttime(pid), cgroup=cgroup)


def test_isolate_without_firewall_goes_to_a_human(fake):
    fw, _ = fake
    net = VirtualNet()
    d = Adjudicator(net, Fake1("ISOLATE"), Executor(True, fw.cg, None), None, 0.6).handle(_ev(net, "etl"))
    assert d["final"] == "ESCALATE" and d["policy"] == "isolate_unavailable" and d["action"] == "needs-human"


def test_isolate_event_without_cgroup_goes_to_a_human(fake):
    fw, _ = fake
    net = VirtualNet()
    d = Adjudicator(net, Fake1("ISOLATE"), Executor(True, fw.cg, fw), None, 0.6).handle(_ev(net, None))
    assert d["final"] == "ESCALATE" and d["policy"] == "isolate_unavailable"


def test_pid_mode_isolate_never_kills():
    p = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"])
    try:
        out = Executor(True).run("ISOLATE", p.pid, None)
        time.sleep(0.2)
        assert out.startswith("failed:unsupported") and p.poll() is None
    finally:
        p.kill(); p.wait()


# =========================== part 2: real kernel ============================
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


def _gateway():
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                return socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
    except OSError:
        pass


MOUNT, GW = _mount(), _gateway()
real = pytest.mark.skipif(not (MOUNT and _nft_ok() and GW), reason="needs root, nft, cgroup v2, a default route")


def sender(delay=0.0):
    return (f"import socket,time;time.sleep({delay});s=socket.socket(2,2);e=0\n"
            f"for _ in range(3):\n    try: s.sendto(b'x',('{GW}',9))\n    except OSError: e+=1\nprint(e)")


@pytest.fixture
def env():
    cg = CgroupRoot(f"{MOUNT}/coranft-{os.getpid()}", MOUNT)
    cg.ensure()
    fw = Firewall(cg, table=f"coratest{os.getpid()}")      # never the production table
    yield cg, fw
    fw.purge()
    for n in cg.names():
        try: cg.kill(n)
        except Exception: pass
    for _ in range(40):
        try:
            for n in cg.names(): (cg.root / n).rmdir()
            cg.root.rmdir(); break
        except OSError:
            time.sleep(0.1)


def popen_in(cg, name, code, **kw):
    e = {**os.environ, "CORA_CGROUP_ROOT": str(cg.root), "CORA_CGROUP_MOUNT": MOUNT}
    return subprocess.Popen([sys.executable, str(HERE / "cora_run.py"), name, sys.executable, "-c", code],
                            env=e, **kw)


def errors_in(cg, name, delay=0.0):
    p = popen_in(cg, name, sender(delay), stdout=subprocess.PIPE, text=True)
    return int(p.communicate(timeout=20)[0].strip())


@real
def test_block_drops_target_not_neighbour_and_unblock_restores(env):
    cg, fw = env
    cg.create("victim"); cg.create("bystander")
    fw.block("victim")
    assert errors_in(cg, "victim") == 3          # EPERM from the netfilter drop
    assert errors_in(cg, "bystander") == 0       # same machine, same code, untouched
    assert fw.rules()["victim"]["packets"] >= 3  # kernel counted them
    fw.unblock("victim")
    assert errors_in(cg, "victim") == 0


@real
def test_block_applies_to_an_already_running_task(env):
    cg, fw = env
    p = popen_in(cg, "live", sender(delay=1.5), stdout=subprocess.PIPE, text=True)
    time.sleep(0.5)
    fw.block("live")                              # task is mid-flight
    assert int(p.communicate(timeout=20)[0].strip()) == 3


@real
def test_loopback_stays_reachable_when_blocked(env):
    cg, fw = env
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(1)
    cg.create("lo")
    fw.block("lo")
    code = f"import socket;socket.create_connection(('127.0.0.1',{lis.getsockname()[1]}),timeout=3);print('up')"
    p = popen_in(cg, "lo", code, stdout=subprocess.PIPE, text=True)
    assert p.communicate(timeout=20)[0].strip() == "up"
    lis.close()


@real
def test_gc_after_cgroup_removed(env):
    cg, fw = env
    cg.create("gone"); fw.block("gone")
    (cg.root / "gone").rmdir()
    assert fw.gc(cg.names()) == ["gone"] and fw.rules() == {}


@real
def test_isolate_via_adjudicator_keeps_tree_alive_and_release_undoes_all(env):
    cg, fw = env
    tree = ("import subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);time.sleep(60)")
    popen_in(cg, "tree", tree)
    end = time.monotonic() + 5
    while time.monotonic() < end and len(cg.pids("tree")) < 2:
        time.sleep(0.1)
    pids = cg.pids("tree")
    net = VirtualNet()
    pid = pids[-1]
    ev = build_payload(pid, net.ensure(pid), "x", "unauthorized_connection", "high",
                       {"remote_ip": "8.8.8.8"}, read_starttime(pid), cgroup="tree")
    d = Adjudicator(net, Fake1("ISOLATE"), Executor(True, cg, fw), None, 0.6).handle(ev)
    assert d["gate"]["ok"] and d["action"].startswith("done:ISOLATE@cgroup:tree")
    assert fw.is_blocked("tree")
    assert all(os.path.exists(f"/proc/{x}") for x in pids)       # contained, not killed
    cg.freeze("tree"); cg.throttle("tree")
    undone = release_task(cg, fw, "tree")
    assert "egress-unblocked" in undone and "thawed" in undone
    assert not fw.is_blocked("tree") and not cg.is_frozen("tree")


@real
def test_full_chain_real_connection_event_to_kernel_drop(env):
    cg, fw = env
    lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen(1)
    code = (f"import socket,time;c=socket.create_connection(('127.0.0.1',{lis.getsockname()[1]}));"
            f"time.sleep(3.0);s=socket.socket(2,2);e=0\n"
            f"for _ in range(3):\n    try: s.sendto(b'x',('{GW}',9))\n    except OSError: e+=1\nprint(e)")
    p = popen_in(cg, "chain", code, stdout=subprocess.PIPE, text=True)
    events = []
    s = Sentinel("UNUSED", ["/tmp"], spike_mb=10**6, window_s=5, emit=events.append,
                 net_allow=["10.0.0.0/8"], cgroups=cg)         # loopback not allowed -> trips
    end = time.monotonic() + 2.5
    while time.monotonic() < end and not events:
        s.tick(); time.sleep(0.1)
    ev = next(e for e in events if e["anomaly"]["kind"] == "unauthorized_connection")
    assert ev["subject"]["cgroup"] == "chain"
    d = Adjudicator(s.net, Fake1("ISOLATE"), Executor(True, cg, fw), None, 0.6).handle(ev)
    assert d["action"].startswith("done:ISOLATE")
    assert int(p.communicate(timeout=20)[0].strip()) == 3        # its later egress is dropped
    lis.close()


@real
def test_recreated_cgroup_is_blocked_not_reported_as_already_blocked(env):
    """Regression: block() used to decide 'already blocked' by NAME, so a recreated task with the
    same name stayed open while the firewall claimed it was contained."""
    cg, fw = env
    cg.create("recycle")
    assert fw.block("recycle") is True and errors_in(cg, "recycle") == 3
    (cg.root / "recycle").rmdir()                       # task finished ...
    cg.create("recycle")                                # ... and a NEW task reuses the name
    assert errors_in(cg, "recycle") == 0                # the old rule matches the old cgroup id: new one is open
    assert fw.block("recycle") is True                  # must re-block, not say "already"
    assert errors_in(cg, "recycle") == 3                # and the new cgroup really is contained
    assert len(fw.rules()) == 1                         # the stale rule was replaced, not accumulated


@real
def test_gc_removes_a_stale_rule_for_a_live_name(env):
    cg, fw = env
    cg.create("again"); fw.block("again")
    (cg.root / "again").rmdir(); cg.create("again")
    assert fw.gc(cg.names()) == ["again"] and fw.rules() == {}


def test_release_thaws_a_freeze_that_is_requested_but_not_yet_complete(tmp_path):
    """Regression. Freezing is asynchronous: cgroup.freeze=1 is written at once, but cgroup.events only
    says 'frozen 1' once every process has stopped. release_task used to key on the latter, so a release
    issued mid-freeze skipped the thaw and silently left the task frozen."""
    base = tmp_path / "cgroup"; root = base / "cora"; (root / "t").mkdir(parents=True)
    (root / "t" / "cgroup.freeze").write_text("1\n")           # requested ...
    (root / "t" / "cgroup.events").write_text("populated 1\nfrozen 0\n")   # ... but not complete yet
    cg = CgroupRoot(str(root), str(base))
    fw = Firewall(cg, nft_base=str(base), run=FakeNft())
    assert not cg.is_frozen("t")                               # the old check would have stopped here
    undone = release_task(cg, fw, "t")
    assert "thawed" in undone
    assert (root / "t" / "cgroup.freeze").read_text().strip() == "0"
