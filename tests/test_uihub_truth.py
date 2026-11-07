"""What is in force comes from the kernel, not the decision log. Real CgroupRoot over a temp tree; a fake firewall
whose rules() is the nft chain as Firewall.rules() returns it."""
import pytest

from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.uihub import Hub, cgroup_tasks


class FakeFirewall:
    def __init__(self):
        self.rules_ = {}
        self.fail = None

    def rules(self):
        if self.fail:
            raise self.fail
        return dict(self.rules_)

    def block(self, cg, name):
        self.rules_[name] = {"handle": 1, "packets": 0, "bytes": 0, "cgid": cg.cgroup_id(name)}


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "cora"
    root.mkdir()
    cg = CgroupRoot(str(root))

    def task(name, cpu="max 100000", high="max", freeze="0", mem=1 << 20):
        d = root / name
        d.mkdir(exist_ok=True)
        (d / "cgroup.procs").write_text("4242\n")
        (d / "cpu.max").write_text(cpu + "\n")
        (d / "memory.high").write_text(high + "\n")
        (d / "cgroup.freeze").write_text(freeze + "\n")
        (d / "memory.current").write_text(f"{mem}\n")
        return d
    return cg, task


def hub_for(tmp_path, cg, fw, mode="enforce"):
    run = tmp_path / "run"
    run.mkdir(exist_ok=True)
    return Hub(str(run / "ui.sock"), mode=mode, tasks=cgroup_tasks(cg, fw), cgroup_id=cg.cgroup_id, log=lambda m: None)


def task_of(snap, name="traytest"):
    return next(t for t in snap["tasks"] if t["name"] == name)


# ---------------------------------------------------------------- the live failure, replayed

def test_a_release_on_the_command_line_shows_up(tmp_path, tree):
    """Nick's live test: Sever pressed, then `sudo cora-firewall release traytest`; the tray stayed indigo [ISOLATE]
    for the whole time the network was back."""
    cg, task = tree
    task("traytest")
    fw = FakeFirewall()
    h = hub_for(tmp_path, cg, fw)
    fw.block(cg, "traytest")                                      # the breaker's nft rule
    h.note_decision({"policy": "manual_operator_override", "action": "done:ISOLATE@cgroup:traytest[nft-drop-egress]"})
    s = h.snapshot()
    assert s["status"] == "contained" and task_of(s)["enforced"] == ["ISOLATE"]
    fw.rules_.clear()                                             # cora-firewall release traytest
    s = h.snapshot()
    assert s["status"] == "clear", "the log says done:ISOLATE, but the kernel no longer holds the rule"
    assert task_of(s)["enforced"] == [] and task_of(s)["contained"] == []


def test_a_block_made_outside_the_daemon_shows_up(tmp_path, tree):
    cg, task = tree
    task("traytest")
    fw = FakeFirewall()
    h = hub_for(tmp_path, cg, fw)
    assert h.snapshot()["status"] == "clear"
    fw.block(cg, "traytest")                                      # sudo cora-firewall block traytest
    assert task_of(h.snapshot())["enforced"] == ["ISOLATE"]


def test_reset_and_thaw_on_the_command_line_show_up(tmp_path, tree):
    cg, task = tree
    d = task("traytest", cpu="20000 100000", high="838860800", freeze="1")
    h = hub_for(tmp_path, cg, FakeFirewall())
    assert task_of(h.snapshot())["enforced"] == ["SUSPEND", "THROTTLE"]
    (d / "cpu.max").write_text("max 100000\n")
    (d / "memory.high").write_text("max\n")                       # sudo cora-cgroup reset traytest
    assert task_of(h.snapshot())["enforced"] == ["SUSPEND"]
    (d / "cgroup.freeze").write_text("0\n")                       # sudo cora-cgroup thaw traytest
    assert h.snapshot()["status"] == "clear"


@pytest.mark.parametrize("cpu,high,throttled", [
    ("max 100000", "max", False),
    ("20000 100000", "max", True),                                # the breaker's cpu cap alone
    ("max 100000", "838860800", True),                            # memory.high alone
])
def test_throttle_is_either_limit(tmp_path, tree, cpu, high, throttled):
    cg, task = tree
    task("traytest", cpu=cpu, high=high)
    t = task_of(hub_for(tmp_path, cg, FakeFirewall()).snapshot())
    assert ("THROTTLE" in t["enforced"]) is throttled


# ---------------------------------------------------------------- stale rules, relaunches, unreadable state

def test_a_rule_for_an_older_cgroup_of_the_same_name_does_not_count(tmp_path, tree):
    cg, task = tree
    task("traytest")
    fw = FakeFirewall()
    fw.rules_["traytest"] = {"handle": 9, "packets": 0, "bytes": 0, "cgid": cg.cgroup_id("traytest") + 1}
    assert task_of(hub_for(tmp_path, cg, fw).snapshot())["enforced"] == []


def test_a_legacy_rule_without_a_cgroup_id_still_counts(tmp_path, tree):
    cg, task = tree
    task("traytest")
    fw = FakeFirewall()
    fw.rules_["traytest"] = {"handle": 9, "packets": 0, "bytes": 0, "cgid": None}
    assert task_of(hub_for(tmp_path, cg, fw).snapshot())["enforced"] == ["ISOLATE"]


def test_unreadable_firewall_is_unknown_never_in_force(tmp_path, tree):
    cg, task = tree
    task("traytest")
    fw = FakeFirewall()
    fw.block(cg, "traytest")
    fw.fail = OSError("netlink: permission denied")
    s = hub_for(tmp_path, cg, fw).snapshot()
    t = task_of(s)
    assert t["enforced"] == [] and t["unknown"] == ["ISOLATE"]
    assert s["truth_errors"] == ["firewall unreadable (OSError)"] and s["status"] == "clear"


def test_unknown_still_offers_sever(tmp_path, tree):
    """Pressing Sever on a task that is in fact already blocked is harmless (block() returns 'already')."""
    from cora_sentinel.uiclient import StatusClient
    cg, task = tree
    task("traytest")
    fw = FakeFirewall()
    fw.fail = OSError("x")
    h = hub_for(tmp_path, cg, fw)
    h._act = lambda v, t: "done"
    c = StatusClient("/x")
    c.sock, c.last_rx, c.clock = object(), 0.0, (lambda: 0.0)
    c.state = h.snapshot()
    v = c.view()
    assert v["tasks"][0]["can_sever"] and "[ISOLATE?]" in v["tasks"][0]["line"]
    assert "firewall unreadable" in v["detail"]


def test_no_firewall_configured_is_not_an_error(tmp_path, tree):
    cg, task = tree
    task("traytest")
    s = hub_for(tmp_path, cg, None).snapshot()
    assert s["truth_errors"] == [] and task_of(s)["unknown"] == [] and task_of(s)["enforced"] == []


def test_missing_cgroup_files_mean_nothing_is_claimed(tmp_path, tree):
    cg, task = tree
    d = task("traytest")
    for f in ("cpu.max", "memory.high", "cgroup.freeze"):
        (d / f).unlink()                                          # controllers not delegated
    assert task_of(hub_for(tmp_path, cg, FakeFirewall()).snapshot())["enforced"] == []


# ---------------------------------------------------------------- dry-run would-haves are kept, apart

def test_dry_run_would_isolate_is_contained_but_not_enforced(tmp_path, tree):
    cg, task = tree
    task("traytest")
    h = hub_for(tmp_path, cg, FakeFirewall(), mode="dry-run")
    h.note_decision({"action": "dry-run:ISOLATE@cgroup:traytest"})
    t = task_of(h.snapshot())
    assert t["contained"] == ["ISOLATE"] and t["enforced"] == []


def test_a_logged_done_without_a_kernel_rule_is_not_claimed(tmp_path, tree):
    """The log can lie (an action that half-failed, or was undone): with a kernel reader, only the kernel counts."""
    cg, task = tree
    task("traytest")
    h = hub_for(tmp_path, cg, FakeFirewall())
    h.note_decision({"action": "done:ISOLATE@cgroup:traytest[nft-drop-egress]"})
    assert h.snapshot()["status"] == "clear"


def test_an_exited_task_whose_cgroup_still_holds_a_block_says_both(tmp_path, tree):
    """Live run: after Ctrl+C the cgroup (never removed; cora-run reuses it) still held the nft rule. That IS the
    truth, so the tray keeps it, and marks the task exited so it is not mistaken for a running one."""
    from cora_sentinel.uiclient import StatusClient
    cg, task = tree
    d = task("traytest")
    fw = FakeFirewall()
    fw.block(cg, "traytest")
    (d / "cgroup.procs").write_text("")                           # every process gone
    h = hub_for(tmp_path, cg, fw)
    c = StatusClient("/x")
    c.sock, c.last_rx, c.clock = object(), 0.0, (lambda: 0.0)
    c.state = h.snapshot()
    line = c.view()["tasks"][0]["line"]
    assert "[ISOLATE]" in line and line.endswith("\u2014 exited") and c.state["status"] == "contained"
