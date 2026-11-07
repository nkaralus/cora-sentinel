"""cora-run refuses to relaunch into a cgroup that still carries containment. Real CgroupRoot over a temp tree."""
import pytest

from cora_sentinel import run
from cora_sentinel.cgroup import CgroupRoot


class FakeFirewall:
    def __init__(self, rules=None, fail=None):
        self.rules_, self.fail = rules or {}, fail

    def rules(self):
        if self.fail:
            raise self.fail
        return dict(self.rules_)


@pytest.fixture
def cg(tmp_path):
    root = tmp_path / "cora"
    root.mkdir()
    return CgroupRoot(str(root))


def leftover(cg, name="traytest", cpu="max 100000", high="max", freeze="0"):
    d = cg.root / name
    d.mkdir()
    (d / "cpu.max").write_text(cpu + "\n")
    (d / "memory.high").write_text(high + "\n")
    (d / "cgroup.freeze").write_text(freeze + "\n")
    return d


def isolated(cg, name="traytest", cgid="current"):
    return FakeFirewall({name: {"handle": 3, "packets": 0, "bytes": 0,
                                "cgid": cg.cgroup_id(name) if cgid == "current" else cgid}})


# ---------------------------------------------------------------- the decision: refuse, naming the undo

def test_isolated_leftover_is_refused_with_the_exact_message(cg):
    leftover(cg)
    assert run.preflight(cg, "traytest", isolated(cg)) == (
        "task 'traytest' is currently isolated in nftables; release it first with 'sudo cora-firewall release traytest'")


def test_frozen_leftover_names_thaw(cg):
    leftover(cg, freeze="1")
    assert "sudo cora-cgroup thaw traytest" in run.preflight(cg, "traytest", FakeFirewall())


@pytest.mark.parametrize("cpu,high", [("20000 100000", "max"), ("max 100000", "838860800")])
def test_throttled_leftover_names_reset(cg, cpu, high):
    leftover(cg, cpu=cpu, high=high)
    assert "sudo cora-cgroup reset traytest" in run.preflight(cg, "traytest", FakeFirewall())


def test_isolation_is_reported_first(cg):
    leftover(cg, cpu="20000 100000", freeze="1")
    assert "cora-firewall release" in run.preflight(cg, "traytest", isolated(cg))


# ---------------------------------------------------------------- what is NOT refused

def test_a_new_task_starts(cg):
    assert run.preflight(cg, "traytest", FakeFirewall()) is None


def test_a_clean_leftover_starts(cg):
    leftover(cg)
    assert run.preflight(cg, "traytest", FakeFirewall()) is None


def test_a_rule_for_an_older_cgroup_of_that_name_does_not_block(cg):
    leftover(cg)
    assert run.preflight(cg, "traytest", isolated(cg, cgid=cg.cgroup_id("traytest") + 1)) is None


def test_a_legacy_rule_without_a_cgroup_id_blocks(cg):
    leftover(cg)
    assert run.preflight(cg, "traytest", isolated(cg, cgid=None)) is not None


def test_another_tasks_rule_does_not_block(cg):
    leftover(cg)
    assert run.preflight(cg, "traytest", isolated(cg, name="other")) is None


def test_missing_controller_files_are_not_containment(cg):
    (cg.root / "traytest").mkdir()                                # no cpu.max, memory.high or cgroup.freeze
    assert run.preflight(cg, "traytest", FakeFirewall()) is None


def test_unreadable_firewall_warns_and_starts(cg):
    """Fail open on purpose: the kernel rule still matches a reused cgroup, so containment does not depend on this."""
    leftover(cg)
    warnings = []
    r = run.preflight(cg, "traytest", FakeFirewall(fail=OSError("EPERM")), warn=warnings.append)
    assert r is None and "starting anyway" in warnings[0] and "cora-firewall list" in warnings[0]


def test_no_firewall_at_all_still_checks_the_cgroup(cg):
    leftover(cg, freeze="1")
    assert "thaw" in run.preflight(cg, "traytest", None)


# ---------------------------------------------------------------- main(): refuses before touching anything

def test_main_refuses_before_creating_moving_or_executing(cg, monkeypatch, capsys):
    d = leftover(cg)
    (d / "cgroup.procs").write_text("")
    monkeypatch.setenv("CORA_CGROUP_ROOT", str(cg.root))
    monkeypatch.setattr(run, "_firewall", lambda c: isolated(c))
    monkeypatch.setattr(run, "_preinstall_tap", lambda *a: pytest.fail("tap touched"))
    monkeypatch.setattr(run.os, "execvp", lambda *a: pytest.fail("the task was started"))
    monkeypatch.setattr("sys.argv", ["cora-run", "traytest", "python3", "traytest.py"])
    assert run.main() == run.EXIT_CONTAINED == 3
    assert (d / "cgroup.procs").read_text() == ""                 # this process was never moved in
    err = capsys.readouterr().err
    assert err.strip() == ("cora_run: task 'traytest' is currently isolated in nftables; "
                           "release it first with 'sudo cora-firewall release traytest'")


def test_main_proceeds_past_preflight_when_clean(cg, monkeypatch):
    leftover(cg)
    monkeypatch.setenv("CORA_CGROUP_ROOT", str(cg.root))
    monkeypatch.setattr(run, "_firewall", lambda c: FakeFirewall())
    monkeypatch.setattr(run, "_preinstall_tap", lambda *a: None)
    started = []
    monkeypatch.setattr(run.os, "execvp", lambda f, a: started.append(a))
    monkeypatch.setattr("sys.argv", ["cora-run", "traytest", "true"])
    run.main()
    assert started == [["true"]]
