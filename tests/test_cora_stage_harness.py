"""tools/cora_stage_harness.py: Ticket -> .cascade/ staging -> verification -> PARKED | atomic symlink swap.

Real files, real flock, real subprocesses, real SIGKILL; the vendored mule and subnetbus. The only seam is the verify
sandbox and memory cap: most tests pass allow_unsandboxed_for_tests (their verifier is a one-line python), and the
sandbox, the cap and the scope kill are tested on their own below, for real, wherever this machine allows them."""
import dataclasses
import importlib.util
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("cora_stage_harness", REPO / "tools" / "cora_stage_harness.py")
H = importlib.util.module_from_spec(_spec)
sys.modules["cora_stage_harness"] = H
_spec.loader.exec_module(H)
B = sys.modules["cora_exec_bridge"]

PY = sys.executable
OK = [PY, "-c", "pass"]
EXCLUDE = ["untyped_variables", "relative_paths_up_tree", "cross_subnet_queries", "freeform_code_blocks",
           "synthetic_transactions"]
ARENA, LOBBY = "10.2.1.0/24", "10.2.2.0/24"


def raw(**over):
    b = {"frame_id": "0x00a1", "time_slot": "SLOT_3_EXECUTE", "subnet": ARENA, "op": "place", "target": "%Crate",
         "ref": "10.2.1.10", "exclude": EXCLUDE, "x": 500, "y": 500, "w": 50, "h": 50}
    b.update(over)
    return json.dumps(b, separators=(",", ":"))


def lobby_raw(**over):
    return raw(subnet=LOBBY, target="%Other", ref="10.2.2.10", x=100, y=100, w=10, h=10, **over)


@pytest.fixture
def base(tmp_path):
    b = tmp_path / "proj"
    (b / "live" / "scenes").mkdir(parents=True)
    B.demo_registry().save(b / "live" / "state_registry.json")
    (b / "live" / "scenes" / "main.tscn").write_text("[gd_scene format=3]\n")
    H.bootstrap(b)
    return b


def harness(base, verify=OK, **kw):
    kw.setdefault("sandbox", ())
    kw.setdefault("memory_max", None)
    return H.Harness(base, verify, allow_unsandboxed_for_tests=True, **kw)


def ticket(h, text=None):
    v, t = h.mint(text or raw())
    assert v.ok, v
    return t


def live(base):
    vid = os.readlink(base / "live").split("/")[-1]
    return vid, H.digest(H.manifest(base / ".cascade" / "versions" / vid))


def stages(base):
    return sorted(p.name for p in (base / ".cascade" / "versions").iterdir() if p.name.startswith("t-"))


def journal(base):
    return [json.loads(line) for line in (base / ".cascade" / "journal.jsonl").read_text().splitlines()]


def assert_rolled_back_clean(base, before, h, tid):
    assert live(base) == before
    committed = {f"t-{i}" for i, st in h.status()["tickets"].items() if st == "COMMITTED"}
    assert [s for s in stages(base) if s not in committed] == [] and not list(base.glob(".live.tmp-*"))
    assert h.halted() is None and h.status()["tickets"][tid] == "ROLLED_BACK"


# ================================================================ contract
def test_the_state_machine_is_exactly_the_specified_one():
    assert H.STATES == ["RECEIVED", "STAGED", "APPLIED", "POSTCHECKED", "PARKED", "COMMITTED", "ROLLED_BACK", "HALTED"]
    assert H.TERMINAL == {"COMMITTED", "ROLLED_BACK", "HALTED"}


def test_tickets_are_immutable_and_round_trip(base):
    t = ticket(harness(base))
    with pytest.raises(dataclasses.FrozenInstanceError):
        t.registry_rev = 99
    with pytest.raises(TypeError):
        t.action["x"] = 0
    assert isinstance(t.action["exclude"], tuple)
    assert B.Ticket.from_dict(json.loads(json.dumps(t.to_dict()))) == t
    assert (t.ttl_s, t.registry_rev, len(t.digest)) == (60, 6, 64)
    for junk in ({}, {**t.to_dict(), "registry_rev": "6"}, {**t.to_dict(), "extra": 1}):
        with pytest.raises(ValueError):
            B.Ticket.from_dict(junk)


def test_only_bridge_tickets_are_accepted(base):
    assert harness(base).submit(ticket(harness(base)).to_dict()).code == "BAD_TICKET"


# ================================================================ bootstrap
def test_a_live_directory_is_refused_until_bootstrapped(tmp_path):
    b = tmp_path / "p"
    (b / "live").mkdir(parents=True)
    B.demo_registry().save(b / "live" / "state_registry.json")
    h = harness(b)
    v, t = B.Bridge(B.demo_registry()).mint(raw())
    assert h.submit(t).code == "NOT_BOOTSTRAPPED"
    assert not (b / ".cascade").exists() and (b / "live").is_dir()
    assert H.bootstrap(b) == "bootstrapped: live -> .cascade/versions/v0"
    assert os.readlink(b / "live") == ".cascade/versions/v0" and (b / ".cascade/versions/v0/state_registry.json").is_file()
    assert H.bootstrap(b).startswith("already bootstrapped")


def test_bootstrap_finishes_after_a_crash_between_its_two_steps(tmp_path):
    b = tmp_path / "p"
    (b / "live").mkdir(parents=True)
    B.demo_registry().save(b / "live" / "state_registry.json")
    (b / ".cascade" / "versions").mkdir(parents=True)
    os.rename(b / "live", b / ".cascade" / "versions" / "v0")              # the rename happened, the symlink did not
    assert H.bootstrap(b).startswith("bootstrapped")
    assert harness(b).status()["live"] == "v0"


def test_bootstrap_refuses_a_tree_without_a_valid_registry(tmp_path):
    b = tmp_path / "p"
    (b / "live").mkdir(parents=True)
    with pytest.raises(OSError):
        H.bootstrap(b)
    assert (b / "live").is_dir() and not (b / ".cascade").exists()


# ================================================================ the happy paths
def test_stage_only_parks_and_live_does_not_move_until_approved(base):
    h = harness(base)
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert (r.ok, r.code, r.state) == (True, "PARKED", "PARKED")
    assert live(base) == before and h.live_registry().revision == 6
    assert [j["t"] for j in journal(base)] == ["RECEIVED", "STAGED", "APPLIED", "POSTCHECKED", "PARKED"]
    r = h.approve(t.id)
    assert (r.ok, r.code) == (True, "COMMITTED")
    assert live(base)[0] == f"t-{t.id}" and os.readlink(base / "live") == f".cascade/versions/t-{t.id}"
    reg = h.live_registry()                                  # files and registry came over in the same swap
    assert reg.revision == 7 and reg.get("%Crate").bounds == B.AABB(500, 500, 50, 50)
    assert (base / "live" / "scenes" / "main.tscn").read_text() == "[gd_scene format=3]\n"
    assert H.digest(H.manifest(base / ".cascade" / "versions" / "v0")) == before[1]     # the old version is untouched


def test_auto_commit_is_opt_in_per_subnet(base):
    h = harness(base, auto_commit=[LOBBY])
    assert h.submit(ticket(h, raw())).code == "PARKED"
    r = h.submit(ticket(h, lobby_raw()))
    assert (r.ok, r.code) == (True, "COMMITTED")
    assert h.live_registry().get("%Other").bounds == B.AABB(100, 100, 10, 10)


def test_a_declared_file_change_travels_with_the_registry(base):
    def write_scene(stage, action):
        (stage / "scenes" / "main.tscn").write_text(f"[gd_scene format=3]\n; {action['target']} at {action['x']}\n")
        return ["scenes/main.tscn"]
    h = harness(base, auto_commit=[ARENA], apply_files=write_scene)
    assert h.submit(ticket(h)).code == "COMMITTED"
    assert (base / "live" / "scenes" / "main.tscn").read_text().endswith("%Crate at 500\n")
    assert h.live_registry().revision == 7


# ================================================================ admission
def test_dedup_key_is_subnet_digest_and_revision(base):
    h = harness(base, auto_commit=[ARENA])
    t = ticket(h)
    assert h.submit(t).code == "COMMITTED"
    assert h.submit(t).code == "DUP_TICKET"                                  # the same ticket
    h2 = harness(base, auto_commit=[ARENA])
    same_text_new_rev = ticket(h2)
    assert same_text_new_rev.registry_rev == 7
    assert h2.submit(same_text_new_rev).code == "COMMITTED"                  # identical text, new revision: allowed
    stale_copy = B.Ticket.from_dict({**t.to_dict(), "id": "another-id"})     # same text, the OLD revision again
    stale_copy = dataclasses.replace(stale_copy, minted_ts=same_text_new_rev.minted_ts)
    assert h2.submit(stale_copy).code == "DUP_TICKET"


def test_one_parked_ticket_per_subnet(base):
    h = harness(base)
    first = ticket(h)
    assert h.submit(first).code == "PARKED"
    second = ticket(h, raw(x=600))
    r = h.submit(second)
    assert r.code == "SUBNET_BUSY" and first.id in r.detail
    assert h.submit(ticket(h, lobby_raw())).code == "PARKED"                 # another subnet is not blocked
    assert h.discard(first.id).code == "DISCARDED"
    assert h.status()["tickets"][first.id] == "ROLLED_BACK" and f"t-{first.id}" not in stages(base)
    assert h.submit(second).code == "PARKED"


def test_one_ticket_in_flight_per_subnet(base):
    h = harness(base)
    lock = base / ".cascade" / "locks" / "subnet-10.2.1.0_24.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT)
    H.fcntl.flock(fd, H.fcntl.LOCK_EX)                                       # another process is mid-ticket
    try:
        assert h.submit(ticket(h)).code == "SUBNET_BUSY"
        assert h.submit(ticket(h, lobby_raw())).code == "PARKED"
    finally:
        os.close(fd)
    assert h.submit(ticket(h)).code == "PARKED"


@pytest.mark.parametrize("shift", [{"mono": -61.0, "wall": 0.0}, {"mono": 0.0, "wall": -61.0}, {"mono": 5.0, "wall": 0.0}])
def test_a_ticket_past_its_ttl_by_either_clock_is_refused(base, shift):
    h = harness(base)
    t = ticket(h)
    ts = {k: t.minted_ts[k] + shift[k] for k in ("mono", "wall")}            # mono in the future: a reboot happened
    old = B.Ticket.from_dict({**t.to_dict(), "minted_ts": ts})
    assert h.submit(old).code == "TICKET_EXPIRED"
    assert not (base / ".cascade" / "journal.jsonl").exists()


# ================================================================ TOCTOU
def test_stale_rev_at_staged(base):
    h = harness(base, auto_commit=[LOBBY])
    arena = ticket(h)                                                        # minted at revision 6
    assert h.submit(ticket(h, lobby_raw())).code == "COMMITTED"              # the registry moves to 7
    before = live(base)
    r = h.submit(arena)
    assert (r.code, r.state) == ("STALE_REV", "ROLLED_BACK") and "revision 7" in r.detail
    assert_rolled_back_clean(base, before, h, arena.id)                      # another subnet's commit is not a mismatch


def test_two_subnets_parked_at_the_same_revision_only_the_first_approval_commits(base):
    h = harness(base)
    a, b = ticket(h, raw()), ticket(h, lobby_raw())
    assert a.registry_rev == b.registry_rev == 6
    assert (h.submit(a).code, h.submit(b).code) == ("PARKED", "PARKED")
    assert h.status()["parked"] == {ARENA: a.id, LOBBY: b.id}
    r = h.approve(a.id)
    assert (r.code, h.live_registry().revision) == ("COMMITTED", 7)
    after_a = live(base)
    assert after_a[0] == f"t-{a.id}"
    r = h.approve(b.id)
    assert (r.ok, r.code, r.state) == (False, "STALE_REV", "ROLLED_BACK") and "revision 7" in r.detail
    assert live(base) == after_a                                             # still exactly A's commit
    reg = h.live_registry()
    assert reg.revision == 7 and reg.get("%Crate").bounds == B.AABB(500, 500, 50, 50)
    assert reg.get("%Other").bounds == B.AABB(0, 0, 10, 10)                  # B's change never landed
    assert f"t-{b.id}" not in stages(base) and h.halted() is None


def test_stale_rev_when_approving_a_parked_ticket(base):
    h = harness(base, auto_commit=[LOBBY])
    parked = ticket(h)
    assert h.submit(parked).code == "PARKED"
    assert h.submit(ticket(h, lobby_raw())).code == "COMMITTED"
    before = live(base)
    r = h.approve(parked.id)
    assert (r.code, r.state) == ("STALE_REV", "ROLLED_BACK")
    assert_rolled_back_clean(base, before, h, parked.id)


def test_a_modified_parked_version_is_drift(base):
    h = harness(base)
    t = ticket(h)
    h.submit(t)
    before = live(base)
    (base / ".cascade" / "versions" / f"t-{t.id}" / "scenes" / "main.tscn").write_text("tampered\n")
    r = h.approve(t.id)
    assert (r.code, r.state) == ("DRIFT", "ROLLED_BACK") and "not what was verified" in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


def test_live_repointed_by_hand_is_drift(base):
    h = harness(base)
    t = ticket(h)
    h.submit(t)
    versions = base / ".cascade" / "versions"
    H.shutil.copytree(versions / "v0", versions / "v0-handmade", symlinks=True)       # same content, same revision
    os.symlink(".cascade/versions/v0-handmade", base / "live.new")
    os.replace(base / "live.new", base / "live")
    r = h.approve(t.id)
    assert r.state == "HALTED" and "DRIFT" in r.detail and "unknown to the journal" in r.detail
    assert live(base)[0] == "v0-handmade"


def test_a_registry_change_to_another_node_fails_the_postcheck(base):
    def move_the_wall(name):
        if name == "after_applied":
            p = next((base / ".cascade" / "versions").glob("t-*")) / "state_registry.json"
            d = json.loads(p.read_text())
            d["nodes"]["%Wall"]["bounds"]["x"] = 900.0
            p.write_text(json.dumps(d))
    h = harness(base, fault=move_the_wall)
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert r.code == "POSTCHECK_FAIL" and "a node other than the target changed" in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


def test_a_modified_live_tree_is_drift_and_then_halts(base):
    h = harness(base)
    t = ticket(h)
    h.submit(t)
    (base / "live" / "scenes" / "main.tscn").write_text("edited behind the harness's back\n")
    r = h.approve(t.id)
    assert (r.code, r.state) == ("ROLLBACK_MISMATCH", "HALTED") and "DRIFT" in r.detail
    assert h.halted()["ticket"] == t.id


# ================================================================ fault injection
def raise_at(point, exc=RuntimeError):
    def fault(name):
        if name == point:
            raise exc(f"injected at {point}")
    return fault


@pytest.mark.parametrize("point, code, exc", [
    ("stage", "STAGE_IO", OSError),
    ("stage", "STAGE_IO", RuntimeError),
    ("apply", "APPLY_FAIL", RuntimeError),
    ("postcheck", "POSTCHECK_FAIL", RuntimeError),
    ("commit", "COMMIT_FAIL", OSError),                                      # after os.replace: the swap is undone
    ("before_swap", "COMMIT_FAIL", RuntimeError),
])
def test_a_fault_in_any_phase_rolls_back_byte_for_byte(base, point, code, exc):
    h = harness(base, auto_commit=[ARENA], fault=raise_at(point, exc))
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert (r.ok, r.code, r.state) == (False, code, "ROLLED_BACK"), r
    assert_rolled_back_clean(base, before, h, t.id)
    assert journal(base)[-1]["t"] == "ROLLED_BACK" and journal(base)[-1]["code"] == code


def test_apply_fail_from_the_file_hook(base):
    def broken(stage, action):
        raise ValueError("cannot place it in the scene")
    h = harness(base, apply_files=broken)
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert r.code == "APPLY_FAIL" and "cannot place it" in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


def test_an_undeclared_change_fails_the_postcheck(base):
    def sneaky(stage, action):
        (stage / "scenes" / "main.tscn").write_text("changed\n")
        (stage / "backdoor.gd").write_text("extends Node\n")
        return ["scenes/main.tscn"]
    h = harness(base, apply_files=sneaky)
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert r.code == "POSTCHECK_FAIL" and "undeclared changes: backdoor.gd" in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


def test_verify_fail(base):
    h = harness(base, [PY, "-c", "import sys; print('scene does not load'); sys.exit(3)"])
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert r.code == "VERIFY_FAIL" and "exit 3" in r.detail and "scene does not load" in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


@pytest.mark.parametrize("dirty, shows", [
    ("open('import.cache', 'w').write('x')", "import.cache"),                               # a new file
    ("open('scenes/main.tscn', 'a').write('x')", "scenes/main.tscn"),                       # changed content
    ("import os; os.remove('scenes/main.tscn')", "scenes/main.tscn"),                       # deleted
    ("import os; os.chmod('scenes/main.tscn', 0o777)", "scenes/main.tscn"),                 # mode only
    ("import os; os.mkdir('.godot')", ".godot"),                                            # a directory
    ("import os; os.remove('scenes/main.tscn'); os.symlink('/etc/passwd', 'scenes/main.tscn')", "scenes/main.tscn"),
    ("open('import.cache', 'w').write('x'); raise SystemExit(4)", "import.cache"),          # dirtied AND failed
])
def test_the_tripwire_catches_any_change_the_verifier_makes(base, dirty, shows):
    h = harness(base, [PY, "-c", dirty])
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert (r.code, r.state) == ("VERIFY_FAIL", "ROLLED_BACK")
    assert r.detail.startswith("staged tree modified by verifier") and shows in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


def test_the_tripwire_also_wins_over_a_timeout(base):
    h = harness(base, [PY, "-c", "open('x', 'w'); import time; time.sleep(60)"], verify_timeout_s=1.0)
    r = h.submit(ticket(h))
    assert r.code == "VERIFY_FAIL" and r.detail.startswith("staged tree modified by verifier")


def test_verify_timeout_kills_the_whole_process_group(base, tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    script = (f"import subprocess, time; p = subprocess.Popen(['sleep', '60']); "
              f"open({str(pidfile)!r}, 'w').write(str(p.pid)); time.sleep(60)")
    h = harness(base, [PY, "-c", script], verify_timeout_s=1.0)
    before = live(base)
    t = ticket(h)
    started = time.monotonic()
    r = h.submit(t)
    assert r.code == "VERIFY_TIMEOUT" and time.monotonic() - started < 10
    pid = int(pidfile.read_text())
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)                                                      # the grandchild went with the group
    assert_rolled_back_clean(base, before, h, t.id)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_commit_fail_when_the_swap_itself_fails(base):
    h = harness(base, auto_commit=[ARENA])
    before = live(base)
    t = ticket(h)
    os.chmod(base, 0o555)                                                    # the new symlink cannot be created
    try:
        r = h.submit(t)
    finally:
        os.chmod(base, 0o755)
    assert (r.code, r.state) == ("COMMIT_FAIL", "ROLLED_BACK") and "PermissionError" in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


# ================================================================ rollback mismatch -> HALTED
def test_rollback_mismatch_halts_everything_until_a_person_clears_it(base):
    escape = str(base / ".cascade" / "versions" / "v0" / "scenes" / "main.tscn")
    h = harness(base, [PY, "-c", f"open({escape!r}, 'w').write('escaped'); raise SystemExit(1)"])   # out of its stage
    t = ticket(h)
    r = h.submit(t)
    assert (r.ok, r.code, r.state) == (False, "ROLLBACK_MISMATCH", "HALTED")
    assert "VERIFY_FAIL" in r.detail and h.halted()["ticket"] == t.id
    assert journal(base)[-1]["t"] == "HALTED"
    assert f"t-{t.id}" in stages(base)                                       # kept for whoever inspects it
    h2 = harness(base, auto_commit=[LOBBY])                                  # every instance, every subnet
    assert h2.recovered == []
    assert h2.submit(ticket(h2, lobby_raw())).code == "HALTED"
    assert h2.status()["halted"]["code"] == "ROLLBACK_MISMATCH"
    (base / ".cascade" / "HALTED").unlink()                                  # a person looked and cleared it
    assert harness(base, auto_commit=[LOBBY]).submit(ticket(h2, lobby_raw())).code == "COMMITTED"


def test_a_halted_harness_refuses_approval_of_parked_tickets(base):
    h = harness(base)
    t = ticket(h)
    assert h.submit(t).code == "PARKED"
    (base / ".cascade" / "HALTED").write_text("{}")
    r = h.approve(t.id)
    assert (r.code, r.state) == ("HALTED", "PARKED") and live(base)[0] == "v0"


def test_a_halt_during_a_run_stops_it_before_the_swap(base):
    def halt_elsewhere(name):
        if name == "after_postchecked":
            (base / ".cascade" / "HALTED").write_text('{"code": "ROLLBACK_MISMATCH"}')
    h = harness(base, auto_commit=[ARENA], fault=halt_elsewhere)
    r = h.submit(ticket(h))
    assert (r.code, r.state) == ("HALTED", "ROLLED_BACK") and live(base)[0] == "v0"


# ================================================================ crash recovery: SIGKILL at every transition
DRIVER = textwrap.dedent("""
    import importlib.util, os, signal, sys, time
    spec = importlib.util.spec_from_file_location("cora_stage_harness", sys.argv[1])
    H = importlib.util.module_from_spec(spec); sys.modules["cora_stage_harness"] = H; spec.loader.exec_module(H)
    base, point, auto, verify, text, ready = sys.argv[2:8]
    def fault(name):
        if name == point:
            if ready != "-":
                open(ready, "w").write("x")
                time.sleep(60)                     # alive and holding the subnet lock until killed
            os.kill(os.getpid(), signal.SIGKILL)
    h = H.Harness(base, verify.split("|"), auto_commit=[auto] if auto != "-" else [], sandbox=(), memory_max=None,
                  allow_unsandboxed_for_tests=True, fault=fault)
    v, t = h.mint(text)
    print(h.submit(t), flush=True)
""")


def crash(base, tmp_path, point, auto="-", verify=OK, text=None, ready="-", wait=True):
    drv = tmp_path / "driver.py"
    drv.write_text(DRIVER)
    args = [PY, str(drv), str(REPO / "tools" / "cora_stage_harness.py"), str(base), point, auto, "|".join(verify),
            text or raw(), ready]
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    if not wait:
        return subprocess.Popen(args, env=env)
    r = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == -signal.SIGKILL, r.stdout + r.stderr
    return r


@pytest.mark.parametrize("point, auto, verify", [
    ("after_received", "-", OK),
    ("stage", "-", OK),                                                      # copied, not yet fsynced or journaled
    ("after_staged", "-", OK),
    ("apply", "-", OK),                                                      # registry changed in memory, not saved
    ("after_applied", "-", OK),
    ("after_postchecked", "-", OK),
    ("before_swap", ARENA, OK),
    ("after_swap", ARENA, OK),                                               # live already points at the new version
    ("rollback_after_swapback", "-", [PY, "-c", "raise SystemExit(1)"]),     # killed while rolling back
])
def test_kill_9_at_any_transition_is_rolled_back_on_restart(base, tmp_path, point, auto, verify):
    before = live(base)
    crash(base, tmp_path, point, auto, verify)
    tid = journal(base)[0]["id"]
    assert journal(base)[-1]["t"] not in H.TERMINAL                         # read without starting a harness
    if point == "after_swap":
        assert live(base)[0] == f"t-{tid}"
    h = harness(base)                                                        # startup: recovery before new input
    assert [(r.code, r.state) for r in h.recovered] == [("RECOVERED", "ROLLED_BACK")]
    assert_rolled_back_clean(base, before, h, tid)
    assert h.submit(ticket(h)).code == "DUP_TICKET"                          # same (subnet, digest, rev) as the crashed one
    assert h.submit(ticket(h, raw(x=600))).code == "PARKED"                  # and it accepts new input


def test_kill_9_after_parked_keeps_the_ticket_and_it_can_still_be_approved(base, tmp_path):
    crash(base, tmp_path, "after_parked")
    tid = journal(base)[0]["id"]
    h = harness(base)
    assert h.recovered == [] and h.status()["tickets"][tid] == "PARKED"
    r = h.approve(tid)
    assert r.code == "COMMITTED" and h.live_registry().revision == 7


def test_a_parked_ticket_whose_version_was_modified_is_rolled_back_on_restart(base, tmp_path):
    crash(base, tmp_path, "after_parked")
    tid = journal(base)[0]["id"]
    (base / ".cascade" / "versions" / f"t-{tid}" / "state_registry.json").write_text("{}")
    before = live(base)
    h = harness(base)
    assert [(r.code, r.state) for r in h.recovered] == [("DRIFT", "ROLLED_BACK")]
    assert_rolled_back_clean(base, before, h, tid)


def test_recovery_leaves_a_live_owner_alone_and_takes_over_when_it_dies(base, tmp_path):
    ready = tmp_path / "ready"
    proc = crash(base, tmp_path, "after_staged", ready=str(ready), wait=False)
    try:
        for _ in range(200):
            if ready.exists():
                break
            time.sleep(0.05)
        assert ready.exists()
        tid = journal(base)[0]["id"]
        h = harness(base)
        assert h.recovered == [] and h.status()["tickets"][tid] == "STAGED"   # its owner holds the subnet lock
    finally:
        proc.kill()
        proc.wait()
    h = harness(base)                                                        # the kernel released the dead owner's lock
    assert [r.code for r in h.recovered] == ["RECOVERED"] and h.status()["tickets"][tid] == "ROLLED_BACK"


def test_a_stray_swap_symlink_is_cleaned_up(base):
    os.symlink(".cascade/versions/v0", base / ".live.tmp-deadbeef")          # killed between symlink() and replace()
    harness(base)
    assert not list(base.glob(".live.tmp-*"))


def test_a_torn_last_journal_line_is_ignored_but_a_corrupt_middle_is_not(base):
    h = harness(base)
    t = ticket(h)
    h.submit(t)
    j = base / ".cascade" / "journal.jsonl"
    with open(j, "a") as f:
        f.write('{"t":"COMMITTED","id":"')                                   # a crash mid-append
    assert harness(base).status()["tickets"][t.id] == "PARKED"
    lines = j.read_text().splitlines()
    lines[1] = "garbage"
    j.write_text("\n".join(lines) + "\n")
    with pytest.raises(RuntimeError, match="line 2 is corrupt"):
        harness(base)


# ================================================================ the verify sandbox
def runs(argv, tmp="/tmp"):
    try:
        argv = [a.replace(H.STAGE, tmp) for a in argv]
        env = {**H.VERIFY_ENV, **{k: os.environ[k] for k in H.SCOPE_ENV if k in os.environ}}
        return subprocess.run([*argv, "true"], capture_output=True, timeout=20, env=env).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


UNSHARE_USERNS = ["unshare", "--user", "--map-root-user", "--net", "--", *H._LO_UP]
SANDBOX = runs(H.default_sandbox())
SCOPE = runs(H.scope_argv(f"cora-probe-{os.getpid()}", "64M"))
NO_SANDBOX = "no network namespace here (bwrap missing and unprivileged unshare refused)"
NO_SCOPE = "systemd-run --scope with MemoryMax is not available here (no user manager, or memory not delegated)"


def test_unsandboxed_or_uncapped_verification_has_to_be_asked_for_by_name(base):
    with pytest.raises(ValueError, match="never runs unsandboxed"):
        H.Harness(base, OK, sandbox=())
    with pytest.raises(ValueError, match="never runs without a memory cap"):
        H.Harness(base, OK, memory_max=None)
    h = H.Harness(base, OK)
    assert (h.sandbox, h.memory_max) == (H.default_sandbox(), "2G")


def test_the_default_sandbox_is_bwrap_when_installed_else_unshare(monkeypatch):
    monkeypatch.setattr(H.shutil, "which", lambda name: "/usr/bin/bwrap")
    bw = H.default_sandbox()
    assert bw[:3] == ["bwrap", "--unshare-net", "--die-with-parent"]
    assert bw[3:6] == ["--ro-bind", "/", "/"]                                               # read-only root
    assert ["--tmpfs", "/tmp", "--tmpfs", "/run"] == bw[bw.index("--tmpfs"):bw.index("--tmpfs") + 4]
    assert bw[-6:] == ["--ro-bind", H.STAGE, H.STAGE, "--chdir", H.STAGE, "--"]              # stage read-only too
    monkeypatch.setattr(H.shutil, "which", lambda name: None)
    assert H.default_sandbox()[-4:] == H._LO_UP and "--net" in H.default_sandbox()


def test_the_scope_caps_memory_without_swap():
    argv = H.scope_argv("cora-verify-x", "512M")
    assert argv[:1] == ["systemd-run"] and "--scope" in argv and "--unit=cora-verify-x" in argv
    assert argv[argv.index("-p") + 1] == "MemoryMax=512M" and "MemorySwapMax=0" in argv and argv[-1] == "--"
    assert ("--user" in argv) == (os.geteuid() != 0)


@pytest.mark.skipif(runs(UNSHARE_USERNS), reason="unprivileged unshare works here; this checks the blocked path")
def test_when_the_sandbox_cannot_be_made_the_verifier_never_runs(base, tmp_path):
    marker = tmp_path / "verifier-ran"
    h = harness(base, [PY, "-c", f"open({str(marker)!r}, 'w')"], sandbox=UNSHARE_USERNS)
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert (r.code, r.state) == ("VERIFY_FAIL", "ROLLED_BACK") and "uid_map" in r.detail
    assert not marker.exists()
    assert_rolled_back_clean(base, before, h, t.id)


@pytest.mark.skipif(not (SANDBOX and SCOPE), reason=NO_SANDBOX + " / " + NO_SCOPE)
def test_the_real_sandbox_severs_egress_keeps_loopback_and_caps_memory(base):
    probe = textwrap.dedent("""
        import socket, sys
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        socket.create_connection(srv.getsockname(), timeout=2).close()          # loopback is up
        cg = open("/proc/self/cgroup").read().strip().split(":")[-1]
        if open(f"/sys/fs/cgroup{cg}/memory.max").read().strip() != str(256 << 20):
            sys.exit("not capped")
        try:
            socket.create_connection(("1.1.1.1", 443), timeout=2)
        except OSError:
            sys.exit(0)
        sys.exit("egress was open")
    """)
    h = H.Harness(base, [PY, "-c", probe], auto_commit=[ARENA], memory_max="256M")           # nothing relaxed
    r = h.submit(ticket(h))
    assert r.code == "COMMITTED", r


@pytest.mark.skipif(not (SANDBOX and SCOPE and H.shutil.which("bwrap")), reason="needs bwrap and the scope")
def test_under_bwrap_the_verifier_cannot_write_anywhere_that_matters_or_reach_the_session_bus(base):
    targets = [str(base / ".cascade" / "versions" / "v0" / "scenes" / "main.tscn"), "scenes/main.tscn"]
    probe = (f"import sys\nfor p in {targets!r}:\n    try:\n        open(p, 'a').write('x')\n"
             f"        sys.exit('wrote ' + p)\n    except OSError:\n        pass\nopen('/tmp/scratch', 'w')\n"
             f"import os\nif os.environ.get('DBUS_SESSION_BUS_ADDRESS') or os.path.exists('/run/user'):\n"
             f"    sys.exit('the session bus is reachable')")
    h = H.Harness(base, [PY, "-c", probe], auto_commit=[ARENA])
    before = live(base)
    r = h.submit(ticket(h))
    assert r.code == "COMMITTED", r                                          # private /tmp is fine
    assert H.digest(H.manifest(base / ".cascade" / "versions" / "v0")) == before[1]


@pytest.mark.skipif(not SCOPE, reason=NO_SCOPE)
def test_a_verifier_over_the_memory_cap_is_killed(base):
    h = harness(base, [PY, "-c", "b = bytearray(512 << 20); print('allocated')"], memory_max="64M")
    before = live(base)
    t = ticket(h)
    r = h.submit(t)
    assert r.code == "VERIFY_FAIL" and "killed" in r.detail and "allocated" not in r.detail
    assert_rolled_back_clean(base, before, h, t.id)


@pytest.mark.skipif(not SCOPE, reason=NO_SCOPE)
def test_the_timeout_kills_the_scope_even_processes_that_left_the_group(base, tmp_path):
    pidfile = tmp_path / "escaped.pid"
    script = (f"import subprocess, time; p = subprocess.Popen(['setsid', 'sleep', '60']); "
              f"open({str(pidfile)!r}, 'w').write(str(p.pid)); time.sleep(60)")
    h = harness(base, [PY, "-c", script], verify_timeout_s=1.0, memory_max="256M")
    r = h.submit(ticket(h))
    assert r.code == "VERIFY_TIMEOUT" and "scope" in r.detail
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail(f"pid {pid} left its process group and survived the timeout")
