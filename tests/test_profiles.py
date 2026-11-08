"""Policy profiles: "agent" (deny-by-default, unchanged) and "app" (cora-run --app scopes: only blocklist hits).
Found live: a Minecraft session under the agent rules hit 72 path violations at load, was ISOLATEd, and ran at 3-4 FPS
with its egress dropped. Payloads are built by the daemon's own build_payload, as the tick, sockdiag and the NFLOG tap do."""
import os

import pytest

from cora_sentinel import daemon
from cora_sentinel.cgroup import CgroupRoot
from cora_sentinel.daemon import Sentinel, build_payload
from cora_sentinel.scope import ScopeError, Scopes

APP, AGENT = "minecraft-1fecb9", "build"
HIT = {"list": "community-trackers", "kind": "tracker_domain", "entry": "doubleclick.net"}


@pytest.fixture
def sentinel():
    out = []
    s = Sentinel("CORA_TASK", ["/tmp"], spike_mb=150, window_s=10.0, emit=out.append)
    s.profile_of = lambda name: "app" if name == APP else "agent"
    s.out = out
    return s


def fire(s, name, kind, evidence, key=None):
    p = build_payload(4242, "10.1.1.10", "java -jar x", kind, "high", evidence, 1, cgroup=name, cgroup_id=7)
    s._fire(key or (name, kind, repr(evidence)), 1000.0, p)
    return p


CONN = {"remote_ip": "203.0.113.9", "remote_port": 443, "local_port": 50000, "dest_class": "public"}


# ---------------------------------------------------------------- what an app scope does NOT raise

@pytest.mark.parametrize("kind,evidence", [
    ("path_violation", {"path": "/home/nick/.local/share/PrismLauncher/libraries/x.jar", "allowed_roots": ["/tmp"]}),
    ("path_violation", {"path": "/etc/shadow", "allowed_roots": ["/tmp"]}),
    ("memory_spike", {"grew_kb": 400000, "window_s": 10}),
    ("unauthorized_connection", CONN),                                          # Mojang auth, a multiplayer server
    ("unauthorized_connection", dict(CONN, proto="udp", l7="dns", qname="sessionserver.mojang.com")),
])
def test_an_app_scope_is_not_quarantined_for_being_a_desktop_program(sentinel, kind, evidence):
    fire(sentinel, APP, kind, evidence)
    assert sentinel.out == [] and sentinel.suppressed[kind] == 1


# ---------------------------------------------------------------- what an app scope STILL raises

@pytest.mark.parametrize("evidence", [dict(CONN, blocklist=HIT),
                                      dict(CONN, blocklist={"list": "rogue-subnets", "kind": "rogue_subnet",
                                                            "entry": "203.0.113.0/24"})])
def test_a_blocklist_hit_in_an_app_scope_is_still_raised(sentinel, evidence):
    p = fire(sentinel, APP, "unauthorized_connection", evidence)
    assert sentinel.out == [p]                                                  # contained at once downstream, as before


# ---------------------------------------------------------------- agent tasks: exactly as before

@pytest.mark.parametrize("kind,evidence", [
    ("path_violation", {"path": "/home/nick/x", "allowed_roots": ["/tmp"]}),
    ("memory_spike", {"grew_kb": 400000, "window_s": 10}),
    ("unauthorized_connection", CONN),
])
@pytest.mark.parametrize("name", [AGENT, None, "unknown-123456"])
def test_agent_tasks_and_unknown_cgroups_keep_every_rule(sentinel, kind, evidence, name):
    p = fire(sentinel, name, kind, evidence)
    assert sentinel.out == [p] and not sentinel.suppressed


def test_the_default_profile_is_agent():
    s = Sentinel("CORA_TASK", ["/tmp"], 150, 10.0, emit=lambda p: None)
    assert s.profile_of(APP) == "agent" and s.app_allows(APP, "path_violation", {}) is True


# ---------------------------------------------------------------- an app scope costs nothing per tick

def test_the_tick_does_not_even_read_an_app_scopes_files_or_memory(sentinel, monkeypatch):
    me = os.getpid()
    sentinel._targets = lambda: {me: "java"}
    sentinel._cg = {me: APP}
    monkeypatch.setattr(daemon, "read_open_paths", lambda pid: pytest.fail("path scan for an app scope"))
    monkeypatch.setattr(daemon, "read_rss_kb", lambda pid: pytest.fail("spike tracking for an app scope"))
    sentinel.netmon_active = True
    sentinel.tick(now=1000.0)
    assert sentinel.out == []


def test_the_tick_still_scans_an_agent_task(sentinel, monkeypatch):
    me = os.getpid()
    sentinel._targets = lambda: {me: "make"}
    sentinel._cg = {me: AGENT}
    monkeypatch.setattr(daemon, "read_open_paths", lambda pid: ["/home/nick/secret.txt"])
    sentinel.netmon_active = True
    sentinel.tick(now=1000.0)
    assert [p["anomaly"]["kind"] for p in sentinel.out] == ["path_violation"]


# ---------------------------------------------------------------- the registry decides, once

@pytest.fixture
def scopes(tmp_path):
    root = tmp_path / "cora"
    root.mkdir()
    return Scopes(CgroupRoot(str(root)), state_path=str(tmp_path / "scopes.json"))


def test_launch_scopes_are_app_and_everything_else_is_agent(scopes):
    name = scopes.create_scope("minecraft", uid=1000)
    assert scopes.profile(name) == "app" and scopes.describe(name)["profile"] == "app"
    assert scopes.profile("build") == "agent" and scopes.profile(None) == "agent"
    assert scopes.profile("minecraft-ffffff") == "agent"                         # looks like a scope, is not ours


def test_an_agent_profile_scope_is_possible_and_kept(scopes, tmp_path):
    name = scopes.create_scope("ci", uid=1000, profile="agent")
    assert Scopes(scopes.cg, state_path=str(tmp_path / "scopes.json")).profile(name) == "agent"


def test_an_unknown_profile_is_refused(scopes):
    with pytest.raises(ScopeError, match="unknown profile"):
        scopes.create_scope("x", uid=1000, profile="trusted")
    assert scopes.owned == {}


def test_a_registry_entry_from_before_profiles_is_an_app(scopes, tmp_path):
    name = scopes.create_scope("minecraft", uid=1000)
    del scopes.owned[name]["profile"]
    scopes._save()
    assert Scopes(scopes.cg, state_path=str(tmp_path / "scopes.json")).profile(name) == "app"


def test_the_daemon_wires_the_registry_into_the_detectors():
    src = open(daemon.__file__).read()
    assert "s.profile_of = scopes.profile" in src
