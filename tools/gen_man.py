#!/usr/bin/env python3
"""
gen_man - the man pages for the nine cora-sentinel commands, generated at build time.

    python tools/gen_man.py --out DIR [--date YYYY-MM-DD]       write DIR/<command>.1 for every command
    python tools/gen_man.py --list                              the commands

Nothing generated is checked in. For the tools that use argparse (cora-sentinel, cora-floor and its dyn-replay, cora-blocklist,
cora-report, cora-demo) the OPTIONS and COMMANDS sections are read from the real parsers, so an option cannot be added to the
code and forgotten here. The hand-parsed tools (cora-run, cora-cgroup, cora-firewall, cora-selfcheck) are written out below, and
tests/test_man.py checks that each subcommand in their usage text is in their page. Everything else (descriptions, files, signals,
exit status, examples) lives in PAGES.

packaging/build_deb.sh calls this and installs the gzipped pages under /usr/share/man/man1. Stdlib only.
"""
from __future__ import annotations

import argparse
import importlib
import re
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

URL = "https://github.com/nkaralus/cora-sentinel"
DOCS = "/usr/share/doc/cora-sentinel"


# --------------------------------------------------------------------------------------------------------------------
# what the pages say
# --------------------------------------------------------------------------------------------------------------------
PAGES = {
    "cora-sentinel": dict(
        summary="out-of-band security sentinel for Linux tasks",
        synopsis=["**cora-sentinel** [//OPTIONS//]"],
        parser=("cora_sentinel.daemon", "main"),
        description=[
            ("p", "**cora-sentinel** is an out-of-band security sentinel for Linux. It watches //tasks//: processes started with "
                  "**cora-run**(1), each in its own cgroup v2 under one delegated root (see **--cgroup-root**). It reports path "
                  "violations, memory spikes and unauthorized network connections as one JSON object per line, to the file named "
                  "by **--out**."),
            ("p", "Network detection has two sources. With **--nflog**, a connect-time tap in nftables NFLOG sees the first packet "
                  "of every TCP connection attempt and every UDP flow (including QUIC and DNS), attributes it to its task by "
                  "cgroup, and so catches connections that live for less than a polling interval. The sock_diag netlink interface "
                  "(or /proc/net/tcp, see **--net-source**) audits live sockets and socket destruction; a connection to a blocklisted "
                  "destination that closed before it could be attributed is reported as a //slip//."),
            ("p", "With **--model**, each event is adjudicated by a local, grammar-constrained language model. A verdict never acts "
                  "directly: it passes a vendored safety gate (the engine-telemetry-bus gates GI_1 to GI_3), and without the gate "
                  "the daemon refuses to act at all. Actions are per task: suspend, terminate or throttle through cgroup v2, and "
                  "isolate through a per-task nftables egress rule. Without **--enforce** actions are only logged (a dry run). A "
                  "verdict that needs a person is marked ESCALATE and never acts."),
            ("p", "**--floor** additionally installs a kernel-side blocklist floor (nftables sets) that drops listed addresses before "
                  "the first packet leaves or arrives. It is host-wide and outlives the daemon. **--floor-confirm** adds a "
                  "dead-man switch, and a pre-check refuses a floor that would drop the default gateway or a live SSH peer. "
                  "**--dyn-policy** can turn the model's ISOLATE verdicts into short-lived kernel drops of the destination; its "
                  "default, //shadow//, only records what it would do."),
            ("p", f"The design and the service setup are in {DOCS}/ (service.md, dyn-policy.md, packaging.md). The packaged systemd "
                  "unit reads its arguments from /etc/cora-sentinel/cora-sentinel.conf."),
        ],
        sections=[
            ("ENVIRONMENT", [
                ("tp", "**CORA_NFT_NATIVE**", "Set to 0 to read the nftables ruleset by running **nft -j list** instead of directly over netlink. The direct read is the default and is far faster when there are many tasks; the fallback is for debugging."),
            ]),
            ("SIGNALS", [
                ("tp", "**SIGHUP**", "Re-read the blocklist files and apply them (including the kernel floor sets) without a restart."),
                ("tp", "**SIGTERM**, **SIGINT**", "Stop. The kernel floor and any per-task isolation rules deliberately stay in place."),
            ]),
            ("FILES", [
                ("tp", "/etc/cora-sentinel/cora-sentinel.conf", "The packaged unit's arguments (CORA_ARGS). Not read by the daemon itself."),
                ("tp", "/usr/lib/systemd/system/cora-sentinel.service", "The packaged unit."),
                ("tp", "/var/log/cora-sentinel/events.jsonl", "Events, one JSON object per line (the packaged **--out**)."),
                ("tp", "/var/log/cora-sentinel/decisions.jsonl", "Adjudicator decisions (the packaged **--decisions**); created at the first verdict."),
                ("tp", "/var/lib/cora-sentinel/", "State: the confirmed floor allow set, the dynamic-policy ledgers, violation reports (**--state-dir**)."),
                ("tp", "/sys/fs/cgroup/cora/", "The default task cgroup root (**--cgroup-root**)."),
            ]),
            ("EXIT STATUS", [("p", "0 after a clean stop. 2 on a usage error: an unknown option, or an argument that looks like unexpanded shell "
                                   "syntax (a variable, a command substitution, a stray quote mark), which it names; the packaged unit does not "
                                   "restart on 2. 1 if it could not start for another reason: a floor refused by the pre-check or that nft "
                                   "cannot install, an unusable option combination, or a damaged install.")]),
            ("EXAMPLES", [
                ("p", "Watch tasks, with the connect-time tap, without acting:"),
                ("code", "cora-sentinel --cgroup-root /sys/fs/cgroup/cora --nft --nflog --out events.jsonl"),
                ("p", "With the model, the kernel floor (confirm it within 120 seconds), your blocklists, and decisions logged:"),
                ("code", "cora-sentinel --cgroup-root /sys/fs/cgroup/cora --nft --nflog --floor --floor-confirm 120 \\\n"
                         "    --model model.gguf --blocklist /etc/cora-sentinel/blocklists \\\n"
                         "    --out events.jsonl --decisions decisions.jsonl"),
            ]),
        ],
        see_also=["cora-run(1)", "cora-floor(1)", "cora-firewall(1)", "cora-cgroup(1)", "cora-blocklist(1)", "cora-selfcheck(1)"],
    ),

    "cora-run": dict(
        summary="run a command as a cora-sentinel task",
        synopsis=["**cora-run** //NAME// //CMD// [//ARGS//...]"],
        description=[
            ("p", "**cora-run** runs //CMD// as a task named //NAME//. It creates the cgroup //root///NAME//, moves itself into it, "
                  "and then replaces itself with //CMD//, so the task and everything it forks are in that cgroup from their first "
                  "instruction: there is no race and no marker argument. The default root is /sys/fs/cgroup/cora."),
            ("p", "If a sentinel is running the connect-time tap, **cora-run** installs the task's tap rule before the move, so the "
                  "task's very first connection is already attributed. This is best effort: if it cannot, the task starts anyway and "
                  "the sentinel installs the rule within one polling interval."),
            ("p", "Moving into a cgroup needs root. If it was started through sudo, **cora-run** drops back to the invoking user "
                  "(SUDO_UID and SUDO_GID) before executing //CMD//, so the task does not keep root."),
        ],
        sections=[
            ("ENVIRONMENT", [
                ("tp", "**CORA_CGROUP_ROOT**", "The task cgroup root. Default /sys/fs/cgroup/cora."),
                ("tp", "**CORA_CGROUP_MOUNT**", "Where cgroup v2 is mounted. Default /sys/fs/cgroup."),
                ("tp", "**CORA_NFT_TABLE**", "The nftables table the tap uses. Default cora."),
                ("tp", "**CORA_NFLOG_GROUP**", "The NFLOG group of the tap. Must match the sentinel's."),
            ]),
            ("EXIT STATUS", [("p", "2 if //NAME// or //CMD// is missing (it prints its usage). 1 if it cannot enter the cgroup. "
                                   "3 if //NAME//'s cgroup is left over from an earlier run and still carries containment "
                                   "(an nft drop rule, a freeze, or THROTTLE limits): a relaunch would inherit it, so it refuses "
                                   "and names the root-only undo (**cora-firewall release**, **cora-cgroup thaw** or "
                                   "**cora-cgroup reset**). Otherwise it does not return: the exit status is //CMD//'s.")]),
            ("EXAMPLES", [("code", "sudo cora-run build python3 build.py\nsudo cora-run fetch curl -s https://example.org/")]),
        ],
        see_also=["cora-sentinel(1)", "cora-cgroup(1)", "cora-firewall(1)"],
    ),

    "cora-cgroup": dict(
        summary="inspect, thaw and un-throttle cora-sentinel task cgroups",
        synopsis=["**cora-cgroup** **list**", "**cora-cgroup** **status** //NAME//", "**cora-cgroup** **thaw** //NAME//",
                  "**cora-cgroup** **reset** //NAME//"],
        description=[
            ("p", "A task is a directory under one delegated cgroup v2 root. A sentinel contains a task through that directory: "
                  "suspend (cgroup.freeze), terminate (cgroup.kill, kernel 5.14 or later) and throttle (cpu.max and memory.high, "
                  "falling back to nice). **cora-cgroup** is the small tool for looking at those tasks and for undoing a suspend."),
        ],
        commands=[
            ("**list**", "Print every task with its process count, whether it is frozen, and whether a freeze was requested."),
            ("**status** //NAME//", "Print one task's process count and whether it is frozen."),
            ("**thaw** //NAME//", "Unfreeze a suspended task."),
            ("**reset** //NAME//", "Undo THROTTLE: cpu.max and memory.high back to max. The only way back from cora-tray's "
                                   "Cap memory breaker, which the tray itself cannot undo."),
        ],
        sections=[
            ("ENVIRONMENT", [
                ("tp", "**CORA_CGROUP_ROOT**", "The task cgroup root. Default /sys/fs/cgroup/cora."),
                ("tp", "**CORA_CGROUP_MOUNT**", "Where cgroup v2 is mounted. Default /sys/fs/cgroup."),
            ]),
            ("EXIT STATUS", [("p", "0 on success. 2 on a usage error (it prints its usage).")]),
            ("EXAMPLES", [("code", "cora-cgroup list\nsudo cora-cgroup thaw build")]),
        ],
        see_also=["cora-run(1)", "cora-firewall(1)", "cora-sentinel(1)"],
    ),

    "cora-firewall": dict(
        summary="per-task egress quarantine with nftables",
        synopsis=["**cora-firewall** **list**", "**cora-firewall** **block** //NAME//", "**cora-firewall** **unblock** //NAME//",
                  "**cora-firewall** **release** //NAME//", "**cora-firewall** **gc**", "**cora-firewall** **purge**"],
        description=[
            ("p", "**cora-firewall** manages the per-task egress rules of a sentinel. The rules live in their own nftables table, "
                  "//inet cora//; the tool never touches any other table, so removing that table removes every rule cora-sentinel "
                  "ever added and nothing else. There is one rule per task, matched on the socket's cgroup v2 and tagged "
                  "\"cora:NAME\"; it drops everything leaving a non-loopback interface. The kernel is the source of truth: there is "
                  "no state file, and a restarted daemon reads the ruleset back. It needs CAP_NET_ADMIN (run it as root)."),
        ],
        commands=[
            ("**list**", "Show each isolated task with the packets and bytes its rule has dropped."),
            ("**block** //NAME//", "Isolate a task: cut its egress."),
            ("**unblock** //NAME//", "Remove a task's egress rule."),
            ("**release** //NAME//", "The review action: undo every containment measure on a task (its egress rule, a freeze, "
                                    "its limits) and drop the dynamic kernel entries that task alone caused. Use it for a false positive."),
            ("**gc**", "Remove rules whose cgroup no longer exists."),
            ("**purge**", "Delete the whole table: every per-task rule and the tap, at once. The panic button. It also removes "
                          "the kernel floor if it is in the same table."),
        ],
        sections=[
            ("ENVIRONMENT", [
                ("tp", "**CORA_CGROUP_ROOT**, **CORA_CGROUP_MOUNT**", "As for cora-cgroup(1)."),
                ("tp", "**CORA_NFT_TABLE**", "The table name. Default cora."),
                ("tp", "**CORA_STATE_DIR**", "Where **release** finds the dynamic-policy ledgers. Default /var/lib/cora-sentinel."),
                ("tp", "**CORA_NFT_NATIVE**", "Set to 0 to read the nftables ruleset by running **nft -j list** instead of directly over netlink. The direct read is the default and is far faster when there are many tasks; the fallback is for debugging."),
            ]),
            ("EXIT STATUS", [("p", "0 on success. 1 on an error from nftables or the cgroup (it prints it). 2 on a usage error.")]),
            ("EXAMPLES", [("code", "sudo cora-firewall list\nsudo cora-firewall release build")]),
        ],
        see_also=["cora-floor(1)", "cora-cgroup(1)", "cora-sentinel(1)"],
    ),

    "cora-floor": dict(
        summary="inspect and drive the kernel-side blocklist floor and the dynamic policy",
        synopsis=["**cora-floor** [**--table** //TABLE//] [**--state-dir** //DIR//] //COMMAND// [//ARGS//]",
                  "**cora-floor** **dyn-replay** //DECISIONS//... [//OPTIONS//]"],
        parser=("cora_sentinel.nftsets", "main"),
        extra_parsers=[("DYN-REPLAY OPTIONS", lambda: importlib.import_module("cora_sentinel.dynreplay").build_parser())],
        description=[
            ("p", "The kernel floor is a set of nftables sets that drop listed addresses before the first packet leaves or arrives "
                  "(**cora-sentinel --floor**). **cora-floor** shows and drives it: the sets, the dead-man confirmation, one-off "
                  "blocks, the dynamic-policy ledger, and a replay tool that rehearses the policy against recorded logs."),
            ("p", "The floor is host-wide and it outlives the daemon: stopping cora-sentinel does not remove it. "
                  "**cora-floor remove** does."),
            ("p", "//dyn-replay// has its own option parser: **cora-floor dyn-replay --help**. It joins decisions.jsonl with "
                  "events.jsonl (a decision has the verdict and the time but not the destination or the task), feeds each recorded "
                  "ISOLATE back through the real policy with a clock that follows the recorded times, and reports what would have "
                  "been blocked, which limits were hit, and whether any web port was promoted. It never touches the live ledger or "
                  "the live ruleset. In kernel mode (root, nft and unshare available) it mirrors every write into a private network "
                  "namespace."),
        ],
        sections=[
            ("ENVIRONMENT", [
                ("tp", "**CORA_NFT_TABLE**", "The table name (**--table**). Default cora."),
                ("tp", "**CORA_STATE_DIR**", "The state directory (**--state-dir**). Default /var/lib/cora-sentinel."),
            ]),
            ("FILES", [
                ("tp", "/var/lib/cora-sentinel/floor.pending.json", "A floor waiting for **confirm** (written by **cora-sentinel --floor-confirm**)."),
                ("tp", "/var/lib/cora-sentinel/floor.confirmed.json", "The allow set a person confirmed; an unchanged set asks for no new confirmation."),
                ("tp", "/var/lib/cora-sentinel/dyn-ledger-shadow.json, dyn-ledger-enforce.json", "The dynamic policy's ledgers, one per mode."),
            ]),
            ("EXIT STATUS", [("p", "0 on success. 1 on an error, or when **confirm** finds nothing waiting. For **dyn-replay**: 1 if **--check** "
                                   "found a mismatch with what the live policy recorded, 2 if a self-check failed (a web port promoted, or "
                                   "the simulated sets disagree with the ledger) or the input was unusable.")]),
            ("EXAMPLES", [
                ("p", "Keep a floor the daemon is waiting on, then look at the sets:"),
                ("code", "sudo cora-floor confirm\nsudo cora-floor status"),
                ("p", "Block one address for ten minutes, by hand:"),
                ("code", "sudo cora-floor block 203.0.113.9 600"),
                ("p", "Rehearse a tweak against a week of shadow-mode logs:"),
                ("code", "cora-floor dyn-replay /var/log/cora-sentinel/decisions.jsonl --events /var/log/cora-sentinel/events.jsonl --task-cap 4"),
            ]),
        ],
        see_also=["cora-sentinel(1)", "cora-firewall(1)", "cora-blocklist(1)"],
    ),

    "cora-blocklist": dict(
        summary="pinned, reviewed blocklist updates, and a blocklist checker",
        synopsis=["**cora-blocklist** **check** //PATH// [//IP-OR-DOMAIN//...]",
                  "**cora-blocklist** [**--dir** //DIR//] //COMMAND// [//ARGS//]"],
        parser=("cora_sentinel.blocklist_store", "main"),
        description=[
            ("p", "**cora-blocklist** keeps the blocklists a sentinel loads under review. **pull** fetches every source and stages what "
                  "changed without touching the active lists; you read the **diff**, and **accept** pins the update by the first "
                  "12 hex digits of its sha256, which you must retype. **verify** checks every active list against its pin. "
                  "Apply an accepted update with SIGHUP to the daemon."),
            ("p", "**check** is separate: it loads a blocklist file or directory, prints a summary, and tells you whether each "
                  "address or domain you name matches."),
        ],
        sections=[
            ("ENVIRONMENT", [("tp", "**CORA_BLOCKLIST_DIR**", "The store directory. Default /var/lib/cora-sentinel/blocklists as root, "
                                                                "otherwise ~/.local/share/cora-sentinel/blocklists.")]),
            ("EXIT STATUS", [("p", "0 on success. 1 on an error or a failed **verify**. 10 when **pull** staged changes that wait for review. "
                                   "2 on a usage error.")]),
            ("EXAMPLES", [("code", "cora-blocklist check /etc/cora-sentinel/blocklists 203.0.113.9 ads.example.com\n"
                                   "cora-blocklist pull\ncora-blocklist diff\ncora-blocklist accept rogue-subnets --sha256 0123456789ab")]),
        ],
        see_also=["cora-sentinel(1)", "cora-floor(1)"],
    ),

    "cora-report": dict(
        summary="anonymized violation report tooling",
        synopsis=["**cora-report** **--write-schema** //PATH//"],
        parser=("cora_sentinel.report", "main"),
        description=[
            ("p", "The sentinel can write anonymized violation reports in the schema //cora.security.violation/v1//. "
                  "**cora-report** writes that JSON Schema to a file, so a report can be validated. With no option it prints "
                  "its help and exits with status 2."),
        ],
        sections=[("EXIT STATUS", [("p", "0 after writing the schema. 2 with no option.")]),
                  ("FILES", [("tp", f"{DOCS}/violation-reports.md", "What a report holds and what it leaves out.")])],
        see_also=["cora-sentinel(1)"],
    ),

    "cora-demo": dict(
        summary="live demonstration of the whole cora-sentinel chain",
        synopsis=["**cora-demo** [//OPTIONS//]"],
        parser=("cora_sentinel.demo", "main"),
        description=[
            ("p", "**cora-demo** runs the whole chain once on this machine: it starts a task that contacts a blocklisted destination "
                  "(an offline stand-in unless **--domain** is given), the sentinel detects it, the model judges it, and the resulting "
                  "action is carried out unless **--dry-run** is given. It checks the machine first and stops with FAIL lines for "
                  "what is missing. It needs root, cgroup v2, nftables, a real network address and a model."),
        ],
        sections=[("EXIT STATUS", [("p", "2 if the machine cannot run it (the FAIL lines say why).")]),
                  ("EXAMPLES", [("code", "sudo cora-demo --model model.gguf --dry-run\nsudo cora-demo --model model.gguf --ephemeral")])],
        see_also=["cora-sentinel(1)", "cora-selfcheck(1)"],
    ),

    "cora-selfcheck": dict(
        summary="can this machine run the sentinel, and is the install complete?",
        synopsis=["**cora-selfcheck**"],
        description=[
            ("p", "**cora-selfcheck** reports what this machine and this install can do. Its //required// section covers the Python "
                  "version, the vendored safety gate (verified byte for byte against its VENDOR.lock, and reported as modified if "
                  "it is not) and the modules' own probes. The rest lists the machine's capabilities: root, cgroup v2, nftables, "
                  "NFLOG, sock_diag. Each missing one says what it costs you, because most are optional: without nftables you lose "
                  "isolation, without NFLOG the connect-time tap, without root all of it."),
        ],
        sections=[("EXIT STATUS", [("p", "0 only if everything required is present. A missing machine capability is reported but is not a "
                                         "failure. 1 if a required item is missing, including a modified vendored gate.")])],
        see_also=["cora-sentinel(1)", "cora-demo(1)"],
    ),
}

ORDER = ["cora-sentinel", "cora-run", "cora-cgroup", "cora-firewall", "cora-floor", "cora-blocklist", "cora-report", "cora-demo",
         "cora-selfcheck"]


# --------------------------------------------------------------------------------------------------------------------
# roff
# --------------------------------------------------------------------------------------------------------------------
ASCII = {"\u2192": "->", "\u2013": "-", "\u2014": " - ", "\u2265": ">=", "\u2264": "<=", "\u2026": "...", "\u201c": '"', "\u201d": '"',
         "\u2018": "'", "\u2019": "'", "\u00d7": "x", "\u00b7": "."}


def esc(s: str) -> str:
    """roff-safe text: backslash and hyphen escaped, anything outside ASCII as a \\[uXXXX] glyph."""
    for k, v in ASCII.items():
        s = s.replace(k, v)
    out = []
    for c in s:
        out.append("\\e" if c == "\\" else "\\-" if c == "-" else c if ord(c) < 128 else f"\\[u{ord(c):04X}]")
    return "".join(out)


def inline(s: str) -> str:
    """**bold** and //italic// markers, on text that is already escaped."""
    s = re.sub(r"\*\*(.+?)\*\*", lambda m: "\\fB" + m.group(1) + "\\fR", s)
    return re.sub(r"//(.+?)//", lambda m: "\\fI" + m.group(1) + "\\fR", s)


def text(s: str) -> str:
    return inline(esc(s))


def guard(line: str) -> str:
    return "\\&" + line if line[:1] in (".", "'") else line


def para(s: str) -> List[str]:
    return [".PP"] + [guard(l) for l in text(s).splitlines()]


def code(s: str) -> List[str]:
    return [".PP", ".nf", ".RS 4"] + [guard(esc(l)) for l in s.splitlines()] + [".RE", ".fi"]


def tagged(label: str, body: str) -> List[str]:
    return [".TP", text(label)] + [guard(l) for l in text(body).splitlines()]


def blocks(items) -> List[str]:
    out: List[str] = []
    for it in items:
        if it[0] == "p":
            out += para(it[1])
        elif it[0] == "code":
            out += code(it[1])
        elif it[0] == "tp":
            out += tagged(it[1], it[2])
    return out


# --------------------------------------------------------------------------------------------------------------------
# argparse introspection
# --------------------------------------------------------------------------------------------------------------------
class _Captured(Exception):
    pass


def capture(module: str, func: str, prog: str) -> argparse.ArgumentParser:
    """Run module.func() until it first calls ArgumentParser.parse_args, and hand back that parser."""
    held: dict = {}
    real = argparse.ArgumentParser.parse_args

    def fake(self, args=None, namespace=None):
        held["parser"] = self
        raise _Captured()
    argparse.ArgumentParser.parse_args = fake
    old = sys.argv
    sys.argv = [prog]
    try:
        getattr(importlib.import_module(module), func)()
    except _Captured:
        pass
    finally:
        argparse.ArgumentParser.parse_args = real
        sys.argv = old
    if "parser" not in held:
        raise RuntimeError(f"{module}.{func} never built an argparse parser")
    return held["parser"]


def _label(act: argparse.Action) -> str:
    mv = act.metavar or act.dest
    mv = " ".join(mv) if isinstance(mv, tuple) else str(mv)
    if not act.option_strings:                                  # a positional argument
        return f"//{mv.upper()}//"
    flags = ", ".join(f"**{o}**" for o in act.option_strings)
    if act.nargs == 0:
        return flags
    val = "{" + "|".join(map(str, act.choices)) + "}" if act.choices else (act.metavar and mv or act.dest.upper())
    return f"{flags} //{val}//"


def _help(parser: argparse.ArgumentParser, act: argparse.Action) -> str:
    h = parser._get_formatter()._expand_help(act)          # fills %(default)s and friends, as --help does
    return re.sub(r"\s+", " ", h).strip()


def option_blocks(parser: argparse.ArgumentParser) -> List[str]:
    out: List[str] = []
    for act in parser._actions:
        if act.help == argparse.SUPPRESS or isinstance(act, (argparse._HelpAction, argparse._SubParsersAction)):
            continue
        if not act.option_strings and not act.help:
            continue
        out += tagged(_label(act), _help(parser, act) if act.help else "")
    return out


def command_blocks(parser: argparse.ArgumentParser) -> List[str]:
    out: List[str] = []
    for act in parser._actions:
        if not isinstance(act, argparse._SubParsersAction):
            continue
        shown = {a.dest: a for a in act._choices_actions if a.help != argparse.SUPPRESS}
        for name, sp in act.choices.items():
            if name not in shown:
                continue
            args = " ".join(_label(a) for a in sp._actions if not isinstance(a, argparse._HelpAction) and a.help != argparse.SUPPRESS)
            out += tagged(f"**{name}**" + (f" {args}" if args else ""), re.sub(r"\s+", " ", shown[name].help or "").strip())
    return out


# --------------------------------------------------------------------------------------------------------------------
# a page
# --------------------------------------------------------------------------------------------------------------------
def render(name: str, version: str, date: str) -> str:
    spec = PAGES[name]
    L: List[str] = [f'.TH {name.upper().replace("-", chr(92) + "-")} 1 "{date}" "cora-sentinel {version}" "cora-sentinel manual"', ".nh",
                    ".SH NAME", f"{esc(name)} \\- {esc(spec['summary'])}", ".SH SYNOPSIS"]
    for i, s in enumerate(spec["synopsis"]):
        L += ([".br"] if i else []) + [text(s)]
    L += [".SH DESCRIPTION"] + blocks(spec["description"])
    parser = None
    if "parser" in spec:
        parser = capture(*spec["parser"], prog=name)
        opts = option_blocks(parser)
        if opts:
            L += [".SH OPTIONS"] + opts
        cmds = command_blocks(parser)
        if cmds:
            L += [".SH COMMANDS"] + cmds
    if "commands" in spec:
        L += [".SH COMMANDS"]
        for label, body in spec["commands"]:
            L += tagged(label, body)
    for title, make in spec.get("extra_parsers", []):
        L += [f".SH {title}"] + option_blocks(make())
    for title, items in spec.get("sections", []):
        L += [f".SH {title}"] + blocks(items)
    L += [".SH SEE ALSO", ", ".join(f"\\fB{esc(r.split('(')[0])}\\fR({r.split('(')[1][:-1]})" for r in spec["see_also"]) + ".",
          ".SH REPORTING BUGS", f"{esc(URL)}/issues"]
    return "\n".join(L) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, help="write DIR/<command>.1 for every command")
    ap.add_argument("--date", default="", help="the date in the page footer (default: none, so the output is reproducible)")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)
    if a.list:
        print("\n".join(ORDER))
        return 0
    if not a.out:
        ap.error("--out DIR is required (or --list)")
    from cora_sentinel import __version__
    a.out.mkdir(parents=True, exist_ok=True)
    for name in ORDER:
        (a.out / f"{name}.1").write_text(render(name, __version__, a.date))
    print(f"wrote {len(ORDER)} pages to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
