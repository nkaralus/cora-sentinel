#!/usr/bin/env python3
"""
cora_nflog.py - connect-time attribution: an NFLOG tap on TCP SYNs, one rule per task cgroup.
Stdlib only: hand-packed NETLINK_NETFILTER, no libnetfilter_log, no eBPF.

    task process ──connect()──► SYN leaves via the OUTPUT hook
                                   │  nft: socket cgroupv2 level N "<task>"  tcp flags syn
                                   │       log prefix "cora-tap:<task>" group G
                                   ▼
                      kernel matches the SENDING SOCKET's cgroup and queues a message to us
                      (before the handshake can even complete, so before the socket can close)

Why this attributes what sock_diag could not: the cgroup is matched in-kernel at packet time, so
the owner is named by the rule itself. There is no race with the socket's lifetime, and a task
that connects and closes in microseconds is attributed exactly like a long-lived one.

What it does NOT give you (measured on Linux 6.18, not assumed):
  * No kernel timestamp: NFULA_TIMESTAMP is absent for locally generated packets, so the only
    time available is the userspace receipt time (Syn.recv_ns).
  * No pid: only the cgroup (and uid). In cgroup mode every action targets the task anyway.
  * A task's FIRST SYNs can precede its rule. cora_run.py installs the rule before exec, so tasks
    started with it have no gap; others are covered within one monitor poll.
  * TCP only. UDP/QUIC are not tapped.
  * Needs root (CAP_NET_ADMIN) and the nfnetlink_log module; a group can be bound by one process.

The tap chain runs at priority -10, BEFORE the egress-drop chain (priority 0), so an isolated
task's attempts are still logged.
"""
from __future__ import annotations

import errno
import json
import socket
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cora_firewall import Firewall, FirewallError

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET, NFULNL_MSG_CONFIG = 0, 1
NFULA_PACKET_HDR, NFULA_PAYLOAD, NFULA_PREFIX, NFULA_UID = 1, 9, 10, 11      # linux/netfilter/nfnetlink_log.h
NFULA_CFG_CMD, NFULA_CFG_MODE, NFULA_CFG_TIMEOUT, NFULA_CFG_QTHRESH = 1, 2, 4, 5
NFULNL_CFG_CMD_BIND, NFULNL_CFG_CMD_UNBIND = 1, 2
NFULNL_COPY_PACKET = 2
NLM_F_REQUEST, NLM_F_ACK, NLMSG_ERROR = 1, 4, 2
SO_RCVBUFFORCE = 33
PREFIX = "cora-tap:"
SNAPLEN = 128
DEFAULT_GROUP = 71
_HDR = struct.Struct("=IHHII")


@dataclass(frozen=True)
class Syn:
    task: str
    family: int
    src: str
    sport: int
    dst: str
    dport: int
    uid: Optional[int]
    recv_ns: int            # userspace receipt time: the kernel supplies none for local packets


def _attr(atype: int, payload: bytes) -> bytes:
    n = 4 + len(payload)
    return struct.pack("=HH", n, atype) + payload + b"\0" * ((4 - n % 4) % 4)


def _config(group: int, attrs: List[bytes], seq: int) -> bytes:
    body = struct.pack("=BB", 0, 0) + struct.pack("!H", group) + b"".join(attrs)   # nfgenmsg, res_id = group
    return _HDR.pack(16 + len(body), (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
                     NLM_F_REQUEST | NLM_F_ACK, seq, 0) + body


# ---------------------------------------------------------------------------
# packet parsing
# ---------------------------------------------------------------------------
def parse_ip_tcp_syn(pay: bytes) -> Tuple[int, str, int, str, int]:
    """IPv4/IPv6 + TCP header -> (family, src, sport, dst, dport). Raises ValueError unless a bare SYN."""
    try:
        ver = pay[0] >> 4
        if ver == 4:
            l4 = (pay[0] & 15) * 4
            if pay[9] != 6:
                raise ValueError("not TCP")
            fam, src, dst = socket.AF_INET, pay[12:16], pay[16:20]
        elif ver == 6:
            nh, l4 = pay[6], 40
            for _ in range(4):                       # skip a few extension headers
                if nh in (0, 43, 60):
                    nh, l4 = pay[l4], l4 + (pay[l4 + 1] + 1) * 8
                elif nh == 44:
                    nh, l4 = pay[l4], l4 + 8
                else:
                    break
            if nh != 6:
                raise ValueError("not TCP")
            fam, src, dst = socket.AF_INET6, pay[8:24], pay[24:40]
        else:
            raise ValueError("not IP")
        sport, dport = struct.unpack_from("!HH", pay, l4)
        flags = pay[l4 + 13]
    except (IndexError, struct.error):
        raise ValueError("truncated packet") from None
    if flags & 0x12 != 0x02:                          # SYN set, ACK clear
        raise ValueError("not a bare SYN")
    return fam, socket.inet_ntop(fam, src), sport, socket.inet_ntop(fam, dst), dport


def parse_packet_msg(body: bytes, recv_ns: int) -> Syn:
    """`body` = nfgenmsg (4 bytes) + attributes of one NFULNL_MSG_PACKET."""
    attrs: Dict[int, bytes] = {}
    q = 4
    while q + 4 <= len(body):
        alen, atype = struct.unpack_from("=HH", body, q)
        if alen < 4 or q + alen > len(body):
            break
        attrs[atype & 0x3FFF] = body[q + 4:q + alen]
        q += (alen + 3) & ~3
    prefix = attrs.get(NFULA_PREFIX, b"").split(b"\0", 1)[0].decode(errors="replace")
    if not prefix.startswith(PREFIX) or NFULA_PAYLOAD not in attrs:
        raise ValueError("not a cora tap message")
    fam, src, sport, dst, dport = parse_ip_tcp_syn(attrs[NFULA_PAYLOAD])
    uid = struct.unpack("!I", attrs[NFULA_UID])[0] if len(attrs.get(NFULA_UID, b"")) == 4 else None
    return Syn(prefix[len(PREFIX):], fam, src, sport, dst, dport, uid, recv_ns)


# ---------------------------------------------------------------------------
# the netlink side
# ---------------------------------------------------------------------------
class NflogListener:
    """Binds one NFLOG group and yields Syn events. Refuses loudly if it cannot bind."""

    def __init__(self, group: int = DEFAULT_GROUP, rcvbuf: int = 4 << 20):
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        s.bind((0, 0))
        s.settimeout(3)
        self.s, self.group, self.lost = s, group, 0
        self._buf = bytearray(1 << 16)
        s.send(_config(group, [
            _attr(NFULA_CFG_CMD, bytes([NFULNL_CFG_CMD_BIND])),
            _attr(NFULA_CFG_MODE, struct.pack("!IBB", SNAPLEN, NFULNL_COPY_PACKET, 0)),
            _attr(NFULA_CFG_QTHRESH, struct.pack("!I", 1)),      # deliver every packet immediately ...
            _attr(NFULA_CFG_TIMEOUT, struct.pack("!I", 1))],     # ... and flush within 10 ms regardless
            seq=1))
        code = self._ack()
        if code:
            s.close()
            why = {errno.EPERM: "needs CAP_NET_ADMIN, or the group is already bound by another process",
                   errno.ENOENT: "nfnetlink_log is not available (modprobe nfnetlink_log)",
                   errno.EOPNOTSUPP: "nfnetlink_log is not available (modprobe nfnetlink_log)"}.get(
                -code, "kernel refused the bind")
            raise OSError(-code, f"NFLOG group {group}: {why}")
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, rcvbuf)
        except OSError:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)

    def _ack(self) -> int:
        while True:
            data = self.s.recv(4096)
            _, typ, _, seq, _ = _HDR.unpack_from(data, 0)
            if typ == NLMSG_ERROR and seq == 1:
                return struct.unpack_from("=i", data, 16)[0]

    def poll(self, timeout: float) -> List[Syn]:
        self.s.settimeout(max(timeout, 0.0001))
        try:
            n = self.s.recv_into(self._buf)
        except socket.timeout:
            return []
        except OSError as e:
            if e.errno == errno.ENOBUFS:
                self.lost += 1                     # a gap of unknown size: counted, never hidden
                return []
            raise
        recv_ns = time.time_ns()
        data = bytes(self._buf[:n])
        out: List[Syn] = []
        off = 0
        while off + 16 <= n:
            ln, typ, _, _, _ = _HDR.unpack_from(data, off)
            if ln < 16 or off + ln > n:
                break
            if typ == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
                try:
                    out.append(parse_packet_msg(data[off + 16:off + ln], recv_ns))
                except ValueError:
                    pass
            off += (ln + 3) & ~3
        return out

    def close(self) -> None:
        try:
            self.s.send(_config(self.group, [_attr(NFULA_CFG_CMD, bytes([NFULNL_CFG_CMD_UNBIND]))], seq=2))
        except OSError:
            pass
        self.s.close()


# ---------------------------------------------------------------------------
# the nftables side: one tap rule per task cgroup
# ---------------------------------------------------------------------------
class TapRules:
    CHAIN = "tap"

    def __init__(self, fw: Firewall, group: int = DEFAULT_GROUP):
        self.fw, self.group = fw, group

    def active(self) -> bool:
        """True if a sentinel has set up the tap chain (used by cora_run to pre-install)."""
        rc, _, _ = self.fw._run(["list", "chain", "inet", self.fw.table, self.CHAIN], None)
        return rc == 0

    def ensure_chain(self) -> None:
        t = self.fw.table
        self.fw._script(f"add table inet {t}\n"
                        f"add chain inet {t} {self.CHAIN} "
                        "{ type filter hook output priority -10 ; policy accept ; }\n")

    def rule_text(self, name: str) -> str:
        level, path, cgid = self.fw.cgroup_match(name)
        return (f'socket cgroupv2 level {level} "{path}" tcp flags & (syn | ack) == syn '
                f'log prefix "{PREFIX}{name}" group {self.group} queue-threshold 1 snaplen {SNAPLEN} '
                f'counter comment "{PREFIX}{name}:{cgid}"')

    def rules(self) -> Dict[str, dict]:
        rc, out, _ = self.fw._run(["-j", "list", "chain", "inet", self.fw.table, self.CHAIN], None)
        if rc != 0:
            return {}
        found: Dict[str, dict] = {}
        for item in json.loads(out).get("nftables", []):
            r = item.get("rule")
            c = r.get("comment", "") if r else ""
            if c.startswith(PREFIX):
                name, _, cgid = c[len(PREFIX):].partition(":")
                cnt = next((e["counter"] for e in r["expr"] if "counter" in e), {})
                found[name] = {"handle": r["handle"], "packets": cnt.get("packets", 0),
                               "cgid": int(cgid) if cgid.isdigit() else None}
        return found

    def sync(self, live: Dict[str, int]) -> Tuple[List[str], List[str]]:
        """Make the rules match `live` ({task name: cgroup id}) in ONE atomic nft transaction."""
        have = self.rules()
        t, lines, added, removed = self.fw.table, [], [], []
        for name, cgid in live.items():
            r = have.get(name)
            if r and r["cgid"] == cgid:
                continue
            if r:                                   # same name, recreated cgroup: replace the stale rule
                lines.append(f"delete rule inet {t} {self.CHAIN} handle {r['handle']}")
            lines.append(f"add rule inet {t} {self.CHAIN} {self.rule_text(name)}")
            added.append(name)
        for name, r in have.items():
            if name not in live:
                lines.append(f"delete rule inet {t} {self.CHAIN} handle {r['handle']}")
                removed.append(name)
        if lines:
            self.fw._script("\n".join(lines) + "\n")
        return added, removed

    def install(self, name: str) -> bool:
        """Install one task's tap rule if missing or stale (used by cora_run, before exec)."""
        cgid = self.fw.cgroup_match(name)[2]
        r = self.rules().get(name)
        if r and r["cgid"] == cgid:
            return False
        self.ensure_chain()
        t = self.fw.table
        lines = [f"delete rule inet {t} {self.CHAIN} handle {r['handle']}"] if r else []
        lines.append(f"add rule inet {t} {self.CHAIN} {self.rule_text(name)}")
        self.fw._script("\n".join(lines) + "\n")
        return True

    def teardown(self) -> None:
        t = self.fw.table
        try:
            self.fw._script(f"flush chain inet {t} {self.CHAIN}\ndelete chain inet {t} {self.CHAIN}\n")
        except FirewallError:
            pass                                    # chain already gone


class TapService:
    """Listener + rules. The listener binds FIRST, so a refusal leaves the ruleset untouched."""

    def __init__(self, fw: Firewall, group: int = DEFAULT_GROUP):
        self.listener = NflogListener(group)
        self.rules = TapRules(fw, group)
        self.rules.ensure_chain()

    def sync(self, live: Dict[str, int]) -> Tuple[List[str], List[str]]:
        return self.rules.sync(live)

    def close(self) -> None:
        self.listener.close()
        self.rules.teardown()


def available(group: int = DEFAULT_GROUP) -> Tuple[bool, str]:
    try:
        NflogListener(group).close()
        return True, ""
    except OSError as e:
        return False, str(e)
