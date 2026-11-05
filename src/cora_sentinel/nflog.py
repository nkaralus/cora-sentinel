#!/usr/bin/env python3
"""
cora_sentinel.nflog - connect-time attribution: an NFLOG tap on the FIRST packet of every flow a task
starts (TCP SYN, and UDP incl. QUIC/HTTP3 and DNS), one rule set per task cgroup.
Stdlib only: hand-packed NETLINK_NETFILTER, no libnetfilter_log, no eBPF.

    task process ──connect()/sendto()──► first packet leaves via the OUTPUT hook
                                   │  nft: socket cgroupv2 level N "<task>"  + a once-per-flow gate
                                   │       log prefix "cora-tap:<task>" group G
                                   ▼
                      the kernel matches the SENDING SOCKET's cgroup and queues a message to us,
                      before the flow can complete or the socket can close

TCP: a bare SYN (`tcp flags & (syn|ack) == syn`).
UDP: there is no SYN, and conntrack's `ct state new` is NOT "first packet": it stays true for every
     packet until a reply is seen, so a one-way UDP stream would be logged packet by packet (a flood
     vector). So the once-per-flow gate is a dynamic nft set keyed on (the sending TASK's cgroup,
     daddr, dport, sport) with a timeout: the first packet is logged, later packets only refresh the
     timer. Measured: 23,005 UDP packets (one a 20,000-packet one-way flood) produced exactly 4
     events. No conntrack needed. A flow idle longer than the timeout (default 30 s) is a new flow.
     The task is part of the key on purpose: the kernel picks UDP source ports at random from about
     28,000, so two flows to one destination share a source port by birthday odds. Without the task
     in the key, one task's flow swallowed another task's (measured: about 2% of later tasks' flows
     lost across 1,800 flows). Within ONE task, the same destination from the same source port inside
     the timeout is the same flow, and the per-task cooldown would collapse it anyway.

What the payload gives us beyond the address:
  * DNS (udp/53): the query NAME, in clear text, attributed to the task even via a local resolver
    stub. Blocklist domains can then be matched by name instead of by resolved address.
  * QUIC (udp/443): a long-header packet with a known QUIC version is labelled "quic". The hostname
    is NOT recoverable: that needs AES to unprotect the Initial packet (not in the stdlib), possibly
    two packets (post-quantum key shares), and Encrypted Client Hello hides it anyway.

Not covered (measured or stated, not assumed):
  * Encrypted DNS (DoH/DoT/DoQ) hides names. Only plain DNS is parsed.
  * No kernel timestamp for locally generated packets: only userspace receipt time (Syn.recv_ns).
  * No pid: only the cgroup (and uid). In cgroup mode every action targets the task anyway.
  * A task's FIRST packets can precede its rules. cora-run installs them before exec; otherwise
    the monitor installs them within one poll.
  * No UDP "dump": a UDP flow that began before the tap existed is invisible until it goes idle.
  * The set holds 65,536 flows per family; if it fills, new flows are not logged (a bound, not a hang).
  * Needs root (CAP_NET_ADMIN) and the nfnetlink_log module; one process may bind a group.

The tap chain runs at priority -10, BEFORE the egress-drop chain (priority 0), so an isolated
task's attempts are still logged. Re-adding a set whose timeout differs succeeds silently and keeps
the old timeout; clean shutdown deletes the sets, so this only matters after a crash.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import re
import socket
import struct
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cora_sentinel.firewall import Firewall, FirewallError

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET, NFULNL_MSG_CONFIG = 0, 1
NFULA_PACKET_HDR, NFULA_PAYLOAD, NFULA_PREFIX, NFULA_UID = 1, 9, 10, 11      # linux/netfilter/nfnetlink_log.h
NFULA_CFG_CMD, NFULA_CFG_MODE, NFULA_CFG_TIMEOUT, NFULA_CFG_QTHRESH = 1, 2, 4, 5
NFULNL_CFG_CMD_BIND, NFULNL_CFG_CMD_UNBIND = 1, 2
NFULNL_COPY_PACKET = 2
NLM_F_REQUEST, NLM_F_ACK, NLMSG_ERROR = 1, 4, 2
SO_RCVBUFFORCE = 33
DEFAULT_LOCK_TIMEOUT_S = 30.0          # the sentinel's sync worker: it is the only installer, so it can afford to wait
PREINSTALL_LOCK_TIMEOUT_S = 5.0        # cora-run: must not hold up starting a task; the sentinel installs the rule anyway
PREFIX = "cora-tap:"
SNAPLEN_TCP = 128          # IP + TCP headers
SNAPLEN_UDP = 320          # IP + UDP + a DNS header and a full question name
COPY_RANGE = SNAPLEN_UDP   # the instance ceiling: a rule's snaplen can only shrink it
DEFAULT_GROUP = 71
_HDR = struct.Struct("=IHHII")
QUIC_VERSIONS = {0x00000001, 0x6B3343CF}   # v1 (RFC 9000), v2 (RFC 9369); IETF drafts are 0xff0000NN


@dataclass(frozen=True)
class Syn:
    """The first packet of a flow. (The name is historical: it is a SYN for TCP.)"""
    task: str
    family: int
    src: str
    sport: int
    dst: str
    dport: int
    uid: Optional[int]
    recv_ns: int                # userspace receipt time: the kernel supplies none for local packets
    proto: str = "tcp"
    l7: Optional[str] = None    # "dns" | "quic" | None
    qname: Optional[str] = None  # DNS query name, lowercased
    seq: Optional[int] = None    # TCP initial sequence number: shared by a SYN, its retransmits and any
                                 # duplicate message, but different for every new connection


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
def _ip_header(pay: bytes) -> Tuple[int, bytes, bytes, int, int]:
    """-> (family, src, dst, l4 protocol number, l4 offset). IndexError means truncated."""
    ver = pay[0] >> 4
    if ver == 4:
        if struct.unpack_from("!H", pay, 6)[0] & 0x1FFF:
            raise ValueError("non-first fragment")          # no L4 header here
        return socket.AF_INET, pay[12:16], pay[16:20], pay[9], (pay[0] & 15) * 4
    if ver == 6:
        nh, l4 = pay[6], 40
        for _ in range(4):                                  # skip a few extension headers
            if nh in (0, 43, 60):
                nh, l4 = pay[l4], l4 + (pay[l4 + 1] + 1) * 8
            elif nh == 44:
                raise ValueError("fragmented")
            else:
                break
        return socket.AF_INET6, pay[8:24], pay[24:40], nh, l4
    raise ValueError("not IP")


def parse_ip_tcp_syn(pay: bytes) -> Tuple[int, str, int, str, int]:
    """IPv4/IPv6 + TCP header -> (family, src, sport, dst, dport). Raises ValueError unless a bare SYN."""
    try:
        fam, src, dst, proto, l4 = _ip_header(pay)
        if proto != 6:
            raise ValueError("not TCP")
        sport, dport = struct.unpack_from("!HH", pay, l4)
        flags = pay[l4 + 13]
    except (IndexError, struct.error):
        raise ValueError("truncated packet") from None
    if flags & 0x12 != 0x02:                                # SYN set, ACK clear
        raise ValueError("not a bare SYN")
    return fam, socket.inet_ntop(fam, src), sport, socket.inet_ntop(fam, dst), dport


def parse_dns_query(p: bytes) -> str:
    """The first question's name of a standard DNS query, lowercased. Raises ValueError otherwise."""
    if len(p) < 17:
        raise ValueError("short")
    flags, qd = struct.unpack_from("!H", p, 2)[0], struct.unpack_from("!H", p, 4)[0]
    if flags & 0x8000 or (flags >> 11) & 0xF or qd < 1:     # a response, a non-QUERY opcode, or no question
        raise ValueError("not a standard query")
    i, labels, total = 12, [], 0
    while True:
        if i >= len(p):
            raise ValueError("truncated name")
        n = p[i]
        if n == 0:
            break
        if n & 0xC0:                                        # compression pointers do not occur in a question
            raise ValueError("compressed or extended label")
        if i + 1 + n > len(p):
            raise ValueError("truncated label")
        labels.append(p[i + 1:i + 1 + n].decode("ascii"))   # non-ASCII (UnicodeDecodeError is a ValueError)
        total += n + 1
        if total > 253:
            raise ValueError("name too long")
        i += 1 + n
    if not labels:
        raise ValueError("root query")
    return ".".join(labels).lower()


def classify_udp(dport: int, payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """-> (l7 label, dns query name). QUIC needs port 443, the long-header bits and a known version."""
    if dport == 53:
        try:
            return "dns", parse_dns_query(payload)
        except ValueError:
            return None, None
    if dport == 443 and len(payload) >= 5 and payload[0] & 0xC0 == 0xC0:
        ver = struct.unpack_from("!I", payload, 1)[0]
        if ver in QUIC_VERSIONS or (ver >> 8) == 0xFF0000:
            return "quic", None
    return None, None


def parse_ip_flow(pay: bytes) -> Tuple[str, int, str, int, str, int, bytes]:
    """-> (proto, family, src, sport, dst, dport, udp payload). A TCP packet must be a bare SYN."""
    try:
        fam, src, dst, proto, l4 = _ip_header(pay)
        if proto == 6:
            f, s, sp, d, dp = parse_ip_tcp_syn(pay)
            return "tcp", f, s, sp, d, dp, b""
        if proto == 17:
            sport, dport = struct.unpack_from("!HH", pay, l4)
            if len(pay) < l4 + 8:
                raise ValueError("truncated UDP header")
            return ("udp", fam, socket.inet_ntop(fam, src), sport, socket.inet_ntop(fam, dst), dport,
                    bytes(pay[l4 + 8:]))
    except (IndexError, struct.error):
        raise ValueError("truncated packet") from None
    raise ValueError("not TCP/UDP")


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
    proto, fam, src, sport, dst, dport, data = parse_ip_flow(attrs[NFULA_PAYLOAD])
    uid = struct.unpack("!I", attrs[NFULA_UID])[0] if len(attrs.get(NFULA_UID, b"")) == 4 else None
    task = prefix[len(PREFIX):]
    if proto == "tcp":
        payload = attrs[NFULA_PAYLOAD]
        seq = struct.unpack_from("!I", payload, _ip_header(payload)[4] + 4)[0]
        return Syn(task, fam, src, sport, dst, dport, uid, recv_ns, seq=seq)
    l7, qname = classify_udp(dport, data)
    return Syn(task, fam, src, sport, dst, dport, uid, recv_ns, "udp", l7, qname)


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
            _attr(NFULA_CFG_MODE, struct.pack("!IBB", COPY_RANGE, NFULNL_COPY_PACKET, 0)),
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
# the nftables side: a small rule set per task cgroup
# ---------------------------------------------------------------------------
COMMENT_RE = re.compile(r"cora-tap(?:-(u4s|u4l|u6s|u6l))?:([a-z0-9][a-z0-9_-]*)(?::(\d+))?")


class TapLockTimeout(FirewallError):
    """The cross-process tap lock could not be taken in time: its holder is stuck, or far slower than normal."""


def lock_timeout_from_env(default: float) -> float:
    """CORA_TAP_LOCK_TIMEOUT (seconds) overrides a default; an invalid value is ignored, loudly."""
    raw = os.environ.get("CORA_TAP_LOCK_TIMEOUT")
    if raw is None:
        return default
    try:
        v = float(raw)
        if 0 < v < float("inf"):
            return v
    except ValueError:
        pass
    print(f"cora-tap: ignoring invalid CORA_TAP_LOCK_TIMEOUT={raw!r}, using {default:g} s", file=sys.stderr)
    return default


class TapRules:
    CHAIN, SET4, SET6 = "tap", "cora_flow4", "cora_flow6"
    LEGACY_SETS = ("cora_udp4", "cora_udp6")   # 0.1.0 keyed flows WITHOUT the task; cleaned up on teardown
    TCP_KINDS, UDP_KINDS = ("t",), ("u4s", "u4l", "u6s", "u6l")

    def __init__(self, fw: Firewall, group: int = DEFAULT_GROUP, udp: Optional[bool] = True,
                 udp_timeout: int = 30, lock_timeout: Optional[float] = None):
        """udp=True/False forces it; udp=None auto-detects from the live table (used by cora_run).
        lock_timeout: seconds to wait for the cross-process tap lock before giving up (TapLockTimeout)."""
        self.fw, self.group, self.udp, self.udp_timeout = fw, group, udp, udp_timeout
        self.lock_timeout = (lock_timeout if lock_timeout is not None
                             else lock_timeout_from_env(DEFAULT_LOCK_TIMEOUT_S))

    last_timing: Dict[str, float] = {}

    @contextlib.contextmanager
    def _locked(self):
        """Serialize the read-rules-then-add step across processes. cora_run (pre-install) and the
        monitor (sync) both do it for a new task at the same moment; without this, both can read
        'no rules yet' and both add, leaving a task with duplicate rules that logs every packet
        twice (measured: 4 of 30 tasks)."""
        for base in ("/run/lock", tempfile.gettempdir()):
            try:
                path = os.path.join(base, f"cora-tap-{self.fw.table}.lock")
                fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
                break
            except OSError:
                continue
        else:
            yield                                    # nowhere to lock (never as root); proceed unlocked
            return
        try:
            t = time.monotonic()
            self._flock(fd, path, t)
            self.fw.timing.lock_ms += (time.monotonic() - t) * 1000.0     # how long WE waited for another holder
            self._note_holder(fd)
            yield
        finally:
            os.close(fd)                             # closing releases the flock

    def _flock(self, fd: int, path: str, start: float) -> None:
        """flock WITH A DEADLINE. A plain blocking flock has no timeout, so a holder that hangs (stopped, or stuck in
        uninterruptible I/O) would hang its caller forever. Polling costs at most 5 ms after the lock is released."""
        delay = 0.0005
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
            waited = time.monotonic() - start
            if waited >= self.lock_timeout:
                self.fw.timing.lock_ms += waited * 1000.0        # a failed wait still shows in last_timing
                raise TapLockTimeout(f"could not get the tap lock {path} within {self.lock_timeout:g} s: "
                                     f"{self._who_holds(fd)}")
            time.sleep(delay)
            delay = min(delay * 2, 0.005)

    @staticmethod
    def _note_holder(fd: int) -> None:
        """Write who holds the lock into it (under the lock), so a timeout can say who is stuck."""
        try:
            os.ftruncate(fd, 0)
            os.pwrite(fd, f"{os.getpid()} {os.path.basename(sys.argv[0]) or 'python'}\n".encode(), 0)
        except OSError:
            pass

    @staticmethod
    def _who_holds(fd: int) -> str:
        try:
            pid, _, name = os.pread(fd, 200, 0).decode(errors="replace").strip().partition(" ")
            with open(f"/proc/{int(pid)}/stat") as f:
                state = f.read().rsplit(")", 1)[1].split()[0]
            what = {"T": "stopped", "t": "traced", "D": "stuck in uninterruptible I/O", "Z": "a zombie",
                    "S": "sleeping", "R": "running"}.get(state, f"state {state}")
            return f"held by pid {int(pid)} ({name}, {what})"
        except (OSError, ValueError, IndexError):
            return "the holder could not be identified"

    def udp_enabled(self) -> bool:
        if self.udp is not None:
            return self.udp
        return self.fw.set_exists(self.SET4)

    def active(self) -> bool:
        """True if a sentinel has set up the tap chain (used by cora_run to pre-install)."""
        return self.fw.chain_exists(self.CHAIN)

    def _level(self) -> int:
        """Depth of a task cgroup in the v2 tree: every task is a direct child of the root."""
        return len(Path(os.path.relpath(self.fw.cg.root, self.fw.cg.mount)).parts) + 1

    def ensure_chain(self) -> None:
        t = self.fw.table
        lines = [f"add table inet {t}"]
        if self.udp_enabled():
            lv = self._level()
            for name, addr in ((self.SET4, "ip"), (self.SET6, "ip6")):
                # The key carries the sending task's cgroup id, so one task's flow can never be mistaken
                # for (and suppress) another task's flow that happens to share a destination and source port.
                lines.append(f"add set inet {t} {name} {{ typeof socket cgroupv2 level {lv} . {addr} daddr . "
                             f"udp dport . udp sport ; flags dynamic,timeout ; timeout {self.udp_timeout}s ; "
                             f"size 65536 ; }}")
        lines.append(f"add chain inet {t} {self.CHAIN} "
                     "{ type filter hook output priority -10 ; policy accept ; }")
        try:
            self.fw._script("\n".join(lines) + "\n")
        except FirewallError as e:
            if not self.udp_enabled():
                raise
            raise FirewallError(
                f"{e}. The UDP flow set is keyed on the sending task's cgroup, which needs an nftables with "
                f"`typeof` sets and a `socket cgroupv2` key (verified on nft 1.0.9, Linux 6.18). If yours "
                f"cannot, run with --no-tap-udp to tap TCP only.") from None

    # ---- rule text ------------------------------------------------------------
    def rule_texts(self, name: str) -> Dict[str, str]:
        """{kind: nft rule}, in the order they must be installed (a 'once' rule precedes its 'log' rule)."""
        level, path, cgid = self.fw.cgroup_match(name)
        base = f'socket cgroupv2 level {level} "{path}"'
        out = {"t": (f'{base} tcp flags & (syn | ack) == syn log prefix "{PREFIX}{name}" group {self.group} '
                     f'queue-threshold 1 snaplen {SNAPLEN_TCP} counter comment "{PREFIX}{name}:{cgid}"')}
        if self.udp_enabled():
            log = (f'log prefix "{PREFIX}{name}" group {self.group} queue-threshold 1 '
                   f'snaplen {SNAPLEN_UDP} counter')
            for fam, addr, st in (("4", "ip", self.SET4), ("6", "ip6", self.SET6)):
                key = f"socket cgroupv2 level {level} . {addr} daddr . udp dport . udp sport"
                out[f"u{fam}s"] = (f'{base} meta l4proto udp {key} @{st} update @{st} {{ {key} }} return '
                                   f'comment "cora-tap-u{fam}s:{name}:{cgid}"')
                out[f"u{fam}l"] = (f'{base} meta l4proto udp add @{st} {{ {key} }} {log} '
                                   f'comment "cora-tap-u{fam}l:{name}:{cgid}"')
        return out

    def rule_text(self, name: str) -> str:
        return self.rule_texts(name)["t"]

    def _needed(self) -> set:
        return set(self.TCP_KINDS) | (set(self.UDP_KINDS) if self.udp_enabled() else set())

    # ---- state read back from the kernel -------------------------------------------
    def rules(self) -> Dict[str, dict]:
        found: Dict[str, dict] = {}
        for r in self.fw.chain_rules(self.CHAIN):            # [] when the table or chain is not there yet
            m = COMMENT_RE.fullmatch(r["comment"] or "")
            if not m:
                continue
            kind, name, cgid = m.group(1) or "t", m.group(2), int(m.group(3)) if m.group(3) else None
            e = found.setdefault(name, {"handles": [], "kinds": set(), "cgids": set(), "packets": 0})
            e["handles"].append(r["handle"])
            e["kinds"].add(kind)
            e["cgids"].add(cgid)
            if kind == "t":
                e["packets"] = r["packets"]
        for e in found.values():                             # one agreed id, or -1 (inconsistent => stale)
            e["cgid"] = next(iter(e["cgids"])) if len(e["cgids"]) == 1 else -1
        return found

    def _complete(self, entry: Optional[dict], cgid: int) -> bool:
        """Right cgroup, every needed kind, and EXACTLY one rule per kind (a duplicate is damage)."""
        need = self._needed()
        return (bool(entry) and entry["cgid"] == cgid and entry["kinds"] == need
                and len(entry["handles"]) == len(need))

    def _replace_lines(self, name: str, entry: Optional[dict]) -> List[str]:
        t = self.fw.table
        lines = [f"delete rule inet {t} {self.CHAIN} handle {h}" for h in (entry["handles"] if entry else [])]
        lines += [f"add rule inet {t} {self.CHAIN} {txt}" for txt in self.rule_texts(name).values()]
        return lines

    def sync(self, live: Dict[str, int]) -> Tuple[List[str], List[str]]:
        """Make the rules match `live` ({task name: cgroup id}) in ONE atomic nft transaction.
        `last_timing` then says where the time went: waiting for the cross-process lock, or inside nft."""
        tm = self.fw.timing
        tm.reset()
        try:
            with self._locked():
                return self._sync(live)
        finally:
            self.last_timing = {"lock_ms": tm.lock_ms, "nft_ms": tm.ms, "nft_calls": tm.calls,
                                "nft_slowest_ms": tm.slowest, "nft_slowest_cmd": tm.slowest_cmd}

    def _sync(self, live: Dict[str, int]) -> Tuple[List[str], List[str]]:
        have = self.rules()
        t, lines, added, removed = self.fw.table, [], [], []
        for name, cgid in live.items():
            if self._complete(have.get(name), cgid):
                continue
            lines += self._replace_lines(name, have.get(name))   # stale/partial: replace the whole set
            added.append(name)
        for name, e in have.items():
            if name not in live:
                lines += [f"delete rule inet {t} {self.CHAIN} handle {h}" for h in e["handles"]]
                removed.append(name)
        if lines:
            self.fw._script("\n".join(lines) + "\n")
        return added, removed

    def install(self, name: str) -> bool:
        """Install one task's rules if missing or stale (used by cora_run, before exec)."""
        cgid = self.fw.cgroup_match(name)[2]
        with self._locked():
            have = self.rules().get(name)
            if self._complete(have, cgid):
                return False
            self.ensure_chain()
            self.fw._script("\n".join(self._replace_lines(name, have)) + "\n")
            return True

    def teardown(self) -> None:
        t = self.fw.table
        try:
            self.fw._script(f"flush chain inet {t} {self.CHAIN}\ndelete chain inet {t} {self.CHAIN}\n")
        except FirewallError:
            pass                                    # chain already gone
        for st in (self.SET4, self.SET6) + self.LEGACY_SETS:   # separately: a missing set must not abort the rest
            try:
                self.fw._script(f"delete set inet {t} {st}\n")
            except FirewallError:
                pass


class TapService:
    """Listener + rules. The listener binds FIRST, so a refusal leaves the ruleset untouched."""

    def __init__(self, fw: Firewall, group: int = DEFAULT_GROUP, udp: bool = True, udp_timeout: int = 30):
        self.listener = NflogListener(group)
        self.rules = TapRules(fw, group, udp=udp, udp_timeout=udp_timeout)
        self.rules.ensure_chain()

    def sync(self, live: Dict[str, int]) -> Tuple[List[str], List[str]]:
        return self.rules.sync(live)

    @property
    def last_timing(self) -> Dict[str, float]:
        return self.rules.last_timing

    def close(self) -> None:
        self.listener.close()
        self.rules.teardown()


def available(group: int = DEFAULT_GROUP) -> Tuple[bool, str]:
    try:
        NflogListener(group).close()
        return True, ""
    except OSError as e:
        return False, str(e)
