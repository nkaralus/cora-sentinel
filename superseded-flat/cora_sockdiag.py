#!/usr/bin/env python3
"""
cora_sockdiag.py - TCP socket inspection over NETLINK_SOCK_DIAG. Stdlib only, no C, no eBPF.

Two kernel interfaces, and they are NOT the same thing:

  SockDiag        request/response. Asks the kernel for a dump of live TCP sockets, filtered
                  kernel-side by state. Each socket carries INET_DIAG_CGROUP_ID (CAP_NET_ADMIN),
                  so a socket is attributed to a task by the kernel itself, no /proc/<pid>/fd
                  scanning. This is POLLING: a socket that opens and closes between two dumps
                  is never in either of them.

  DestroyListener multicast. The kernel broadcasts one message for every TCP socket as it is
                  destroyed (the mechanism behind `ss -E`). Nothing can be missed, short of the
                  receive buffer overflowing, which is counted in .lost and never hidden.
                  BUT a destroy message carries no cgroup id and inode 0: it says WHAT was
                  contacted, not WHICH TASK did it. Its cookie, however, equals the cookie the
                  same socket had in any earlier dump, which is an exact identity for dedupe.

Offsets of struct inet_diag_msg (72 bytes, then netlink attributes):
  0 family 1 state 2 timer 3 retrans | 4 sport(be16) 6 dport(be16) 8 src[16] 24 dst[16]
  40 if 44 cookie[2*u32] | 52 expires 56 rqueue 60 wqueue 64 uid 68 inode
"""
from __future__ import annotations

import errno
import os
import socket
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST, NLM_F_DUMP, NLM_F_DUMP_INTR = 0x1, 0x300, 0x10
NLMSG_ERROR, NLMSG_DONE = 2, 3
SOL_NETLINK, NETLINK_ADD_MEMBERSHIP = 270, 1
SO_RCVBUFFORCE = 33
SKNLGRP_INET_TCP_DESTROY, SKNLGRP_INET6_TCP_DESTROY = 1, 3   # linux/sock_diag.h
INET_DIAG_CGROUP_ID = 21                                      # linux/inet_diag.h
NOCOOKIE = 0xFFFFFFFFFFFFFFFF
TCP_ESTABLISHED, TCP_SYN_SENT, TCP_LISTEN = 1, 2, 10
LIVE_MASK = (1 << TCP_ESTABLISHED) | (1 << TCP_SYN_SENT) | (1 << TCP_LISTEN)
_HDR = struct.Struct("=IHHII")
MSG_MIN = 72


@dataclass(frozen=True)
class Sock:
    family: int
    state: int
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    uid: int
    inode: int
    cookie: Optional[int]
    cgroup_id: Optional[int]

    def row(self) -> dict:
        """Same shape as parse_proc_net_tcp() rows, plus cookie/uid/cgroup_id."""
        return {"local_ip": self.local_ip, "local_port": self.local_port,
                "remote_ip": self.remote_ip, "remote_port": self.remote_port,
                "state": f"{self.state:02X}", "inode": self.inode,
                "cookie": self.cookie, "uid": self.uid, "cgroup_id": self.cgroup_id}


def parse_msg(buf: bytes) -> Sock:
    """Parse one struct inet_diag_msg (+attributes). Raises ValueError if malformed."""
    if len(buf) < MSG_MIN:
        raise ValueError("short inet_diag_msg")
    fam, state = buf[0], buf[1]
    if fam == socket.AF_INET:
        af, n = socket.AF_INET, 4
    elif fam == socket.AF_INET6:
        af, n = socket.AF_INET6, 16
    else:
        raise ValueError(f"unexpected family {fam}")
    sport, dport = struct.unpack_from("!HH", buf, 4)
    c0, c1 = struct.unpack_from("=II", buf, 44)
    uid, inode = struct.unpack_from("=II", buf, 64)
    cookie = (c1 << 32) | c0
    cgroup = None
    q = MSG_MIN
    while q + 4 <= len(buf):                       # netlink attributes
        alen, atype = struct.unpack_from("=HH", buf, q)
        if alen < 4 or q + alen > len(buf):
            break
        if (atype & 0x3FFF) == INET_DIAG_CGROUP_ID and alen >= 12:
            cgroup = struct.unpack_from("=Q", buf, q + 4)[0]
        q += (alen + 3) & ~3
    return Sock(fam, state, socket.inet_ntop(af, buf[8:8 + n]), sport,
                socket.inet_ntop(af, buf[24:24 + n]), dport, uid, inode,
                None if cookie == NOCOOKIE else cookie, cgroup)


def _nl_socket() -> socket.socket:
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
    s.bind((0, 0))
    return s


class SockDiag:
    """Dump live TCP sockets (v4 + v6), state-filtered by the kernel."""

    def __init__(self):
        self.s = _nl_socket()
        self.s.settimeout(5)
        self._seq = 0
        self._buf = bytearray(1 << 18)

    def close(self) -> None:
        self.s.close()

    def dump(self, states: int = LIVE_MASK,
             families: Tuple[int, ...] = (socket.AF_INET, socket.AF_INET6)) -> List[Sock]:
        out: List[Sock] = []
        for fam in families:
            for _ in range(2):                      # one retry if the kernel flags the dump inconsistent
                socks, interrupted = self._dump_family(fam, states)
                if not interrupted:
                    break
            out += socks
        return out

    def _dump_family(self, family: int, states: int) -> Tuple[List[Sock], bool]:
        self._seq += 1
        req = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, 0, 0, states) + b"\0" * 48
        self.s.send(_HDR.pack(16 + len(req), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP,
                              self._seq, 0) + req)
        out: List[Sock] = []
        interrupted = False
        while True:
            n = self.s.recv_into(self._buf)
            data = bytes(self._buf[:n])
            off = 0
            while off + 16 <= n:
                ln, typ, flags, _, _ = _HDR.unpack_from(data, off)
                if ln < 16 or off + ln > n:
                    raise ValueError("truncated netlink message")
                if typ == NLMSG_DONE:
                    return out, interrupted
                if typ == NLMSG_ERROR:
                    code = struct.unpack_from("=i", data, off + 16)[0]
                    if code:
                        raise OSError(-code, os.strerror(-code))
                elif typ == SOCK_DIAG_BY_FAMILY:
                    try:
                        out.append(parse_msg(data[off + 16:off + ln]))
                    except ValueError:
                        pass                        # skip a malformed record, keep the dump
                if flags & NLM_F_DUMP_INTR:
                    interrupted = True
                off += (ln + 3) & ~3


class DestroyListener:
    """One event per TCP socket destroyed anywhere in this network namespace."""

    def __init__(self, rcvbuf: int = 8 << 20):
        s = _nl_socket()
        for grp in (SKNLGRP_INET_TCP_DESTROY, SKNLGRP_INET6_TCP_DESTROY):
            s.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, grp)
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, rcvbuf)
        except OSError:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.s = s
        self.lost = 0            # ENOBUFS count: each is a gap of unknown size, never hidden
        self._buf = bytearray(1 << 16)

    def close(self) -> None:
        self.s.close()

    def poll(self, timeout: float) -> List[Sock]:
        self.s.settimeout(max(timeout, 0.0001))
        try:
            n = self.s.recv_into(self._buf)
        except socket.timeout:
            return []
        except OSError as e:
            if e.errno == errno.ENOBUFS:
                self.lost += 1
                return []
            raise
        data = bytes(self._buf[:n])
        out: List[Sock] = []
        off = 0
        while off + 16 <= n:
            ln, typ, _, _, _ = _HDR.unpack_from(data, off)
            if ln < 16 or off + ln > n:
                break
            if typ == SOCK_DIAG_BY_FAMILY:
                try:
                    out.append(parse_msg(data[off + 16:off + ln]))
                except ValueError:
                    pass
            off += (ln + 3) & ~3
        return out


def available() -> bool:
    """True if this kernel/privilege level lets us talk to sock_diag at all."""
    try:
        d = SockDiag()
        try:
            d.dump(states=1 << TCP_LISTEN, families=(socket.AF_INET,))
        finally:
            d.close()
        return True
    except (OSError, ValueError):
        return False
