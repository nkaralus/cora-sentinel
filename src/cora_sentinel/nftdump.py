#!/usr/bin/env python3
"""
cora_sentinel.nftdump - read nftables rules and objects straight from the kernel over netlink. Stdlib only.

WHY. `nft list` prints a `socket cgroupv2` match by turning the cgroup id back into a PATH, and it finds the path by
walking the cgroup tree, once per rule. So listing the tap chain costs (cgroup rules x cgroups on the machine), however
few rules there are. Measured with 15 cgroup rules: 3.5 ms with 4 cgroups on the machine, 777 ms with 1,487, 3.2 s with
5,987, while the same table's chain WITHOUT cgroup rules stayed at 2 ms; text, JSON and numeric output are all alike.
Every task adds 5 tap rules and one cgroup, so the cost grows with load, and the listing runs inside the tap lock (which
every cora-run launch and the sync worker serialize on) and inside Firewall.gc (which an ISOLATE waits behind).

The kernel's own dump carries the raw ids: its cost is O(rules). This module reads only what the callers need: for each
rule its handle, its comment, and its first counter; and whether a chain or a set exists. Anything unexpected raises
NftNetlinkError, and the caller falls back to the nft command, which is slow but always right.
"""
from __future__ import annotations

import errno
import socket
import struct
from typing import Iterator, List, Tuple

NETLINK_NETFILTER = 12
NFNL_SUBSYS_NFTABLES = 10
NFPROTO_INET = 1

NFT_MSG_GETCHAIN, NFT_MSG_NEWRULE, NFT_MSG_GETRULE, NFT_MSG_GETSET = 4, 6, 7, 10
NFTA_CHAIN_TABLE, NFTA_CHAIN_NAME = 1, 3
NFTA_SET_TABLE, NFTA_SET_NAME = 1, 2
NFTA_RULE_TABLE, NFTA_RULE_CHAIN, NFTA_RULE_HANDLE, NFTA_RULE_EXPRESSIONS, NFTA_RULE_USERDATA = 1, 2, 3, 4, 7
NFTA_EXPR_NAME, NFTA_EXPR_DATA = 1, 2
NFTA_COUNTER_BYTES, NFTA_COUNTER_PACKETS = 1, 2
NFTNL_UDATA_RULE_COMMENT = 0

NLM_F_REQUEST, NLM_F_DUMP_INTR, NLM_F_DUMP = 0x1, 0x10, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
_MAX_RETRIES = 5


class NftNetlinkError(Exception):
    """The kernel refused, or sent something unexpected. `errno` is set when the kernel gave one."""

    def __init__(self, msg: str, err: int = 0):
        super().__init__(msg)
        self.errno = err


def _nla(typ: int, payload: bytes) -> bytes:
    n = 4 + len(payload)
    return struct.pack("=HH", n, typ) + payload + b"\0" * (-n % 4)


def _str(typ: int, s: str) -> bytes:
    return _nla(typ, s.encode() + b"\0")


def _attrs(buf: bytes, off: int = 0) -> Iterator[Tuple[int, bytes]]:
    while off + 4 <= len(buf):
        ln, typ = struct.unpack_from("=HH", buf, off)
        if ln < 4 or off + ln > len(buf):
            raise NftNetlinkError("malformed netlink attribute")
        yield typ & 0x3FFF, buf[off + 4:off + ln]
        off += (ln + 3) & ~3


def _messages(data: bytes) -> Iterator[Tuple[int, int, bytes]]:
    off = 0
    while off + 16 <= len(data):
        ln, typ, flags, _seq, _pid = struct.unpack_from("=IHHII", data, off)
        if ln < 16 or off + ln > len(data):
            raise NftNetlinkError("malformed netlink message")
        yield typ, flags, data[off + 16:off + ln]
        off += (ln + 3) & ~3


def _request(msg_type: int, flags: int, attrs: bytes, family: int = NFPROTO_INET,
             timeout: float = 5.0) -> List[Tuple[int, int, bytes]]:
    """One request; returns the nf_tables messages (type without the subsystem byte, flags, payload)."""
    body = struct.pack("=BBH", family, 0, 0) + attrs                      # struct nfgenmsg
    msg = struct.pack("=IHHII", 16 + len(body), (NFNL_SUBSYS_NFTABLES << 8) | msg_type,
                      NLM_F_REQUEST | flags, 1, 0) + body
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    except OSError as e:
        raise NftNetlinkError(f"cannot open a NETLINK_NETFILTER socket: {e.strerror}", e.errno or 0) from None
    out: List[Tuple[int, int, bytes]] = []
    try:
        s.settimeout(timeout)
        s.sendto(msg, (0, 0))
        dump = bool(flags & NLM_F_DUMP)
        while True:
            for typ, fl, payload in _messages(s.recv(1 << 17)):
                if typ == NLMSG_ERROR:
                    code = -struct.unpack_from("=i", payload)[0] if len(payload) >= 4 else errno.EPROTO
                    if code:
                        raise NftNetlinkError(f"the kernel said {errno.errorcode.get(code, code)}", code)
                    return out                                              # an ack
                if typ == NLMSG_DONE:
                    return out
                out.append((typ & 0xFF, fl, payload))
            if not dump:
                return out                                                  # a plain GET answers with one message
    except (OSError, struct.error) as e:
        raise NftNetlinkError(f"netlink read failed: {e}", getattr(e, "errno", 0) or 0) from None
    finally:
        s.close()


def _udata_comment(v: bytes) -> str | None:
    i = 0
    while i + 2 <= len(v):
        typ, ln = v[i], v[i + 1]
        val = v[i + 2:i + 2 + ln]
        i += 2 + ln
        if typ == NFTNL_UDATA_RULE_COMMENT:
            return val.rstrip(b"\0").decode(errors="replace")
    return None


def _parse_rule(payload: bytes) -> dict:
    rule = {"handle": None, "comment": None, "packets": 0, "bytes": 0}
    counted = False
    try:
        for typ, val in _attrs(payload, 4):                                 # skip the 4-byte nfgenmsg
            if typ == NFTA_RULE_HANDLE:
                rule["handle"] = struct.unpack(">Q", val)[0]
            elif typ == NFTA_RULE_USERDATA:
                rule["comment"] = _udata_comment(val)
            elif typ == NFTA_RULE_EXPRESSIONS and not counted:
                for _, elem in _attrs(val):                                 # NFTA_LIST_ELEM
                    name, data = None, b""
                    for et, ev in _attrs(elem):
                        if et == NFTA_EXPR_NAME:
                            name = ev.rstrip(b"\0").decode(errors="replace")
                        elif et == NFTA_EXPR_DATA:
                            data = ev
                    if name == "counter":
                        for ct, cv in _attrs(data):
                            if ct == NFTA_COUNTER_PACKETS:
                                rule["packets"] = struct.unpack(">Q", cv)[0]
                            elif ct == NFTA_COUNTER_BYTES:
                                rule["bytes"] = struct.unpack(">Q", cv)[0]
                        counted = True                                      # the FIRST counter, as nft's JSON path did
                        break
    except struct.error:
        raise NftNetlinkError("malformed nf_tables rule") from None
    if rule["handle"] is None:
        raise NftNetlinkError("a rule without a handle")
    return rule


def dump_rules(table: str, chain: str, family: int = NFPROTO_INET) -> List[dict]:
    """[{handle, comment, packets, bytes}] for one chain; [] if the table or chain does not exist."""
    attrs = _str(NFTA_RULE_TABLE, table) + _str(NFTA_RULE_CHAIN, chain)
    for _ in range(_MAX_RETRIES):
        try:
            msgs = _request(NFT_MSG_GETRULE, NLM_F_DUMP, attrs, family)
        except NftNetlinkError as e:
            if e.errno == errno.ENOENT:
                return []
            raise
        if any(fl & NLM_F_DUMP_INTR for _, fl, _ in msgs):
            continue                                                         # the ruleset changed mid-dump: redo it
        return [_parse_rule(p) for typ, _, p in msgs if typ == NFT_MSG_NEWRULE]
    raise NftNetlinkError("the ruleset kept changing during the dump")


def _exists(msg_type: int, attrs: bytes, family: int) -> bool:
    try:
        return bool(_request(msg_type, 0, attrs, family))
    except NftNetlinkError as e:
        if e.errno == errno.ENOENT:
            return False
        raise


def chain_exists(table: str, chain: str, family: int = NFPROTO_INET) -> bool:
    return _exists(NFT_MSG_GETCHAIN, _str(NFTA_CHAIN_TABLE, table) + _str(NFTA_CHAIN_NAME, chain), family)


def set_exists(table: str, name: str, family: int = NFPROTO_INET) -> bool:
    return _exists(NFT_MSG_GETSET, _str(NFTA_SET_TABLE, table) + _str(NFTA_SET_NAME, name), family)
