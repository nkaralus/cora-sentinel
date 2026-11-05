"""Reading nftables rules and objects over netlink. Synthetic kernel messages: no kernel needed."""
import errno
import socket
import struct

import pytest

from cora_sentinel import nftdump
from cora_sentinel.nftdump import NftNetlinkError, _nla, _str


def udata(comment, first_other=False):
    out = b""
    if first_other:
        out += bytes([1, 3]) + b"xy\0"                                   # some other userdata TLV before the comment
    return out + bytes([0, len(comment) + 1]) + comment.encode() + b"\0"


def counter(packets, byts):
    """The counter's DATA attributes only (expr() adds the name and wraps them)."""
    return _nla(nftdump.NFTA_COUNTER_PACKETS, struct.pack(">Q", packets)) + _nla(nftdump.NFTA_COUNTER_BYTES, struct.pack(">Q", byts))


def expr(name, data=b""):
    return _nla(1, _str(1, name) + (_nla(2, data) if data else b""))


def rule_payload(handle=7, comment="cora-tap:t0:123", exprs=(), ud=None):
    attrs = _str(nftdump.NFTA_RULE_TABLE, "t") + _str(nftdump.NFTA_RULE_CHAIN, "tap")
    if handle is not None:
        attrs += _nla(nftdump.NFTA_RULE_HANDLE, struct.pack(">Q", handle))
    if exprs:
        attrs += _nla(nftdump.NFTA_RULE_EXPRESSIONS | 0x8000, b"".join(exprs))      # NLA_F_NESTED, as the kernel sets it
    if comment is not None or ud is not None:
        attrs += _nla(nftdump.NFTA_RULE_USERDATA, ud if ud is not None else udata(comment))
    return struct.pack("=BBH", 1, 0, 0) + attrs                                      # struct nfgenmsg first


def test_a_rule_is_read_with_handle_comment_and_counter():
    r = nftdump._parse_rule(rule_payload(7, "cora-tap:t0:123", [expr("socket"), expr("counter", counter(4, 240))]))
    assert r == {"handle": 7, "comment": "cora-tap:t0:123", "packets": 4, "bytes": 240}


def test_only_the_FIRST_counter_is_read_as_nfts_json_path_did():
    r = nftdump._parse_rule(rule_payload(exprs=[expr("counter", counter(4, 240)), expr("counter", counter(99, 9999))]))
    assert (r["packets"], r["bytes"]) == (4, 240)


def test_a_rule_without_a_counter_or_a_comment_still_reads():
    r = nftdump._parse_rule(rule_payload(5, comment=None, exprs=[expr("log")]))
    assert r == {"handle": 5, "comment": None, "packets": 0, "bytes": 0}


def test_the_comment_is_found_even_when_another_userdata_entry_comes_first():
    assert nftdump._parse_rule(rule_payload(ud=udata("hello", first_other=True)))["comment"] == "hello"


def test_counters_and_handles_use_the_full_64_bits():
    big = 2**40 + 5
    r = nftdump._parse_rule(rule_payload(handle=big, exprs=[expr("counter", counter(big, big * 3))]))
    assert (r["handle"], r["packets"], r["bytes"]) == (big, big, big * 3)


@pytest.mark.parametrize("payload", [
    rule_payload(handle=None),                                    # a rule without a handle is not a rule
    b"",                                                          # not even an nfgenmsg
    struct.pack("=BBH", 1, 0, 0) + struct.pack("=HH", 200, 3),    # an attribute that claims more than there is
    struct.pack("=BBH", 1, 0, 0) + struct.pack("=HH", 2, 3),      # an attribute shorter than its own header
    struct.pack("=BBH", 1, 0, 0) + _nla(nftdump.NFTA_RULE_HANDLE, b"abc"),   # a handle that is not 8 bytes
])
def test_malformed_rules_raise_our_error_and_nothing_else(payload):
    with pytest.raises(NftNetlinkError):
        nftdump._parse_rule(payload)


def test_a_truncated_message_header_raises_our_error():
    with pytest.raises(NftNetlinkError):
        list(nftdump._messages(struct.pack("=IHHII", 9999, 0, 0, 0, 0)))          # claims more bytes than it has


def msg(flags=0):
    return [(nftdump.NFT_MSG_NEWRULE, flags, rule_payload(1, "a")), (nftdump.NFT_MSG_NEWRULE, flags, rule_payload(2, "b"))]


def test_a_dump_the_kernel_marks_interrupted_is_redone(monkeypatch):
    seq = iter([msg(nftdump.NLM_F_DUMP_INTR), msg(nftdump.NLM_F_DUMP_INTR), msg()])
    monkeypatch.setattr(nftdump, "_request", lambda *a, **k: next(seq))
    assert [r["handle"] for r in nftdump.dump_rules("t", "tap")] == [1, 2]       # the third, clean, dump


def test_a_ruleset_that_never_stops_changing_is_an_error_not_a_loop(monkeypatch):
    calls = []
    monkeypatch.setattr(nftdump, "_request", lambda *a, **k: calls.append(1) or msg(nftdump.NLM_F_DUMP_INTR))
    with pytest.raises(NftNetlinkError, match="kept changing"):
        nftdump.dump_rules("t", "tap")
    assert len(calls) == nftdump._MAX_RETRIES


def test_a_missing_table_is_an_empty_dump_and_a_missing_object_is_false(monkeypatch):
    def enoent(*a, **k):
        raise NftNetlinkError("the kernel said ENOENT", errno.ENOENT)
    monkeypatch.setattr(nftdump, "_request", enoent)
    assert nftdump.dump_rules("t", "tap") == []
    assert nftdump.chain_exists("t", "tap") is False and nftdump.set_exists("t", "s") is False


def test_any_other_kernel_error_is_raised_not_swallowed(monkeypatch):
    def eperm(*a, **k):
        raise NftNetlinkError("the kernel said EPERM", errno.EPERM)
    monkeypatch.setattr(nftdump, "_request", eperm)
    for call in (lambda: nftdump.dump_rules("t", "tap"), lambda: nftdump.chain_exists("t", "tap"),
                 lambda: nftdump.set_exists("t", "s")):
        with pytest.raises(NftNetlinkError):
            call()


def test_a_socket_that_cannot_be_opened_is_our_error_with_its_errno(monkeypatch):
    def refuse(*a, **k):
        raise OSError(errno.EPROTONOSUPPORT, "Protocol not supported")
    monkeypatch.setattr(socket, "socket", refuse)
    with pytest.raises(NftNetlinkError) as e:
        nftdump.dump_rules("t", "tap")
    assert e.value.errno == errno.EPROTONOSUPPORT
