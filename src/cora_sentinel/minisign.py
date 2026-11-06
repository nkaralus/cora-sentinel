"""
cora_sentinel.minisign - verify minisign signatures. Stdlib only, verify-only.

Ed25519 verification is RFC 8032 section 5.1.7, written out in plain integers so the package keeps
`dependencies = []`. It is not constant-time, which does not matter here: verification handles only
public data (key, message, signature). There is deliberately NO signing code in this module; the
secret key lives offline and never touches a node.

Formats (https://jedisct1.github.io/minisign/):
  public key   base64( "Ed" | keyid[8] | pk[32] )
  signature    line 1 untrusted comment; line 2 base64( alg[2] | keyid[8] | sig[64] )
               line 3 "trusted comment: <text>";  line 4 base64( global_sig[64] )
  alg "ED": sig is over BLAKE2b-512(message)  (minisign >= 0.10 default)
  alg "Ed": sig is over the raw message        (legacy, accepted)
  global_sig is over sig[64] | <trusted comment text>, so the trusted comment cannot be swapped.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

# ---------------------------------------------------------------- RFC 8032 Ed25519 (verify)
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _recover_x(y: int, sign: int):
    if y >= _p:
        return None
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p:
        x = x * _I % _p
    if (x * x - x2) % _p:
        return None
    if x & 1 != sign:
        x = _p - x
    return x


_Gy = 4 * pow(5, _p - 2, _p) % _p
_G = (_recover_x(_Gy, 0), _Gy, 1, _recover_x(_Gy, 0) * _Gy % _p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _decompress(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:                                   # reject malleable / non-canonical S
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(R, _mul(k, A)))


# ---------------------------------------------------------------- minisign envelope
class MinisignError(Exception):
    pass


@dataclass(frozen=True)
class PublicKey:
    keyid: bytes
    key: bytes

    @property
    def keyid_hex(self) -> str:
        return self.keyid[::-1].hex().upper()      # minisign prints the id little-endian


def _b64(s: str, n: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(s.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise MinisignError(f"{what}: not base64") from None
    if len(raw) != n:
        raise MinisignError(f"{what}: expected {n} bytes, got {len(raw)}")
    return raw


def load_public_key(text: str) -> PublicKey:
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        raise MinisignError("public key: empty")
    raw = _b64(lines[-1], 42, "public key")
    if raw[:2] != b"Ed":
        raise MinisignError("public key: not an Ed25519 minisign key")
    return PublicKey(raw[2:10], raw[10:42])


@dataclass(frozen=True)
class Verified:
    keyid_hex: str
    trusted_comment: str
    prehashed: bool


def verify(pub: PublicKey, message: bytes, sig_text: str) -> Verified:
    """Return the trusted comment if (and only if) BOTH signatures check. Raises MinisignError otherwise."""
    lines = sig_text.splitlines()
    if len(lines) < 4 or not lines[0].startswith("untrusted comment:") or \
            not lines[2].startswith("trusted comment: "):
        raise MinisignError("signature: not a 4-line minisign signature file")
    raw = _b64(lines[1], 74, "signature")
    alg, keyid, sig = raw[:2], raw[2:10], raw[10:]
    if alg not in (b"ED", b"Ed"):
        raise MinisignError(f"signature: unknown algorithm {alg!r}")
    if keyid != pub.keyid:
        raise MinisignError(f"signature: made by key {keyid[::-1].hex().upper()}, "
                            f"not the pinned key {pub.keyid_hex}")
    body = hashlib.blake2b(message, digest_size=64).digest() if alg == b"ED" else message
    if not ed25519_verify(pub.key, body, sig):
        raise MinisignError("signature: does not match the message")
    trusted = lines[2][len("trusted comment: "):]
    gsig = _b64(lines[3], 64, "global signature")
    if not ed25519_verify(pub.key, sig + trusted.encode(), gsig):
        raise MinisignError("signature: trusted comment was altered")
    return Verified(pub.keyid_hex, trusted, alg == b"ED")
