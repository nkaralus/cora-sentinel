"""Virtual subnets and host allocation. v1 scope: /24 networks inside 10.0.0.0/8."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Iterable, Optional

from .errors import RegistryError, show
from .geometry import AABB

__all__ = ["Subnet", "parse_subnet", "parse_host", "DEFAULT_RESERVED_BELOW"]

_TEN = ipaddress.ip_network("10.0.0.0/8")
DEFAULT_RESERVED_BELOW = 10   # hosts .1-.9 are reserved for infrastructure


def parse_subnet(cidr: Any) -> ipaddress.IPv4Network:
    if type(cidr) is not str or not cidr.isascii() or len(cidr) > 18:
        raise RegistryError("BAD_SUBNET", show(cidr))
    try:
        n = ipaddress.ip_network(cidr, strict=True)
    except ValueError:
        raise RegistryError("BAD_SUBNET", show(cidr)) from None
    if n.version != 4 or n.prefixlen != 24 or not n.subnet_of(_TEN) or str(n) != cidr:
        raise RegistryError("BAD_SUBNET", f"{show(cidr)}: need canonical a.b.c.0/24 inside 10.0.0.0/8")
    return n


def parse_host(s: Any) -> ipaddress.IPv4Address:
    if type(s) is not str or not s.isascii() or len(s) > 15:
        raise RegistryError("BAD_IP", show(s))
    try:
        return ipaddress.IPv4Address(s)       # rejects leading zeros and octets > 255
    except ValueError:
        raise RegistryError("BAD_IP", show(s)) from None


@dataclass(frozen=True)
class Subnet:
    cidr: str
    label: str = ""
    reserved_below: int = DEFAULT_RESERVED_BELOW
    world: Optional[AABB] = None

    def __post_init__(self):
        parse_subnet(self.cidr)
        if type(self.reserved_below) is not int or not 1 <= self.reserved_below <= 250:
            raise RegistryError("BAD_SUBNET", "reserved_below must be an int in 1..250")
        if type(self.label) is not str or not self.label.isascii() or not self.label.isprintable() or len(self.label) > 64:
            raise RegistryError("BAD_SUBNET", "label must be printable ASCII, max 64")
        if self.world is not None and not isinstance(self.world, AABB):
            raise RegistryError("BAD_SUBNET", "world must be an AABB")

    @cached_property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.cidr)

    def usable(self, ip: ipaddress.IPv4Address) -> bool:
        base = int(self.network.network_address)
        return (ip in self.network and ip != self.network.broadcast_address
                and int(ip) - base >= self.reserved_below)

    def next_free(self, used: Iterable[ipaddress.IPv4Address]) -> ipaddress.IPv4Address:
        taken = set(used)
        base = int(self.network.network_address)
        for host in range(self.reserved_below, 255):
            ip = ipaddress.IPv4Address(base + host)
            if ip not in taken:
                return ip
        raise RegistryError("SUBNET_EXHAUSTED", self.cidr)
