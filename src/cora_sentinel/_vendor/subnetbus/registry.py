"""State registry: names <-> virtual IPs, with strict load/save and duplicate prevention."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .addressing import Subnet, parse_host, parse_subnet
from .errors import BusError, PathError, RegistryError, show
from .fsguard import lexical_segments
from .geometry import AABB, find_overlaps

__all__ = ["Registry", "Node", "NAME_RE", "REGISTRY_VERSION"]

NAME_RE = re.compile(r"%[A-Z][a-zA-Z0-9]{0,63}", re.ASCII)   # same shape as Mule `target`
KIND_RE = re.compile(r"[a-z][a-z0-9_]{0,31}", re.ASCII)
REGISTRY_VERSION = "1.0.0"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_NODES = 20000


@dataclass(frozen=True)
class Node:
    name: str
    ip: str
    subnet: str
    kind: str = "scene_node"
    bounds: Optional[AABB] = None
    solid: bool = True
    path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"ip": self.ip, "subnet": self.subnet, "kind": self.kind, "solid": self.solid}
        if self.bounds is not None:
            d["bounds"] = self.bounds.to_dict()
        if self.path is not None:
            d["path"] = self.path
        return d


def _no_dupes(pairs):
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise RegistryError("DUPLICATE_KEY", show(k))
        out[k] = v
    return out


def _no_const(name: str):
    raise RegistryError("BAD_JSON", f"non-finite constant {name}")


class Registry:
    def __init__(self) -> None:
        self._subnets: Dict[str, Subnet] = {}
        self._nodes: Dict[str, Node] = {}
        self._by_ip: Dict[str, str] = {}
        self._fold: Dict[str, str] = {}
        self.revision = 0

    # ---- reads ------------------------------------------------------------
    def subnet(self, cidr: str) -> Optional[Subnet]:
        return self._subnets.get(cidr) if type(cidr) is str else None

    def subnets(self) -> List[Subnet]:
        return list(self._subnets.values())

    def get(self, name: str) -> Optional[Node]:
        return self._nodes.get(name) if type(name) is str else None

    def by_ip(self, ip: str) -> Optional[Node]:
        n = self._by_ip.get(ip) if type(ip) is str else None
        return self._nodes[n] if n else None

    def nodes(self, subnet: Optional[str] = None) -> List[Node]:
        return [n for n in self._nodes.values() if subnet is None or n.subnet == subnet]

    def resolve(self, ref: str) -> Optional[Node]:
        """Resolve '%Name' or a dotted IP to a node. Unknown or malformed -> None."""
        if type(ref) is not str:
            return None
        if ref.startswith("%"):
            return self.get(ref)
        try:
            return self.by_ip(str(parse_host(ref)))
        except BusError:
            return None

    def __len__(self) -> int:
        return len(self._nodes)

    # ---- geometry ---------------------------------------------------------
    def placement_problems(self, subnet: str, bounds: AABB, *, ignore: Optional[str] = None,
                           solid: bool = True) -> List[Tuple[str, str]]:
        """[(code, detail)] explaining why `bounds` cannot be placed in `subnet`."""
        sn = self.subnet(subnet)
        if sn is None:
            return [("UNKNOWN_SUBNET", show(subnet))]
        out: List[Tuple[str, str]] = []
        if sn.world is not None and not sn.world.contains(bounds):
            out.append(("OUT_OF_WORLD", f"bounds leave the world of {subnet}"))
        if solid:
            others = [(n.name, n.bounds) for n in self._nodes.values()
                      if n.subnet == subnet and n.solid and n.bounds is not None and n.name != ignore]
            hits = find_overlaps(bounds, others)
            if hits:
                shown = ", ".join(f"{n} ({d:.4g}px)" for n, d in hits[:5])
                out.append(("SOLID_OVERLAP", f"overlaps {len(hits)} solid node(s): {shown}"))
        return out

    # ---- mutations (all-or-nothing) ---------------------------------------
    def add_subnet(self, cidr: str, *, label: str = "", reserved_below: int = 10,
                   world: Optional[AABB] = None) -> Subnet:
        if cidr in self._subnets:
            raise RegistryError("DUPLICATE_SUBNET", show(cidr))
        sn = Subnet(cidr, label, reserved_below, world)
        self._subnets[cidr] = sn
        self.revision += 1
        return sn

    def allocate(self, name: str, subnet: str, *, kind: str = "scene_node", ip: Optional[str] = None,
                 bounds: Optional[AABB] = None, solid: bool = True, path: Optional[str] = None) -> Node:
        sn = self.subnet(subnet)
        if sn is None:
            raise RegistryError("UNKNOWN_SUBNET", show(subnet))
        used = {ipaddress.IPv4Address(i) for i, n in self._by_ip.items() if self._nodes[n].subnet == subnet}
        if ip is None:
            chosen = sn.next_free(used)
        else:
            chosen = parse_host(ip)
            if not sn.usable(chosen):
                raise RegistryError("IP_NOT_USABLE", f"{show(ip)} is outside {subnet}, reserved, or broadcast")
        node = Node(name, str(chosen), subnet, kind, bounds, solid, path)
        self._check_node(node)
        if bounds is not None:
            problems = self.placement_problems(subnet, bounds, solid=solid)
            if problems:
                raise RegistryError(problems[0][0], problems[0][1])
        self._insert(node)
        self.revision += 1
        return node

    def release(self, name: str) -> None:
        node = self._nodes.pop(name, None)
        if node is None:
            raise RegistryError("UNKNOWN_NODE", show(name))
        del self._by_ip[node.ip]
        del self._fold[node.name.casefold()]
        self.revision += 1

    def set_bounds(self, name: str, bounds: AABB) -> Node:
        node = self.get(name)
        if node is None:
            raise RegistryError("UNKNOWN_NODE", show(name))
        problems = self.placement_problems(node.subnet, bounds, ignore=name, solid=node.solid)
        if problems:
            raise RegistryError(problems[0][0], problems[0][1])
        new = Node(node.name, node.ip, node.subnet, node.kind, bounds, node.solid, node.path)
        self._nodes[name] = new
        self.revision += 1
        return new

    # ---- integrity --------------------------------------------------------
    def _check_node(self, n: Node) -> None:
        """Field-level and uniqueness checks against current state. Raises RegistryError."""
        if type(n.name) is not str or not NAME_RE.fullmatch(n.name):
            raise RegistryError("BAD_NAME", show(n.name))
        if type(n.kind) is not str or not KIND_RE.fullmatch(n.kind):
            raise RegistryError("BAD_KIND", show(n.kind))
        if type(n.solid) is not bool:
            raise RegistryError("BAD_SOLID", n.name)
        if n.bounds is not None and not isinstance(n.bounds, AABB):
            raise RegistryError("BAD_BOUNDS", n.name)
        sn = self.subnet(n.subnet)
        if sn is None:
            raise RegistryError("UNKNOWN_SUBNET", f"{n.name}: {show(n.subnet)}")
        ip = parse_host(n.ip)
        if str(ip) != n.ip or not sn.usable(ip):
            raise RegistryError("IP_NOT_USABLE", f"{n.name}: {show(n.ip)}")
        if n.path is not None:
            try:
                lexical_segments(n.path)
            except PathError as e:
                raise RegistryError("BAD_PATH", f"{n.name}: {e.code}") from None
        if n.name in self._nodes:
            raise RegistryError("DUPLICATE_NAME", n.name)
        if n.name.casefold() in self._fold:
            raise RegistryError("DUPLICATE_NAME", f"{n.name} collides with {self._fold[n.name.casefold()]} (case-insensitive)")
        if n.ip in self._by_ip:
            raise RegistryError("DUPLICATE_IP", f"{n.ip} already bound to {self._by_ip[n.ip]}")
        if len(self._nodes) >= MAX_NODES:
            raise RegistryError("TOO_MANY_NODES", str(MAX_NODES))

    def _insert(self, n: Node) -> None:
        self._nodes[n.name] = n
        self._by_ip[n.ip] = n.name
        self._fold[n.name.casefold()] = n.name

    def validate(self) -> List[str]:
        """Full consistency report for a registry that was built or mutated by hand."""
        errs: List[str] = []
        probe = Registry()
        probe._subnets = dict(self._subnets)
        for n in self._nodes.values():
            try:
                probe._check_node(n)
                probe._insert(n)
            except BusError as e:
                errs.append(str(e))
        for n in self._nodes.values():
            if n.bounds is not None:
                for code, detail in self.placement_problems(n.subnet, n.bounds, ignore=n.name, solid=n.solid):
                    errs.append(f"{code}: {n.name}: {detail}")
        return errs

    # ---- serialization ----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        subs = {}
        for c, s in self._subnets.items():
            d: Dict[str, Any] = {"label": s.label, "reserved_below": s.reserved_below}
            if s.world is not None:
                d["world"] = s.world.to_dict()
            subs[c] = d
        return {"registry_version": REGISTRY_VERSION, "revision": self.revision,
                "subnets": subs, "nodes": {n: v.to_dict() for n, v in self._nodes.items()}}

    def fingerprint(self) -> str:
        d = self.to_dict()
        d.pop("revision")
        return hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @classmethod
    def from_dict(cls, d: Any) -> "Registry":
        errs: List[str] = []

        def bad(msg: str) -> None:
            errs.append(msg)

        if type(d) is not dict or set(d) != {"registry_version", "revision", "subnets", "nodes"}:
            raise RegistryError("INVALID_REGISTRY", "top level must have exactly registry_version, revision, subnets, nodes")
        if type(d["registry_version"]) is not str or d["registry_version"].split(".")[0] != REGISTRY_VERSION.split(".")[0]:
            raise RegistryError("INVALID_REGISTRY", f"unsupported registry_version {show(d['registry_version'])}")
        if type(d["revision"]) is not int or d["revision"] < 0:
            raise RegistryError("INVALID_REGISTRY", "revision must be a non-negative int")
        if type(d["subnets"]) is not dict or type(d["nodes"]) is not dict:
            raise RegistryError("INVALID_REGISTRY", "subnets and nodes must be objects")
        if len(d["nodes"]) > MAX_NODES:
            raise RegistryError("TOO_MANY_NODES", str(MAX_NODES))
        reg = cls()
        for cidr, sd in d["subnets"].items():
            try:
                if type(sd) is not dict or not set(sd) <= {"label", "reserved_below", "world"}:
                    raise RegistryError("BAD_SUBNET", f"{show(cidr)}: unknown or malformed fields")
                world = AABB.from_dict(sd["world"]) if "world" in sd else None
                reg._subnets[cidr] = Subnet(cidr, sd.get("label", ""), sd.get("reserved_below", 10), world)
            except BusError as e:
                bad(str(e))
        for name, nd in d["nodes"].items():
            try:
                if type(nd) is not dict or not {"ip", "subnet"} <= set(nd) <= {"ip", "subnet", "kind", "bounds", "solid", "path"}:
                    raise RegistryError("BAD_NODE", f"{show(name)}: unknown or missing fields")
                node = Node(name, nd["ip"], nd["subnet"], nd.get("kind", "scene_node"),
                            AABB.from_dict(nd["bounds"]) if "bounds" in nd else None,
                            nd.get("solid", True), nd.get("path"))
                reg._check_node(node)
                reg._insert(node)
            except BusError as e:
                bad(str(e))
        if not errs:
            errs.extend(reg.validate())
        if errs:
            raise RegistryError("INVALID_REGISTRY", "; ".join(errs[:20]))
        reg.revision = d["revision"]
        return reg

    @classmethod
    def loads(cls, text: str) -> "Registry":
        try:
            data = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_const)
        except BusError:
            raise
        except (ValueError, RecursionError) as e:
            raise RegistryError("BAD_JSON", type(e).__name__) from None
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: "str | os.PathLike") -> "Registry":
        p = Path(path)
        if p.stat().st_size > MAX_FILE_BYTES:
            raise RegistryError("FILE_TOO_LARGE", str(MAX_FILE_BYTES))
        try:
            text = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise RegistryError("BAD_JSON", "not valid UTF-8") from None
        return cls.loads(text)

    def save(self, path: "str | os.PathLike") -> None:
        """Atomic: write temp file, fsync, rename. Refuses to persist an inconsistent registry."""
        errs = self.validate()
        if errs:
            raise RegistryError("INVALID_REGISTRY", "; ".join(errs[:20]))
        p = Path(path)
        tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(self.to_dict(), indent=2) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        finally:
            if tmp.exists():
                tmp.unlink()
        try:
            fd = os.open(p.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
