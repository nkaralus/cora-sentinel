"""Virtual subnet bus: resource addressing, registry, and pre-execution safety gates."""
from .addressing import Subnet, parse_host, parse_subnet
from .errors import BusError, PathError, RegistryError
from .fsguard import PathGuard, active_mountpoints, lexical_segments
from .gates import Action, GateResult, Verdict, check_all, gi_1, gi_2, gi_3
from .geometry import AABB, find_overlaps
from .registry import Node, Registry

__version__ = "0.1.0"
__all__ = [
    "AABB", "Action", "BusError", "GateResult", "Node", "PathError", "PathGuard", "Registry",
    "RegistryError", "Subnet", "Verdict", "active_mountpoints", "check_all", "find_overlaps",
    "gi_1", "gi_2", "gi_3", "lexical_segments", "parse_host", "parse_subnet",
]
