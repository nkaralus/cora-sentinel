"""2D axis-aligned bounding boxes and the pre-commit overlap guard."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Tuple

from .errors import BusError

__all__ = ["AABB", "find_overlaps", "MAX_COORD", "OVERLAP_TOLERANCE"]

MAX_COORD = 1.0e7
OVERLAP_TOLERANCE = 1.0e-6   # px. Touching edges are not an overlap.


def _num(v: Any, field: str) -> float:
    if type(v) not in (int, float):          # rejects bool, str, None
        raise BusError("BAD_BOUNDS", f"{field} must be a number")
    f = float(v)
    if not math.isfinite(f) or abs(f) > MAX_COORD:
        raise BusError("BAD_BOUNDS", f"{field} out of range")
    return f


@dataclass(frozen=True)
class AABB:
    x: float
    y: float
    w: float
    h: float

    def __post_init__(self):
        for f in ("x", "y", "w", "h"):
            object.__setattr__(self, f, _num(getattr(self, f), f))
        if self.w <= 0 or self.h <= 0:
            raise BusError("BAD_BOUNDS", "w and h must be > 0")

    @property
    def right(self) -> float:
        return self.x + self.w

    @property
    def bottom(self) -> float:
        return self.y + self.h

    def overlap_depth(self, o: "AABB") -> Tuple[float, float]:
        ox = min(self.right, o.right) - max(self.x, o.x)
        oy = min(self.bottom, o.bottom) - max(self.y, o.y)
        return max(ox, 0.0), max(oy, 0.0)

    def intersects(self, o: "AABB", tolerance: float = OVERLAP_TOLERANCE) -> bool:
        ox, oy = self.overlap_depth(o)
        return ox > tolerance and oy > tolerance

    def contains(self, o: "AABB", tolerance: float = OVERLAP_TOLERANCE) -> bool:
        return (o.x >= self.x - tolerance and o.y >= self.y - tolerance
                and o.right <= self.right + tolerance and o.bottom <= self.bottom + tolerance)

    def to_dict(self) -> dict:
        return {"x": self.x, "y": self.y, "w": self.w, "h": self.h}

    @classmethod
    def from_dict(cls, d: Any) -> "AABB":
        if type(d) is not dict or set(d) != {"x", "y", "w", "h"}:
            raise BusError("BAD_BOUNDS", "bounds must be an object with exactly x, y, w, h")
        return cls(d["x"], d["y"], d["w"], d["h"])


def find_overlaps(
    proposed: AABB, others: Iterable[Tuple[str, AABB]], tolerance: float = OVERLAP_TOLERANCE
) -> List[Tuple[str, float]]:
    """Return [(name, penetration_depth)] for every box that overlaps `proposed`,
    deepest first. Depth is the smaller axis overlap (the minimum translation)."""
    hits = []
    for name, box in others:
        ox, oy = proposed.overlap_depth(box)
        if ox > tolerance and oy > tolerance:
            hits.append((name, min(ox, oy)))
    return sorted(hits, key=lambda t: (-t[1], t[0]))
