"""Error types. Every error carries a machine-readable `code`."""
from __future__ import annotations

from typing import Any


def show(v: Any) -> str:
    """Bounded, ASCII-only rendering of untrusted values for messages and logs."""
    s = ascii(v)
    return s if len(s) <= 48 else s[:45] + "..."


class BusError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class RegistryError(BusError):
    pass


class PathError(BusError):
    pass
