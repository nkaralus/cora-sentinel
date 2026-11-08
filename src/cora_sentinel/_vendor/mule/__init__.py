"""Mule Protocol: deterministic validation of slotted JSON task blocks."""
import json
from importlib import resources

__version__ = "0.2.0"


def load_spec() -> dict:
    """Load the packaged spec (works from a wheel, not just a checkout).

    Resolved from THIS package (__name__), not by the name "mule": a copy vendored under another package must read
    its own spec, never fail or silently read the spec of some other mule that happens to be installed."""
    with resources.files(__name__).joinpath("spec/mule_spec.json").open("r", encoding="utf-8") as f:
        return json.load(f)


from .validator import MuleValidator  # noqa: E402

__all__ = ["MuleValidator", "load_spec", "__version__"]
