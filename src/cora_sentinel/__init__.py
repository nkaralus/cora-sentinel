"""cora-sentinel: an out-of-band security sentinel for tasks running on Linux.

Deterministic detectors (cgroups, sock_diag, an NFLOG flow tap, blocklists) find anomalies; a small
local model (grammar-constrained) proposes a verdict; deterministic gates decide whether it may act.
See README.md.
"""

__version__ = "0.10.0"
