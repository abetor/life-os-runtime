"""Fail-closed capability probes for external Life OS tools.

The module is intentionally not registered in the central CLI.  P1 doctor can
consume :func:`probe_all` after its config contract is implemented.
"""

from .capabilities import (
    DEFAULT_SPECS,
    CapabilityContract,
    MachineOutputContract,
    ProbeRecord,
    ProbeSpec,
    probe_all,
    probe_tool,
)

__all__ = [
    "DEFAULT_SPECS",
    "CapabilityContract",
    "MachineOutputContract",
    "ProbeRecord",
    "ProbeSpec",
    "probe_all",
    "probe_tool",
]
