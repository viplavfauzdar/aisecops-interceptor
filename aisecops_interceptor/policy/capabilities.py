from __future__ import annotations

from aisecops_interceptor.policy.loader import PolicyLoader
from aisecops_interceptor.policy.schema import CapabilityBundle


def load_capability_bundle(path: str | None = None) -> CapabilityBundle:
    """Load capability mappings and capability metadata only."""
    return PolicyLoader.from_capabilities_yaml(path)
