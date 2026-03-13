from __future__ import annotations

from aisecops_interceptor.policy.loader import PolicyLoader
from aisecops_interceptor.policy.schema import CapabilityBundle


def load_capability_bundle(path: str) -> CapabilityBundle:
    return PolicyLoader.from_capabilities_yaml(path)
