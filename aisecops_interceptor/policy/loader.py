from __future__ import annotations

from pathlib import Path

import yaml

from aisecops_interceptor.policy.schema import (
    CapabilityBundle,
    PolicyBundle,
    parse_capability_bundle,
    parse_policy_bundle,
)


class PolicyLoader:
    @staticmethod
    def from_yaml(path: str) -> PolicyBundle:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return parse_policy_bundle(data)

    @staticmethod
    def from_capabilities_yaml(path: str) -> CapabilityBundle:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return parse_capability_bundle(data)
