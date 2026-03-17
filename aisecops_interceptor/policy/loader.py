from __future__ import annotations

from pathlib import Path

import yaml

from aisecops_interceptor.policy.schema import (
    CapabilityBundle,
    PolicyBundle,
    parse_capability_bundle,
    parse_policy_bundle,
)

DEFAULT_POLICY_BUNDLE_PATH = Path("policies/policies.yaml")
DEFAULT_CAPABILITY_BUNDLE_PATH = Path("policies/capabilities.yaml")


class PolicyLoader:
    @staticmethod
    def from_yaml(path: str | None = None) -> PolicyBundle:
        """Load policy behavior from the canonical external policy bundle."""
        resolved_path = Path(path) if path is not None else DEFAULT_POLICY_BUNDLE_PATH
        data = yaml.safe_load(resolved_path.read_text(encoding="utf-8"))
        return parse_policy_bundle(data)

    @staticmethod
    def from_capabilities_yaml(path: str | None = None) -> CapabilityBundle:
        """Load capability mappings from the canonical external capability bundle."""
        resolved_path = Path(path) if path is not None else DEFAULT_CAPABILITY_BUNDLE_PATH
        data = yaml.safe_load(resolved_path.read_text(encoding="utf-8"))
        return parse_capability_bundle(data)
