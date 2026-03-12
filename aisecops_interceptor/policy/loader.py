from __future__ import annotations

from pathlib import Path

import yaml

from aisecops_interceptor.policy.schema import PolicyBundle, parse_policy_bundle


class PolicyLoader:
    @staticmethod
    def from_yaml(path: str) -> PolicyBundle:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return parse_policy_bundle(data)
