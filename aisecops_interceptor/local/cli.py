from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from aisecops_interceptor.core.models import InstructionProvenance, RuntimeUsage
from aisecops_interceptor.local.runner import LocalEnforcementRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisecops-local",
        description="Evaluate and optionally execute local agent tool calls through AISecOps enforcement.",
    )
    parser.add_argument("--policy", required=True, help="Path to the policy YAML file")
    parser.add_argument("--capabilities", help="Path to the capability YAML file")
    parser.add_argument("--agent-name", required=True, help="Local agent name")
    parser.add_argument("--tool-name", required=True, help="Requested tool name")
    parser.add_argument("--args", default="{}", help="Tool arguments as a JSON object")
    parser.add_argument("--audit-log", required=True, help="Local JSONL audit log path")
    parser.add_argument("--dry-run", action="store_true", help="Evaluate without executing the tool")
    parser.add_argument(
        "--allowed-capability",
        action="append",
        dest="allowed_capabilities",
        help="Granted capability name; may be provided multiple times",
    )
    parser.add_argument("--provenance", help="Instruction provenance as a JSON array")
    parser.add_argument("--runtime-usage", help="Runtime usage as a JSON object")
    return parser


def _load_json_object(raw: str, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _load_provenance(raw: str | None) -> list[InstructionProvenance] | None:
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"provenance must be valid JSON: {exc.msg}") from exc
    if not isinstance(value, list):
        raise ValueError("provenance must be a JSON array")
    return [
        item if isinstance(item, InstructionProvenance) else InstructionProvenance.from_dict(item)
        for item in value
    ]


def _load_runtime_usage(raw: str | None) -> RuntimeUsage | None:
    if raw is None:
        return None
    return RuntimeUsage(**_load_json_object(raw, label="runtime-usage"))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        tool_args = _load_json_object(args.args, label="args")
        provenance = _load_provenance(args.provenance)
        runtime_usage = _load_runtime_usage(args.runtime_usage)
    except (TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        runner = LocalEnforcementRunner(
            policy_path=args.policy,
            capabilities_path=args.capabilities,
            audit_log_path=args.audit_log,
        )
        result = runner.run(
            agent_name=args.agent_name,
            tool_name=args.tool_name,
            arguments=tool_args,
            dry_run=args.dry_run,
            provenance=provenance,
            allowed_capabilities=args.allowed_capabilities,
            runtime_usage=runtime_usage,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
