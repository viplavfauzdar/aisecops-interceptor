from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from uuid import uuid4

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import DryRunResult, InstructionProvenance, InterceptionRequest
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.mcp.adapter import capability_for_mcp_tool, mcp_capability_mapping
from aisecops_interceptor.mcp.models import MCPDecision, MCPInvocation


class MCPPolicyProxy:
    def __init__(
        self,
        *,
        policy_path: str | None = None,
        audit_log_path: str = "logs/mcp-audit.jsonl",
    ) -> None:
        self.policy_engine = PolicyEngine.from_yaml(policy_path)
        self.audit_logger = AuditLogger(log_path=audit_log_path)
        self.approval_store = ApprovalStore()
        self.audit_log_path = audit_log_path

    def evaluate(self, invocation: MCPInvocation) -> MCPDecision:
        capability, unknown_tool = capability_for_mcp_tool(invocation.tool_name)
        context = RuntimeContext(
            agent_name=invocation.client_id,
            session_id=invocation.session_id,
            tool_name=invocation.tool_name,
            arguments=invocation.arguments,
            framework="mcp",
            source=invocation.server_name,
            provenance=invocation.provenance or self.default_provenance(invocation),
            allowed_capabilities=[capability],
            metadata={
                "protocol": "mcp",
                "client_id": invocation.client_id,
                "server_name": invocation.server_name,
                "capability": capability,
            },
        )
        interceptor = AgentInterceptor(
            policy_engine=self.policy_engine,
            audit_logger=self.audit_logger,
            approval_store=self.approval_store,
            capability_registry=CapabilityRegistry(mcp_capability_mapping(invocation.tool_name)),
        )
        request = InterceptionRequest(
            context=context,
            tool_registry={invocation.tool_name: lambda **_kwargs: None},
            dry_run=True,
        )
        plan = interceptor.plan(request)
        trace = interceptor.evaluate(plan)
        dry_run_result = interceptor.execute_plan(plan)
        if not isinstance(dry_run_result, DryRunResult):
            raise RuntimeError("MCP policy proxy expected dry-run evaluation result")

        allowed = dry_run_result.would_allow
        risk_level = (
            trace.policy_decision.risk_level
            if trace.policy_decision is not None
            else ("medium" if trace.capability_result == "blocked" else "low")
        )
        reason = dry_run_result.reason
        decision = MCPDecision(
            allowed=allowed,
            reason=reason,
            risk_level=risk_level,
            capability=capability,
            trace_id=context.ensure_trace_id(),
        )
        self.audit_logger.log(
            RuntimeEvent.audit_event(
                event_type="mcp_policy_decision",
                decision="allowed" if allowed else "blocked",
                reason=reason,
                stage="tool",
                context=context,
                risk_level=risk_level,
                execution_plan_id=plan.execution_plan_id,
                plan_id=plan.structured_plan.plan_id if plan.structured_plan is not None else None,
                plan_intent=plan.structured_plan.intent if plan.structured_plan is not None else None,
                plan_risk_level=plan.structured_plan.risk_level if plan.structured_plan is not None else None,
                requested_capabilities=(
                    list(plan.structured_plan.requested_capabilities)
                    if plan.structured_plan is not None
                    else None
                ),
                plan_steps=(
                    [step.model_dump() for step in plan.structured_plan.steps]
                    if plan.structured_plan is not None
                    else None
                ),
                decision_stage="mcp_policy",
                capabilities=[capability],
                provenance=context.provenance,
                protocol="mcp",
                client_id=invocation.client_id,
                server_name=invocation.server_name,
                capability=capability,
                payload={
                    "protocol": "mcp",
                    "client_id": invocation.client_id,
                    "server_name": invocation.server_name,
                    "tool_name": invocation.tool_name,
                    "decision": "allowed" if allowed else "blocked",
                    "capability": capability,
                    "unknown_tool": unknown_tool,
                    "warning": (
                        f"Unknown MCP tool '{invocation.tool_name}' preserved as capability"
                        if unknown_tool
                        else None
                    ),
                },
            )
        )
        return decision

    def allow(self, invocation: MCPInvocation) -> bool:
        return self.evaluate(invocation).allowed

    def block(self, invocation: MCPInvocation) -> bool:
        return not self.evaluate(invocation).allowed

    @staticmethod
    def default_provenance(invocation: MCPInvocation) -> list[InstructionProvenance]:
        return [
            InstructionProvenance(
                source_type="mcp_client",
                source_name=invocation.client_id,
                trust_level="internal",
                metadata={"server_name": invocation.server_name},
            )
        ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisecops-mcp-proxy",
        description="Evaluate MCP tool invocations through AISecOps policy without executing them.",
    )
    parser.add_argument("--policy", help="Path to the policy YAML file")
    parser.add_argument("--audit-log", default="logs/mcp-audit.jsonl", help="Replay-compatible JSONL audit log path")
    parser.add_argument("--session-id", help="MCP session ID")
    parser.add_argument("--client-id", required=True, help="MCP client ID")
    parser.add_argument("--server", required=True, help="MCP server name")
    parser.add_argument("--tool", required=True, help="MCP tool name")
    parser.add_argument("--args", default="{}", help="MCP tool arguments as a JSON object")
    return parser


def _load_args(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"args must be valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError("args must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        arguments = _load_args(args.args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    invocation = MCPInvocation(
        session_id=args.session_id or uuid4().hex,
        client_id=args.client_id,
        server_name=args.server,
        tool_name=args.tool,
        arguments=arguments,
    )
    try:
        decision = MCPPolicyProxy(
            policy_path=args.policy,
            audit_log_path=args.audit_log,
        ).evaluate(invocation)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("ALLOWED" if decision.allowed else "BLOCKED")
    print(decision.reason)
    return 0 if decision.allowed else 3


if __name__ == "__main__":
    raise SystemExit(main())
