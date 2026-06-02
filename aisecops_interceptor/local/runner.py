from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import DryRunResult, InstructionProvenance, InterceptionRequest, RuntimeUsage
from aisecops_interceptor.core.policy import PolicyEngine


@dataclass(slots=True)
class LocalEnforcementResult:
    status: str
    decision: str
    reason: str
    trace_id: str
    audit_log: str
    dry_run: bool
    data: dict[str, Any] | None = None
    warnings: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload["warnings"]:
            payload.pop("warnings")
        if payload["data"] is None:
            payload.pop("data")
        return payload


class LocalEnforcementRunner:
    def __init__(
        self,
        *,
        policy_path: str | None = None,
        capabilities_path: str | None = None,
        audit_log_path: str,
        tool_registry: dict[str, Callable[..., Any]] | None = None,
    ) -> None:
        self.audit_log_path = str(audit_log_path)
        self.warnings: list[str] = []
        self.policy_engine = PolicyEngine.from_yaml(policy_path)
        self.capability_registry = self._load_capabilities(capabilities_path)
        self.audit_logger = AuditLogger(log_path=self.audit_log_path)
        self.approval_store = ApprovalStore()
        self.interceptor = AgentInterceptor(
            policy_engine=self.policy_engine,
            audit_logger=self.audit_logger,
            approval_store=self.approval_store,
            capability_registry=self.capability_registry,
        )
        self.tool_registry = tool_registry or default_local_tool_registry()

    def run(
        self,
        *,
        agent_name: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        dry_run: bool = False,
        approval_id: str | None = None,
        provenance: list[InstructionProvenance] | None = None,
        allowed_capabilities: list[str] | None = None,
        runtime_usage: RuntimeUsage | None = None,
    ) -> LocalEnforcementResult:
        context = RuntimeContext(
            agent_name=agent_name,
            tool_name=tool_name,
            arguments=arguments or {},
            framework="local",
            provenance=provenance or self.default_provenance(agent_name),
            allowed_capabilities=allowed_capabilities,
            runtime_usage=runtime_usage,
        )
        request = InterceptionRequest(
            context=context,
            tool_registry=self.tool_registry,
            approval_id=approval_id,
            dry_run=dry_run,
        )

        try:
            result = self.interceptor.intercept(request)
        except ApprovalRequiredError as exc:
            return LocalEnforcementResult(
                status="require_approval",
                decision="require_approval",
                reason=str(exc),
                trace_id=context.ensure_trace_id(),
                audit_log=self.audit_log_path,
                dry_run=dry_run,
                data={"approval_id": exc.approval_id},
                warnings=list(self.warnings),
            )
        except PolicyViolationError as exc:
            return LocalEnforcementResult(
                status="blocked",
                decision="block",
                reason=str(exc),
                trace_id=context.ensure_trace_id(),
                audit_log=self.audit_log_path,
                dry_run=dry_run,
                warnings=list(self.warnings),
            )
        except ToolNotFoundError as exc:
            return LocalEnforcementResult(
                status="blocked",
                decision="block",
                reason=str(exc),
                trace_id=context.ensure_trace_id(),
                audit_log=self.audit_log_path,
                dry_run=dry_run,
                warnings=list(self.warnings),
            )

        if isinstance(result, DryRunResult):
            decision = "require_approval" if result.would_require_approval else ("block" if result.would_block else "allow")
            status = "dry_run"
            return LocalEnforcementResult(
                status=status,
                decision=decision,
                reason=result.reason,
                trace_id=context.ensure_trace_id(),
                audit_log=self.audit_log_path,
                dry_run=True,
                data=asdict(result),
                warnings=list(self.warnings),
            )

        return LocalEnforcementResult(
            status="success",
            decision="allow",
            reason="Tool executed locally",
            trace_id=context.ensure_trace_id(),
            audit_log=self.audit_log_path,
            dry_run=False,
            data=result if isinstance(result, dict) else {"result": result},
            warnings=list(self.warnings),
        )

    @staticmethod
    def default_provenance(agent_name: str) -> list[InstructionProvenance]:
        return [
            InstructionProvenance(
                source_type="local_agent",
                source_name=agent_name,
                trust_level="internal",
            )
        ]

    def _load_capabilities(self, capabilities_path: str | None) -> CapabilityRegistry:
        try:
            return CapabilityRegistry.from_yaml(capabilities_path)
        except FileNotFoundError:
            if capabilities_path is None:
                self.warnings.append("Default capability bundle not found; capability metadata disabled")
                return CapabilityRegistry()
            raise


def default_local_tool_registry() -> dict[str, Callable[..., Any]]:
    return {
        "read_customer": lambda customer_id: {"customer_id": customer_id, "status": "active"},
        "get_deployment_status": lambda service: {"service": service, "status": "green"},
        "create_incident": lambda service, severity: {
            "service": service,
            "severity": severity,
            "ticket": "LOCAL-INC-1",
        },
        "restart_service": lambda service: {"service": service, "status": "restart_simulated"},
        "send_email": lambda to, subject, body: {
            "status": "queued_simulated",
            "to": to,
            "subject": subject,
            "body": body,
        },
    }


def ensure_audit_parent(path: str) -> None:
    parent = Path(path).parent
    if str(parent) in {"", "."}:
        return
    parent.mkdir(parents=True, exist_ok=True)
