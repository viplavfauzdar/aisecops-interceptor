from __future__ import annotations

from dataclasses import asdict

from fastapi import Body, FastAPI, HTTPException
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse, RedirectResponse

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import (
    ApprovalRequiredResponse,
    BlockedResponse,
    DryRunResultModel,
    ExecuteAllowedResponse,
    ExecuteDryRunResponse,
    ExplainResponse,
    InterceptionRequest,
    ToolCall,
    ToolNotFoundResponse,
)
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.integrations.openclaw_adapter import OpenClawToolRunnerAdapter

app = FastAPI(title="AISecOps Interceptor", version="0.3.0")
policy = PolicyEngine.from_yaml_file()
audit = AuditLogger(log_path="audit/audit.jsonl")
approvals = ApprovalStore(store_path="audit/approvals.jsonl")
interceptor = AgentInterceptor(policy_engine=policy, audit_logger=audit, approval_store=approvals)
openclaw_adapter = OpenClawToolRunnerAdapter(interceptor=interceptor)


def read_customer(customer_id: str) -> dict[str, str]:
    return {"customer_id": customer_id, "status": "active"}


def send_email(to: str, subject: str, body: str) -> dict[str, str]:
    return {"status": "queued", "to": to, "subject": subject, "body": body}


def get_deployment_status(service: str) -> dict[str, str]:
    return {"service": service, "status": "green"}


def create_incident(service: str, severity: str) -> dict[str, str]:
    return {"service": service, "severity": severity, "ticket": "INC-1001"}


def restart_service(service: str) -> dict[str, str]:
    return {"service": service, "status": "restarted"}


def shell_exec(command: str) -> dict[str, str]:
    return {"command": command, "status": "simulated"}


tool_registry = {
    "read_customer": read_customer,
    "send_email": send_email,
    "get_deployment_status": get_deployment_status,
    "create_incident": create_incident,
    "restart_service": restart_service,
    "shell_exec": shell_exec,
}

EXECUTE_REQUEST_EXAMPLES = {
    "safe_tool_execution": {
        "summary": "Safe tool execution",
        "description": "A normal allowed request that executes immediately.",
        "value": {
            "agent_name": "sales_agent",
            "tool_name": "read_customer",
            "arguments": {"customer_id": "123"},
            "dry_run": False,
        },
    },
    "approval_required_tool": {
        "summary": "Approval-required tool",
        "description": "A high-risk or policy-gated tool that requires approval.",
        "value": {
            "agent_name": "ops_agent",
            "tool_name": "restart_service",
            "arguments": {"service": "orders"},
            "dry_run": False,
        },
    },
    "dry_run_request": {
        "summary": "Dry-run request",
        "description": "Evaluate the request without executing the tool.",
        "value": {
            "agent_name": "ops_agent",
            "tool_name": "restart_service",
            "arguments": {"service": "orders"},
            "dry_run": True,
        },
    },
}

EXECUTE_RESPONSES = {
    200: {
        "description": "Allowed execution or dry-run decision",
        "content": {
            "application/json": {
                "examples": {
                    "allowed_execution": {
                        "summary": "Allowed execution",
                        "value": {
                            "status": "allowed",
                            "result": {"customer_id": "123", "status": "active"},
                        },
                    },
                    "dry_run_result": {
                        "summary": "Dry-run result",
                        "value": {
                            "status": "dry_run",
                            "result": {
                                "would_allow": False,
                                "would_block": False,
                                "would_require_approval": True,
                                "reason": "Tool 'restart_service' requires human approval",
                            },
                        },
                    },
                }
            }
        },
    },
    202: {
        "description": "Approval required",
        "model": ApprovalRequiredResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "approval_required",
                    "decision": "require_approval",
                    "reason": "Tool 'restart_service' requires human approval",
                    "approval_id": "apr-demo123456",
                }
            }
        },
    },
    403: {
        "description": "Blocked by policy or capability gate",
        "model": BlockedResponse,
        "content": {
            "application/json": {
                "examples": {
                    "policy_block": {
                        "summary": "Blocked by policy",
                        "value": {
                            "status": "blocked",
                            "decision": "blocked",
                            "reason": "Tool 'shell_exec' is globally blocked",
                        },
                    },
                    "capability_block": {
                        "summary": "Blocked by capability gate",
                        "value": {
                            "status": "blocked",
                            "decision": "blocked",
                            "reason": "Tool 'restart_service' requires one of the granted capabilities: cap_service_ops",
                        },
                    },
                }
            }
        },
    },
    404: {
        "description": "Tool not found",
        "model": ToolNotFoundResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "not_found",
                    "decision": "not_found",
                    "reason": "Tool 'missing_tool' not found",
                }
            }
        },
    },
}

EXPLAIN_RESPONSES = {
    200: {
        "description": "Structured decision trace",
        "content": {
            "application/json": {
                "examples": {
                    "require_approval": {
                        "summary": "Approval-required decision",
                        "value": {
                            "decision": "require_approval",
                            "reason_chain": [
                                "Capability gate skipped because no capabilities were provided",
                                "Tool 'restart_service' requires human approval",
                            ],
                            "capability_result": "not_applicable",
                            "policy_result": "require_approval",
                            "final_decision": "require_approval",
                            "capability_metadata": {
                                "cap_service_ops": {
                                    "tools": ["restart_service", "stop_service"],
                                    "description": "Manage service lifecycle operations",
                                    "risk": "high",
                                }
                            },
                        },
                    },
                    "blocked": {
                        "summary": "Blocked decision",
                        "value": {
                            "decision": "blocked",
                            "reason_chain": [
                                "Capability gate skipped because no capabilities were provided",
                                "Tool 'delete_database' is globally blocked",
                            ],
                            "capability_result": "not_applicable",
                            "policy_result": "blocked",
                            "final_decision": "blocked",
                        },
                    },
                    "allowed": {
                        "summary": "Allowed decision",
                        "value": {
                            "decision": "allowed",
                            "reason_chain": [
                                "Capability gate skipped because no capabilities were provided",
                                "Tool 'read_customer' is allowed",
                            ],
                            "capability_result": "not_applicable",
                            "policy_result": "allowed",
                            "final_decision": "allowed",
                        },
                    },
                }
            }
        },
    },
    404: {
        "description": "Tool not found",
        "model": ToolNotFoundResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "not_found",
                    "decision": "not_found",
                    "reason": "Tool 'missing_tool' not found",
                }
            }
        },
    },
}


class ExecuteRequest(BaseModel):
    agent_name: str = Field(..., examples=["sales_agent"])
    tool_name: str = Field(..., examples=["read_customer"])
    arguments: dict = Field(default_factory=dict)
    approval_id: str | None = None
    dry_run: bool = False


class ApprovalReviewRequest(BaseModel):
    reviewed_by: str
    note: str | None = None


class OpenClawExecuteRequest(BaseModel):
    agent_name: str | None = None
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    approval_id: str | None = None
    correlation_id: str | None = None


def _approval_required_response(exc: ApprovalRequiredError) -> JSONResponse:
    return JSONResponse(
        status_code=202,
        content=ApprovalRequiredResponse(
            status="approval_required",
            decision="require_approval",
            reason=str(exc),
            approval_id=exc.approval_id,
        ).model_dump(),
    )


def _blocked_response(exc: PolicyViolationError) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content=BlockedResponse(
            status="blocked",
            decision="blocked",
            reason=str(exc),
        ).model_dump(),
    )


def _tool_not_found_response(tool_name: str) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content=ToolNotFoundResponse(
            status="not_found",
            decision="not_found",
            reason=f"Tool '{tool_name}' not found",
        ).model_dump(),
    )


@app.post(
    "/execute",
    responses=EXECUTE_RESPONSES,
    response_model=ExecuteAllowedResponse | ExecuteDryRunResponse,
)
def execute(request: ExecuteRequest = Body(..., openapi_examples=EXECUTE_REQUEST_EXAMPLES)) -> dict:
    try:
        result = interceptor.execute(
            agent_name=request.agent_name,
            tool_call=ToolCall(name=request.tool_name, arguments=request.arguments),
            tool_registry=tool_registry,
            approval_id=request.approval_id,
            dry_run=request.dry_run,
        )
        if request.dry_run:
            return ExecuteDryRunResponse(
                status="dry_run",
                result=DryRunResultModel.model_validate(asdict(result)),
            ).model_dump()
        return ExecuteAllowedResponse(status="allowed", result=result).model_dump()
    except ApprovalRequiredError as exc:
        return _approval_required_response(exc)
    except PolicyViolationError as exc:
        return _blocked_response(exc)
    except ToolNotFoundError:
        return _tool_not_found_response(request.tool_name)


@app.post("/explain", responses=EXPLAIN_RESPONSES, response_model=ExplainResponse)
def explain(request: ExecuteRequest = Body(..., openapi_examples=EXECUTE_REQUEST_EXAMPLES)) -> dict:
    if request.tool_name not in tool_registry:
        return _tool_not_found_response(request.tool_name)

    trace = interceptor.explain(
        InterceptionRequest(
            context=interceptor_context_from_request(request),
            tool_registry=tool_registry,
            approval_id=request.approval_id,
            dry_run=request.dry_run,
        )
    )
    return ExplainResponse(
        decision=trace.decision,
        reason_chain=trace.reason_chain,
        capability_result=trace.capability_result,
        policy_result=trace.policy_result,
        final_decision=trace.final_decision,
        capability_metadata=(
            {
                capability: asdict(definition)
                for capability, definition in trace.capability_metadata.items()
            }
            if trace.capability_metadata is not None
            else None
        ),
    ).model_dump()


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}




@app.post("/approvals/{approval_id}/approve")
def approve(approval_id: str, request: ApprovalReviewRequest) -> dict:
    try:
        approval = approvals.approve(approval_id, reviewed_by=request.reviewed_by, note=request.note)
        return {"status": approval.status, "approval_id": approval.approval_id}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/approvals/{approval_id}/reject")
def reject(approval_id: str, request: ApprovalReviewRequest) -> dict:
    try:
        approval = approvals.reject(approval_id, reviewed_by=request.reviewed_by, note=request.note)
        return {"status": approval.status, "approval_id": approval.approval_id}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/approvals")
def list_approvals() -> list[dict]:
    return [asdict(item) for item in approvals.list_requests()]


@app.post("/openclaw/execute")
def execute_openclaw(request: OpenClawExecuteRequest) -> dict:
    payload = request.model_dump(exclude_none=True)
    try:
        result = openclaw_adapter.run(payload, tool_registry=tool_registry, approval_id=request.approval_id)
        return {"status": "allowed", "result": result}
    except ApprovalRequiredError as exc:
        raise HTTPException(status_code=202, detail={"message": str(exc), "approval_id": exc.approval_id}) from exc
    except PolicyViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ToolNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def interceptor_context_from_request(request: ExecuteRequest) -> RuntimeContext:
    return RuntimeContext(
        agent_name=request.agent_name,
        tool_name=request.tool_name,
        arguments=request.arguments,
        framework="legacy",
    )


@app.get("/audit")
def get_audit(
    event_type: str | None = None,
    stage: str | None = None,
    agent_name: str | None = None,
    tool_name: str | None = None,
    correlation_id: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    return [
        event.to_dict()
        for event in audit.query_persisted_events(
            event_type=event_type,
            stage=stage,
            agent_name=agent_name,
            tool_name=tool_name,
            correlation_id=correlation_id,
            limit=limit,
        )
    ]


@app.get("/audit/failures")
def get_audit_failures(
    sink_type: str | None = None,
    event_type: str | None = None,
    error_type: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    return [
        asdict(item)
        for item in audit.query_sink_failures(
            sink_type=sink_type,
            event_type=event_type,
            error_type=error_type,
            limit=limit,
        )
    ]
