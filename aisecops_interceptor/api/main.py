from __future__ import annotations

from dataclasses import asdict

from fastapi import Body, FastAPI, HTTPException
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse, RedirectResponse

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import (
    APIResponse,
    DryRunResultModel,
    ExplainTraceModel,
    InterceptionRequest,
    ToolCall,
)
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.integrations.openclaw_adapter import OpenClawToolRunnerAdapter

app = FastAPI(title="AISecOps Interceptor", version="0.3.0")
policy = PolicyEngine.from_yaml_file()
audit = AuditLogger(log_path="audit/audit.jsonl")
approvals = ApprovalStore(store_path="audit/approvals.jsonl")
capabilities = CapabilityRegistry.from_yaml()
interceptor = AgentInterceptor(
    policy_engine=policy,
    audit_logger=audit,
    approval_store=approvals,
    capability_registry=capabilities,
)
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
        "model": APIResponse,
        "content": {
            "application/json": {
                "examples": {
                    "allowed_execution": {
                        "summary": "Allowed execution",
                        "value": {
                            "status": "success",
                            "decision": "allow",
                            "reason": "Tool 'read_customer' allowed with audit monitoring",
                            "data": {"customer_id": "123", "status": "active"},
                            "trace": {
                                "reason_chain": [
                                    "Capability gate skipped because no capabilities were provided",
                                    "Capability cap_customer_read (risk: medium) governs access to read_customer",
                                    "Tool 'read_customer' allowed with audit monitoring",
                                ],
                                "capability_result": "not_applicable",
                                "policy_result": "allowed",
                                "final_decision": "allowed",
                            },
                        },
                    },
                    "dry_run_result": {
                        "summary": "Dry-run result",
                        "value": {
                            "status": "dry_run",
                            "decision": "require_approval",
                            "reason": "Tool 'restart_service' requires human approval",
                            "data": {
                                "would_allow": False,
                                "would_block": False,
                                "would_require_approval": True,
                                "reason": "Tool 'restart_service' requires human approval",
                            },
                            "trace": {
                                "reason_chain": [
                                    "Capability gate skipped because no capabilities were provided",
                                    "Capability cap_service_ops (risk: high) governs access to restart_service",
                                    "Tool 'restart_service' requires human approval",
                                ],
                                "capability_result": "not_applicable",
                                "policy_result": "require_approval",
                                "final_decision": "require_approval",
                            },
                        },
                    },
                }
            }
        },
    },
    202: {
        "description": "Approval required",
        "model": APIResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "require_approval",
                    "decision": "require_approval",
                    "reason": "Tool 'restart_service' requires human approval",
                    "data": {"approval_id": "apr-demo123456"},
                    "trace": {
                        "reason_chain": [
                            "Capability gate skipped because no capabilities were provided",
                            "Capability cap_service_ops (risk: high) governs access to restart_service",
                            "Tool 'restart_service' requires human approval",
                        ],
                        "capability_result": "not_applicable",
                        "policy_result": "require_approval",
                        "final_decision": "require_approval",
                    },
                }
            }
        },
    },
    403: {
        "description": "Blocked by policy or capability gate",
        "model": APIResponse,
        "content": {
            "application/json": {
                "examples": {
                    "policy_block": {
                        "summary": "Blocked by policy",
                        "value": {
                            "status": "blocked",
                            "decision": "block",
                            "reason": "Tool 'shell_exec' is globally blocked",
                            "data": None,
                        },
                    },
                    "capability_block": {
                        "summary": "Blocked by capability gate",
                        "value": {
                            "status": "blocked",
                            "decision": "block",
                            "reason": "Tool 'restart_service' requires one of the granted capabilities: cap_service_ops",
                            "data": None,
                        },
                    },
                }
            }
        },
    },
    404: {
        "description": "Tool not found",
        "model": APIResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "blocked",
                    "decision": "block",
                    "reason": "Tool 'missing_tool' not found",
                    "data": None,
                }
            }
        },
    },
}

EXPLAIN_RESPONSES = {
    200: {
        "description": "Structured decision trace",
        "model": APIResponse,
        "content": {
            "application/json": {
                "examples": {
                    "allowed": {
                        "summary": "Allowed decision",
                        "value": {
                            "status": "success",
                            "decision": "allow",
                            "reason": "Tool 'read_customer' allowed with audit monitoring",
                            "data": None,
                            "trace": {
                                "reason_chain": [
                                    "Capability gate skipped because no capabilities were provided",
                                    "Capability cap_customer_read (risk: medium) governs access to read_customer",
                                    "Tool 'read_customer' allowed with audit monitoring",
                                ],
                                "capability_result": "not_applicable",
                                "policy_result": "allowed",
                                "final_decision": "allowed",
                                "capability_metadata": {
                                    "cap_customer_read": {
                                        "tools": ["read_customer"],
                                        "description": "Read customer account records",
                                        "risk": "medium",
                                    }
                                },
                            },
                        },
                    },
                }
            }
        },
    },
    202: {
        "description": "Approval required decision trace",
        "model": APIResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "require_approval",
                    "decision": "require_approval",
                    "reason": "Tool 'restart_service' requires human approval",
                    "data": None,
                    "trace": {
                        "reason_chain": [
                            "Capability gate skipped because no capabilities were provided",
                            "Capability cap_service_ops (risk: high) governs access to restart_service",
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
                }
            }
        },
    },
    403: {
        "description": "Blocked decision trace",
        "model": APIResponse,
        "content": {
            "application/json": {
                "examples": {
                    "blocked": {
                        "summary": "Blocked decision",
                        "value": {
                            "status": "blocked",
                            "decision": "block",
                            "reason": "Tool 'shell_exec' is globally blocked",
                            "data": None,
                            "trace": {
                                "reason_chain": [
                                    "Capability gate skipped because no capabilities were provided",
                                    "Tool 'shell_exec' is globally blocked",
                                ],
                                "capability_result": "not_applicable",
                                "policy_result": "blocked",
                                "final_decision": "blocked",
                            },
                        },
                    },
                }
            }
        },
    },
    404: {
        "description": "Tool not found",
        "model": APIResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "blocked",
                    "decision": "block",
                    "reason": "Tool 'missing_tool' not found",
                    "data": None,
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


def _trace_payload(trace) -> ExplainTraceModel:
    return ExplainTraceModel(
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
    )


def _approval_required_response(exc: ApprovalRequiredError, trace) -> JSONResponse:
    return JSONResponse(
        status_code=202,
        content=APIResponse(
            status="require_approval",
            decision="require_approval",
            reason=str(exc),
            data={"approval_id": exc.approval_id},
            trace=_trace_payload(trace),
        ).model_dump(),
    )


def _blocked_response(exc: PolicyViolationError, trace=None) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content=APIResponse(
            status="blocked",
            decision="block",
            reason=str(exc),
            trace=_trace_payload(trace) if trace is not None else None,
        ).model_dump(),
    )


def _tool_not_found_response(tool_name: str) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content=APIResponse(
            status="blocked",
            decision="block",
            reason=f"Tool '{tool_name}' not found",
        ).model_dump(),
    )


@app.post(
    "/execute",
    responses=EXECUTE_RESPONSES,
    response_model=APIResponse,
)
def execute(request: ExecuteRequest = Body(..., openapi_examples=EXECUTE_REQUEST_EXAMPLES)) -> dict:
    if request.tool_name not in tool_registry:
        return _tool_not_found_response(request.tool_name)

    plan = interceptor.plan(
        InterceptionRequest(
            context=interceptor_context_from_request(request),
            tool_registry=tool_registry,
            approval_id=request.approval_id,
            dry_run=request.dry_run,
        )
    )
    trace = interceptor.evaluate(plan)
    try:
        result = interceptor.execute_plan(plan)
        if request.dry_run:
            decision = "require_approval" if result.would_require_approval else ("block" if result.would_block else "allow")
            return APIResponse(
                status="dry_run",
                decision=decision,
                reason=result.reason,
                data=DryRunResultModel.model_validate(asdict(result)).model_dump(),
                trace=_trace_payload(trace),
            ).model_dump()
        return APIResponse(
            status="success",
            decision="allow",
            reason=trace.policy_reason or "Allowed by policy",
            data=result,
            trace=_trace_payload(trace),
        ).model_dump()
    except ApprovalRequiredError as exc:
        return _approval_required_response(exc, trace)
    except PolicyViolationError as exc:
        return _blocked_response(exc, trace)
    except ToolNotFoundError:
        return _tool_not_found_response(request.tool_name)


@app.post("/explain", responses=EXPLAIN_RESPONSES, response_model=APIResponse)
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
    status_code = 200
    status = "success"
    decision = "allow"
    if trace.final_decision == "require_approval":
        status_code = 202
        status = "require_approval"
        decision = "require_approval"
    elif trace.final_decision == "blocked":
        status_code = 403
        status = "blocked"
        decision = "block"

    return JSONResponse(
        status_code=status_code,
        content=APIResponse(
            status=status,
            decision=decision,
            reason=trace.policy_reason or trace.capability_reason or (trace.reason_chain[-1] if trace.reason_chain else "Decision evaluated"),
            trace=_trace_payload(trace),
        ).model_dump(),
    )


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
