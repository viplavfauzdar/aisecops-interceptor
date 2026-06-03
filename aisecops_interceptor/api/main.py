from __future__ import annotations

from dataclasses import asdict

from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse, RedirectResponse

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger, DEFAULT_AUDIT_LOG_PATH
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import (
    APIResponse,
    DryRunResultModel,
    ExplainTraceModel,
    InterceptionRequest,
    InstructionProvenance,
    ReplaySummaryResponseModel,
    ReplayTimelineEntryModel,
    ReplayTraceResponseModel,
    ToolCall,
)
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.integrations.openclaw_adapter import OpenClawToolRunnerAdapter
from aisecops_interceptor.replay.engine import AuditFileNotFoundError, AuditReplayEngine, TraceNotFoundError
from aisecops_interceptor import __version__

app = FastAPI(title="AISecOps Interceptor", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
policy = PolicyEngine.from_yaml_file()
audit = AuditLogger(log_path=DEFAULT_AUDIT_LOG_PATH)
approvals = ApprovalStore(store_path="audit/approvals.jsonl")
capabilities = CapabilityRegistry.from_yaml()
interceptor = AgentInterceptor(
    policy_engine=policy,
    audit_logger=audit,
    approval_store=approvals,
    capability_registry=capabilities,
)
openclaw_adapter = OpenClawToolRunnerAdapter(interceptor=interceptor)
replay_engine = AuditReplayEngine()


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

REPLAY_RESPONSES = {
    200: {
        "description": "Full replay reconstruction for a trace",
        "model": ReplayTraceResponseModel,
        "content": {
            "application/json": {
                "example": {
                    "trace_id": "run-123",
                    "event_count": 2,
                    "execution_plan_ids": ["plan-123"],
                    "timeline": [
                        {
                            "timestamp": "2026-05-17T00:00:00+00:00",
                            "event_type": "plan",
                            "schema_version": "0.5.0",
                            "event_id": "evt-abc123",
                            "decision_stage": "plan",
                            "agent_name": "ops_agent",
                            "tool_name": "restart_service",
                            "decision": "pending",
                            "reason": "Execution plan created",
                            "provenance": [
                                {
                                    "source_type": "skill",
                                    "source_name": "untrusted_openclaw_skill",
                                    "source_hash": None,
                                    "origin_uri": None,
                                    "trust_level": "unverified",
                                    "metadata": {},
                                }
                            ],
                            "execution_plan_id": "plan-123",
                        }
                    ],
                    "schema_versions_observed": ["0.5.0"],
                    "provenance_summary": {"unverified": 1},
                    "final_decision": "blocked",
                    "final_reason": "Rule blocked tool 'send_email'",
                }
            }
        },
    },
    404: {
        "description": "Trace or audit file not found",
        "model": APIResponse,
        "content": {
            "application/json": {
                "example": {
                    "status": "blocked",
                    "decision": "block",
                    "reason": "No audit events found for trace_id 'run-missing'",
                    "data": None,
                    "trace": None,
                }
            }
        },
    },
}

REPLAY_SUMMARY_RESPONSES = {
    200: {
        "description": "Concise replay summary for a trace",
        "model": ReplaySummaryResponseModel,
        "content": {
            "application/json": {
                "example": {
                    "trace_id": "run-123",
                    "event_count": 2,
                    "final_decision": "blocked",
                    "tool_name": "send_email",
                    "final_reason": "Rule blocked tool 'send_email'",
                    "provenance_trust_summary": {"unverified": 1},
                    "schema_versions_observed": ["0.5.0"],
                }
            }
        },
    },
    404: REPLAY_RESPONSES[404],
}

REPLAY_LIST_RESPONSES = {
    200: {
        "description": "Replay trace summaries for the audit log",
        "content": {
            "application/json": {
                "example": {
                    "traces": [
                        {
                            "trace_id": "run-123",
                            "event_count": 2,
                            "final_decision": "blocked",
                            "tool_name": "send_email",
                            "final_reason": "Rule blocked tool 'send_email'",
                            "provenance_trust_summary": {"unverified": 1},
                            "schema_versions_observed": ["0.5.0"],
                            "first_seen": "2026-05-17T00:00:00+00:00",
                            "last_seen": "2026-05-17T00:00:05+00:00",
                        }
                    ],
                    "count": 1,
                    "limit": 50,
                }
            }
        },
    }
}


class ExecuteRequest(BaseModel):
    agent_name: str = Field(..., examples=["sales_agent"])
    tool_name: str = Field(..., examples=["read_customer"])
    arguments: dict = Field(default_factory=dict)
    user_input: str | None = None
    model_output: str | None = None
    approval_id: str | None = None
    dry_run: bool = False
    provenance: list[InstructionProvenance] = Field(default_factory=list)


class ApprovalReviewRequest(BaseModel):
    reviewed_by: str
    note: str | None = None


class OpenClawExecuteRequest(BaseModel):
    agent_name: str | None = None
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    approval_id: str | None = None
    correlation_id: str | None = None
    provenance: list[InstructionProvenance] = Field(default_factory=list)


def _default_api_provenance() -> list[InstructionProvenance]:
    return [
        InstructionProvenance(
            source_type="user_prompt",
            source_name="api_request",
            trust_level="internal",
        )
    ]


def _request_provenance(
    provenance: list[InstructionProvenance] | None,
) -> list[InstructionProvenance]:
    if provenance:
        return list(provenance)
    return _default_api_provenance()


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


def replay_audit_file_path() -> str:
    return DEFAULT_AUDIT_LOG_PATH


def _replay_not_found_response(reason: str) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content=APIResponse(
            status="blocked",
            decision="block",
            reason=reason,
        ).model_dump(),
    )


def _replay_timeline_entry_payload(entry) -> ReplayTimelineEntryModel:
    return ReplayTimelineEntryModel(
        timestamp=entry.timestamp,
        event_type=entry.event_type,
        schema_version=entry.schema_version,
        event_id=entry.event_id,
        decision_stage=entry.decision_stage,
        agent_name=entry.agent_name,
        tool_name=entry.tool_name,
        decision=entry.decision,
        reason=entry.reason,
        provenance=[item.to_dict() for item in entry.provenance],
        execution_plan_id=entry.execution_plan_id,
        plan_id=entry.plan_id,
        plan_intent=entry.plan_intent,
        plan_risk_level=entry.plan_risk_level,
        requested_capabilities=entry.requested_capabilities,
        plan_steps=entry.plan_steps,
        model_output=entry.model_output,
        user_input=entry.user_input,
        protocol=entry.protocol,
        client_id=entry.client_id,
        server_name=entry.server_name,
        capability=entry.capability,
        budget_status=entry.budget_status,
        runtime_budget=entry.runtime_budget,
        runtime_usage=entry.runtime_usage,
        runtime_violations=entry.runtime_violations or None,
        tool_calls_used=entry.tool_calls_used,
        tool_calls_remaining=entry.tool_calls_remaining,
        depth_used=entry.depth_used,
        runtime_seconds=entry.runtime_seconds,
        estimated_cost_usd=entry.estimated_cost_usd,
    )


def _load_replay_timeline(trace_id: str):
    return replay_engine.replay_trace(replay_audit_file_path(), trace_id)


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


@app.get("/replay", responses=REPLAY_LIST_RESPONSES)
def replay_trace_list(
    limit: int = 50,
    decision: str | None = None,
    tool_name: str | None = None,
    provenance_trust: str | None = None,
) -> dict:
    summaries = replay_engine.list_traces(
        replay_audit_file_path(),
        limit=limit,
        decision=decision,
        tool_name=tool_name,
        provenance_trust=provenance_trust,
    )
    return {
        "traces": [
            {
                "trace_id": summary.trace_id,
                "event_count": summary.event_count,
                "final_decision": summary.final_decision,
                "tool_name": summary.tool_name,
                "final_reason": summary.final_reason,
                "provenance_trust_summary": summary.provenance_trust_summary,
                "schema_versions_observed": summary.schema_versions_observed,
                "first_seen": summary.first_seen,
                "last_seen": summary.last_seen,
                **(
                    {
                        "plan_id": summary.plan_id,
                        "intent": summary.intent,
                        "risk_level": summary.risk_level,
                        "requested_capabilities": summary.requested_capabilities,
                        "step_count": summary.step_count,
                        "protocol": summary.protocol,
                        "client_id": summary.client_id,
                        "server_name": summary.server_name,
                        "capability": summary.capability,
                        "budget_status": summary.budget_status,
                        "usage_summary": summary.usage_summary,
                        "violations": summary.violations,
                    }
                    if summary.plan_id is not None or summary.usage_summary is not None or summary.protocol is not None
                    else {}
                ),
            }
            for summary in summaries
        ],
        "count": len(summaries),
        "limit": limit,
    }


@app.get(
    "/replay/{trace_id}",
    responses=REPLAY_RESPONSES,
    response_model=ReplayTraceResponseModel,
    response_model_exclude_none=True,
)
def replay_trace(trace_id: str):
    try:
        timeline = _load_replay_timeline(trace_id)
    except (AuditFileNotFoundError, TraceNotFoundError) as exc:
        return _replay_not_found_response(str(exc))

    result = replay_engine.build_trace_result(timeline)
    return ReplayTraceResponseModel(
        trace_id=result.trace_id,
        event_count=result.event_count,
        execution_plan_ids=result.execution_plan_ids,
        timeline=[_replay_timeline_entry_payload(entry) for entry in result.timeline],
        schema_versions_observed=result.schema_versions_observed,
        provenance_summary=result.provenance_summary,
        final_decision=result.final_decision,
        final_reason=result.final_reason,
        plan_id=result.plan_id,
        intent=result.intent,
        risk_level=result.risk_level,
        requested_capabilities=result.requested_capabilities,
        step_count=result.step_count,
        protocol=result.protocol,
        client_id=result.client_id,
        server_name=result.server_name,
        capability=result.capability,
        budget_status=result.budget_status,
        usage_summary=result.usage_summary,
        violations=result.violations or None,
    ).model_dump(exclude_none=True)


@app.get(
    "/replay/{trace_id}/summary",
    responses=REPLAY_SUMMARY_RESPONSES,
    response_model=ReplaySummaryResponseModel,
    response_model_exclude_none=True,
)
def replay_trace_summary(trace_id: str):
    try:
        timeline = _load_replay_timeline(trace_id)
    except (AuditFileNotFoundError, TraceNotFoundError) as exc:
        return _replay_not_found_response(str(exc))

    summary = replay_engine.summarize_timeline(timeline)
    return ReplaySummaryResponseModel(
        trace_id=summary.trace_id,
        event_count=summary.event_count,
        final_decision=summary.final_decision,
        tool_name=summary.tool_name,
        final_reason=summary.final_reason,
        provenance_trust_summary=summary.provenance_trust_summary,
        schema_versions_observed=summary.schema_versions_observed,
        plan_id=summary.plan_id,
        intent=summary.intent,
        risk_level=summary.risk_level,
        requested_capabilities=summary.requested_capabilities,
        step_count=summary.step_count,
        protocol=summary.protocol,
        client_id=summary.client_id,
        server_name=summary.server_name,
        capability=summary.capability,
        budget_status=summary.budget_status,
        usage_summary=summary.usage_summary,
        violations=summary.violations or None,
    ).model_dump(exclude_none=True)




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
    payload["provenance"] = [item.to_dict() for item in _request_provenance(request.provenance)]
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
        prompt=request.user_input,
        model_output=request.model_output,
        tool_name=request.tool_name,
        arguments=request.arguments,
        framework="legacy",
        provenance=_request_provenance(request.provenance),
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
