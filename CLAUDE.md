# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

AISecOps Interceptor is a runtime security library for AI agents. It intercepts tool calls, evaluates them against a policy engine, enforces a capability gate, routes through an approval workflow when required, and produces a unified audit log. It also wraps LLM calls with prompt injection and output inspection guards.

## Commands

All commands assume the virtual environment at `.venv`.

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests (preferred form)
./.venv/bin/python -m pytest -q

# Run a single test file
./.venv/bin/python -m pytest tests/test_interceptor.py -q

# Compile-check all source
python -m compileall aisecops_interceptor examples tests

# Run the demo
./.venv/bin/python -m examples.agent_demo

# Start the FastAPI server (Swagger UI at http://localhost:8000/docs)
uvicorn aisecops_interceptor.api.main:app --reload

# Replay CLI (registered entry point)
aisecops-replay
```

Before submitting changes, both `compileall` and the full pytest suite must pass.

## Architecture

### Runtime flow

```
Prompt
→ Prompt Guard (guard/input_inspector.py)
→ GuardedLLMPipeline (llm/pipeline.py)
→ Output Guard (guard/output_inspector.py)
→ RuntimeContext construction (core/context.py)
→ AgentInterceptor (core/interceptor.py)
  → CapabilityRegistry gate (core/capability_registry.py)
  → PolicyEngine evaluation (core/policy.py + policy/rule_engine.py)
  → ApprovalStore (core/approval.py)
→ PlanExecutor / ExecutionGate (core/executor.py + core/execution.py)
→ Tool execution
→ AuditLogger (core/audit.py → logs/audit.jsonl)
```

No new logic should bypass the interceptor or execution gate.

### Key canonical files

| Concern | File |
|---|---|
| Runtime metadata contract | `core/context.py` — single home of `RuntimeContext`; do not duplicate |
| Shared dataclasses | `core/models.py` — `ToolCall`, `InterceptionRequest`, `PolicyDecision`, `ApprovalRequest` |
| Unified event model | `core/events.py` — `RuntimeEvent` used for both LLM and tool-stage events |
| Policy evaluation | `core/policy.py` — `PolicyEngine` wraps `policy/rule_engine.py` |
| Policy & capability config | `policies/policies.yaml` and `policies/capabilities.yaml` |
| Audit log | `logs/audit.jsonl` (JSONL, one event per line) |
| Approval store | `audit/approvals.jsonl` |

### Packages

- **`core/`** — interceptor, policy engine, audit logger, approval store, capability registry, execution gate, runtime models, events
- **`policy/`** — YAML loader, rule engine, schema parsing
- **`guard/`** — prompt injection detection, secret leakage detection (input and output inspectors)
- **`llm/`** — `GuardedLLMPipeline`, LLM client base/factory, providers
- **`edge/`** — `local_guard.py` for lightweight in-process inspection
- **`integrations/`** — thin adapters: `LangGraphToolAdapter`, `OpenClawToolRunnerAdapter`, `SimpleAdapter`
- **`replay/`** — `AuditReplayEngine` reconstructs decision timelines from the audit log; `cli.py` is the `aisecops-replay` entry point
- **`api/`** — FastAPI app exposing `/execute`, `/explain`, `/audit`, `/approvals`, `/replay`, `/openclaw/execute`

### Architecture rules

- `RuntimeContext` has exactly one definition. Verify with: `rg "^class RuntimeContext"`
- Framework adapters translate external payloads into `RuntimeContext`; they must not contain security logic.
- All security enforcement is centralized in the interceptor and guard layers.
- Any new runtime metadata goes into `RuntimeContext`, not ad-hoc dicts.
- Policy decisions flow: capability gate → rule engine → config-level blocks → default allow.

### Policy configuration

`policies/policies.yaml` controls: `blocked_tools`, `monitored_tools`, `dangerous_argument_patterns`, `high_risk_tools`, named `rules` (with `effect: deny | require_approval` plus optional `provenance_trust` / `provenance_source_type` filters), and per-`agents` allow/approval lists.

`policies/capabilities.yaml` maps capability names to tool sets and risk levels — coarse-grained authorization layered before policy evaluation.

## Git workflow

- Commit after each logical milestone with a short, focused message.
- Push the current branch unless the user says otherwise.
- Do not commit if a task only inspects or verifies the codebase without modifying files.
- Do not push automatically to `main`.
