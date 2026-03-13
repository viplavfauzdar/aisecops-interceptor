# 🛡️ AISecOps Interceptor
### Runtime security and governance layer for AI agents.
**A framework-agnostic runtime control plane for agent security, policy enforcement, and auditability.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/viplavfauzdar/aisecops-interceptor/actions/workflows/ci.yml/badge.svg)](https://github.com/viplavfauzdar/aisecops-interceptor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/viplavfauzdar/aisecops-interceptor/actions/workflows/security.yml/badge.svg)](https://github.com/viplavfauzdar/aisecops-interceptor/actions/workflows/security.yml)

AISecOps Interceptor provides a framework-agnostic control plane to detect prompt injections, prevent secret leakage, and enforce human-in-the-loop approvals before your agents execute dangerous tools.

## CI and Security

All pull requests and pushes to `main` are validated by GitHub Actions.
The pipeline runs compile checks, tests, and demo smoke tests in CI, plus Bandit, pip-audit, Gitleaks, and CodeQL in the security workflow.

## ⚡ Getting Started

### 1. Installation
```bash
git clone https://github.com/viplavfauzdar/aisecops-interceptor.git
cd aisecops-interceptor
pip install -e .[dev]
```

### 2. Basic Interceptor Usage
```python
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest

# In practice, initialize the interceptor with the repo's policy engine,
# audit logger, and approval store.
interceptor = AgentInterceptor(...)

context = RuntimeContext(
    agent_name="ops_agent",
    tool_name="restart_service",
    sensitivity_level="high",
)

request = InterceptionRequest(
    context=context,
    tool_registry={
        "restart_service": lambda service: {"service": service, "status": "restarted"}
    },
)

# interceptor.intercept(...) capability-gates the request, then evaluates
# allow / block / require_approval before the tool executes.
result = interceptor.intercept(request)
```

## What AISecOps Interceptor Is

AISecOps Interceptor is to AI agents what application security middleware is to web apps: a **framework‑agnostic runtime security layer** that sits between an agent runtime and the tools, APIs, or actions it wants to execute.

It is designed for developers building agents that can call tools, trigger workflows, access sensitive data, or interact with real infrastructure. Instead of scattering security checks across application code, AISecOps Interceptor centralizes runtime governance in one place.


In practical terms, the interceptor sits between your **agent framework** and the **tools or APIs** the agent attempts to call. Every execution request passes through capability gating, policy evaluation, approval workflows, and audit logging before the action occurs.

Release metadata:

- License: [Apache License 2.0](LICENSE)
- Release notes: [CHANGELOG.md](CHANGELOG.md)

This project is licensed under the **Apache License 2.0**.
See the [LICENSE](LICENSE) and `NOTICE` files for full legal details and attribution information.

## Why this exists

AI agents can call tools, execute code, access data, and trigger real-world actions.

Most agent frameworks still leave runtime governance to application code.
That means developers often have to bolt on security checks, approval workflows, prompt filtering, and audit logging themselves.

AISecOps Interceptor provides that missing runtime layer.

It helps teams:

- detect prompt injection attempts before tool use
- inspect large language model (LLM) outputs for secret leakage
- enforce policy decisions before execution
- require approval for sensitive actions
- persist runtime events for audit and observability

---

# What the interceptor provides

AISecOps Interceptor enforces security and policy at **two critical layers of agentic AI systems**:

1. **Prompt layer protection** (before a large language model (LLM) is called)
2. **Tool execution protection** (before a tool or API is executed)

This ensures:

- prompt injection protection
- secret exfiltration protection
- policy‑based tool execution
- human approval for sensitive actions
- full audit trail

## Common use cases

- **Agent tool governance** — prevent agents from executing dangerous tools or APIs without policy checks.
- **Prompt injection resistance** — detect malicious instruction patterns before they influence downstream actions.
- **Approval workflows** — require a human decision before sensitive operations run.
- **Agent audit trails** — persist and query runtime events for incident review and compliance.
- **Security event delivery** — fan out runtime events to file, memory, or webhook sinks.

---

# Included capabilities

Current implementation includes:

### Core runtime

- Interceptor core
- Runtime context propagation
- Capability-gated tool execution
- Policy evaluation
- Optional declarative rule engine
- YAML policy bundles with validation
- Decision engine + execution gate
- Human approval workflow
- Structured runtime event logging with JSONL persistence
- Optional multi-sink runtime event emission

### LLM security layer

- Provider‑agnostic LLM abstraction
- Guarded LLM pipeline
- Prompt inspection
- Output inspection

### Supported model providers

- OpenAI
- Ollama (local models)
- Anthropic (Claude)

### Integrations

- LangGraph‑style adapter
- OpenClaw‑style adapter
- Generic adapter example

### Developer tooling

- FastAPI runtime wrapper
- Demo scripts (`agent_demo`, `capabilities_demo`, `demo.py`, `langgraph_style_demo`, `openclaw_demo`, `policy_bundle_demo`)
- Full pytest test suite

---

# High‑level architecture

At a high level, AISecOps Interceptor sits in the missing control plane layer between agent frameworks and real execution.

```mermaid
flowchart TD

A[Agent Runtime / Framework]

A --> B[Framework Adapter]

B --> C[Runtime Context Builder]

C --> D[Capability Gate]

D --> E[AISecOps Interceptor]

E --> F[Decision Engine]

F --> G[Execution Gate]

G --> H[Tool / API Execution]

H --> I[Audit Event]
```

This is the core execution path developers integrate with:

- agent framework builds runtime context
- capability gate checks granted capabilities against tool mappings
- interceptor evaluates policy and rules
- execution gate decides allow, block, or approval
- runtime events are emitted to audit sinks

Adapters are intentionally **thin**.


All security logic lives inside the interceptor core.
> This makes AISecOps Interceptor useful as a standalone security layer even when the surrounding agent framework changes.

The **capability gate** acts as the interceptor’s first authorization boundary. It ensures an agent can only request tools it has explicitly been granted access to. Even if a tool is discovered through prompt injection, probing, or model hallucination, the request is blocked before policy evaluation unless the agent has the required capability.

---

# LLM security architecture

The interceptor now includes a **guarded LLM pipeline**.

This protects both prompt input and model output before tools are executed.

```mermaid
flowchart TD

A[Agent Prompt]

A --> B[Prompt Guard]

B --> C[Guarded LLM Pipeline]

C --> D[LLM Provider]

D --> E[Model Response]

E --> F[Output Guard]

F --> G[AISecOps Interceptor]

G --> H[Tool Execution]
```

---

# Guarded LLM pipeline

The pipeline ensures every LLM request follows this path:

```mermaid
flowchart LR

A[LLMRequest]

A --> B[Input Inspector]

B --> C[LLM Client]

C --> D[Output Inspector]

D --> E[LLMResponse]
```

`GuardedLLMPipeline.chat(...)` can optionally accept a `RuntimeContext` and propagate it through LLM guard checks.
It can also emit structured LLM-stage security events (`prompt_allowed`, `prompt_blocked`, `output_allowed`, `output_blocked`) through the same runtime event model used by tool execution and audit logging.
`RuntimeContext` also carries optional source and sensitivity metadata (`source`, `data_classification`, `sensitivity_level`) for downstream security workflows and policy decisions.

Runtime events can be persisted to JSONL and retrieved through the API for downstream analysis or audit review.
The `/audit` endpoint supports optional query parameters: `event_type`, `stage`, `agent_name`, `tool_name`, `correlation_id`, and `limit`.
`AuditLogger` can also emit the same `RuntimeEvent` records to multiple sinks, such as JSONL persistence and additional in-memory or external streaming adapters.
Supported sink types include file-backed JSONL persistence, in-memory collection, and webhook delivery to external HTTP endpoints.
Webhook sinks support a small configurable retry count and backoff delay for transient delivery failures.
Webhook sinks can also optionally sign each event payload with HMAC SHA256 and include the digest in a configurable signature header for downstream verification.
Sink delivery is isolated per sink, so one failing sink does not block the others.
Sink failures are recorded in-memory by `AuditLogger` for local inspection and persisted to JSONL for cross-process inspection without interrupting delivery to healthy sinks.
The API exposes recorded sink delivery issues through `/audit/failures`, reading persisted sink failure records with optional query parameters: `sink_type`, `event_type`, `error_type`, and `limit`.

Security violations raise:

```
LLMGuardViolationError
```

Which prevents unsafe model responses from reaching the agent runtime.

---

# Supported LLM providers

All providers implement the same interface:

```
LLMClient
   └── chat(LLMRequest) → LLMResponse
```

Providers included:

```
ollama_client.py
openai_client.py
anthropic_client.py
```

The factory creates providers dynamically:

```
create_llm_client(LLMConfig)
```

---

# Rule-based policy

`PolicyEngine` can evaluate an ordered set of declarative rules before falling back to the existing config-driven checks.
When `RuntimeContext.allowed_capabilities` is provided, a capability gate runs before policy evaluation. That gate maps granted capabilities to tool names and blocks any tool request that is not explicitly granted.

Each rule supports:

- `tool_name`
- `agent_name` (optional)
- `sensitivity_level` (optional)
- `action`: `allow`, `block`, or `require_approval`

If rules are provided, the first matching rule wins and overrides the default policy behavior. If no rule matches, the existing blocked-tool, dangerous-argument, allowlist, approval, and monitored-tool logic still applies. The current test suite covers allow, block, require-approval, and sensitivity-based rule evaluation.

Capability mappings can be defined declaratively in YAML, for example in `policies/capabilities.yaml`:

```yaml
capabilities:
  cap_service_ops:
    tools:
      - restart_service
      - stop_service

  cap_customer_read:
    tools:
      - read_customer
```

If an agent receives `allowed_capabilities=["cap_service_ops"]`, it can request `restart_service`. If the capability list is omitted, current behavior remains unchanged and the interceptor falls back to the existing policy flow. Direct Python mappings still work, but YAML-backed loading is the preferred path.

Example:

```python
policy = PolicyEngine(
    {
        "rules": [
            {"tool_name": "restart_service", "agent_name": "ops_agent", "action": "require_approval"},
            {"tool_name": "read_customer", "sensitivity_level": "high", "action": "block"},
        ]
    }
)
```

---

# Policy bundles

Declarative rules can also be loaded from YAML bundles instead of Python dictionaries.

Example bundle:

```yaml
rules:
  - tool_name: restart_service
    agent_name: ops_agent
    action: require_approval

  - tool_name: read_customer
    sensitivity_level: high
    action: block
```

Supported rule fields:

- `tool_name` (required)
- `action` (required): `allow`, `block`, or `require_approval`
- `agent_name` (optional)
- `sensitivity_level` (optional)

Load a bundle with:

```python
policy = PolicyEngine.from_yaml("policies/production.yaml")
```

YAML bundles are validated before rules are constructed, and invalid bundles raise a validation error.

---

# Repository layout

```text
aisecops_interceptor/

  api/
    main.py

  core/
    interceptor.py
    policy.py
    approval.py
    audit.py
    context.py
    decision.py
    execution.py
    events.py

  guard/
    detectors.py
    input_inspector.py
    output_inspector.py
    models.py

  llm/
    base.py
    config.py
    factory.py
    models.py
    pipeline.py

    providers/
      ollama_client.py
      openai_client.py
      anthropic_client.py

  policy/
    rules.py
    rule_engine.py
    schema.py
    loader.py

  integrations/
    langgraph_adapter.py
    openclaw_adapter.py
    simple_adapter.py

policies/
  capabilities.yaml

examples/

  agent_demo.py
  capabilities_demo.py
  demo.py
  langgraph_style_demo.py
  openclaw_demo.py
  policy_bundle_demo.py

tests/
  test_capability_registry.py
  test_policy_engine.py
  test_policy_loader.py
```

---


# Full AISecOps security pipeline

This diagram shows the **complete runtime security flow** from prompt to tool execution.

```mermaid
flowchart TD

A[User / Agent Prompt]

A --> B[Prompt Guard]

B --> C[Guarded LLM Pipeline]

C --> D[Output Guard]

D --> E[Runtime Context Builder]

E --> F[Capability Gate]

F --> G[AISecOps Interceptor]

G --> H[Decision Engine]

H --> I[Execution Gate]

I --> J[Tool / API Execution]

J --> K[Audit Event]
```

This makes it clear that **both prompt-layer threats and tool-execution risks are governed by the AISecOps runtime**.

# Example runtime flow

```mermaid
flowchart TD

A[Agent Tool Request]

A --> B[Runtime Context Builder]

B --> C[Capability Gate]

C --> D[AISecOps Interceptor]

D --> E[Decision Engine]

E --> F{Decision}

F -->|Allow| G[Execution Gate]

F -->|Block| H[Reject Request]

F -->|Require Approval| I[Approval Workflow]

I --> G

G --> J[Tool / API Execution]

J --> K[Audit Event]
```

This diagram shows the **tool-execution governance path** after prompt and output checks have already completed.
Policy decisions in this flow may come from declarative rules or from the fallback config-driven policy logic.

---

# Full local quick start

Minimal local setup and demo:

```bash
# create environment
python3.13 -m venv .venv
source .venv/bin/activate

# install package + local dev tooling
python -m pip install -e .[dev]

# run tests
python -m pytest -q

# run API
uvicorn aisecops_interceptor.api.main:app --reload

# run demos
python -m examples.agent_demo
python -m examples.capabilities_demo
python examples/demo.py
python -m examples.langgraph_style_demo
python examples/openclaw_demo.py
python -m examples.policy_bundle_demo
```

## Minimal example

```python
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest

# In practice, use the provided policy engine / adapters from the repo.
context = RuntimeContext(
    agent_name="ops_agent",
    tool_name="restart_service",
    sensitivity_level="high",
)

# interceptor.intercept(...) evaluates policy and returns
# allow / block / require_approval before the tool executes.
```

For a complete end-to-end example, run:

```bash
python -m examples.agent_demo
```

`pyproject.toml` is the source of truth for runtime and development dependencies. `requirements.txt` is a thin wrapper around the editable install with the `dev` extra.

---

# Test coverage

Current tests validate:

- prompt injection detection
- secret detection in model output
- guarded LLM pipeline behavior
- declarative rule-based policy evaluation
- YAML policy bundle loading and validation
- provider factory behavior
- interceptor decisions and approval flow
- runtime context and execution gate behavior
- adapter and API route coverage

Latest verified local run:

```
65 passed
```

---

# Example approval workflow

1. Agent calls sensitive tool
2. Policy requires approval
3. Interceptor creates approval ID
4. Human approves request
5. Tool execution proceeds

---

# Architecture direction

AISecOps Interceptor is intended to become a **universal security runtime for AI agents**.

Goal architecture:

```mermaid
flowchart TD

A[Any Agent Framework]

A --> B[AISecOps Interceptor]

B --> C[Security Layer]

C --> D[Policy]
C --> E[Risk]
C --> F[Approval]
C --> G[Audit]

C --> H[LLM Guard]

B --> I[Tool Execution]
```

Frameworks like:

- OpenClaw
- LangGraph
- CrewAI
- AutoGen

should all plug into the same interceptor runtime.

---

# Project direction

AISecOps Interceptor is the **core product**.

Agent frameworks are **integration surfaces**, not the center of the architecture.

The objective is a portable runtime capable of securing:

- AI copilots
- autonomous agents
- enterprise AI systems
- AI developer platforms

---

# Status

Current state:

Working runtime core + guarded large language model pipeline + interceptor enforcement + declarative policy engine + end-to-end demo coverage.

Current engineering focus:

- expand declarative policy coverage while keeping fallback policy behavior simple
- strengthen policy evaluation with richer runtime metadata
- improve audit and event visibility across prompt and tool execution stages
- keep adapters thin while improving real framework integrations

---

# Positioning

AISecOps Interceptor is best understood as a **runtime governance layer for AI agents**.

It combines:

- prompt and output inspection
- policy-driven execution control
- approval workflows
- unified runtime events
- audit and sink delivery

for agentic systems that need security, observability, and controlled execution.

---

# Ecosystem positioning

AISecOps Interceptor is designed to complement modern agent frameworks rather than replace them.

Typical integration targets include:

- LangGraph
- CrewAI
- AutoGen
- OpenClaw

These frameworks orchestrate agents, while AISecOps Interceptor governs **runtime security, execution control, and auditability**.

The long‑term goal is a portable runtime security layer that can protect any agent framework with minimal adapter code.
