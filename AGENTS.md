# AGENTS.md

## Scope
These instructions apply to the repository rooted at `/Users/viplavfauzdar/Projects/aisecops-interceptor`.

## Session startup

Before making any changes:

1. Read `.codex-handoff.md`.
2. Verify:
   - current branch
   - git status
   - latest commits
3. Compare repository state with `.codex-handoff.md`.
4. Report any drift before editing files.

## Project intent
- This repo implements a runtime security interceptor for AI agents.
- Keep security logic centralized in the interceptor and policy layers.
- Keep framework adapters thin. They should translate framework payloads into the repo's shared runtime models, not add security logic.


## Architecture rules
- `aisecops_interceptor/core/context.py` is the single canonical home of `RuntimeContext`.
- Do not introduce another `RuntimeContext` definition anywhere else.
- `aisecops_interceptor/core/models.py` contains shared runtime dataclasses such as `ToolCall`, `InterceptionRequest`, `PolicyDecision`, and `ApprovalRequest`.
- `aisecops_interceptor/core/events.py` is the canonical home of the unified runtime event model used by both LLM-stage and tool-stage events.
- Preserve the current approval flow shape: policy decides, interceptor handles approval orchestration, execution gate stays minimal.

### Runtime flow contract
The expected runtime execution order must remain:

Prompt
→ Prompt Guard (input inspection)
→ Guarded LLM Pipeline
→ Output Guard
→ RuntimeContext construction
→ AgentInterceptor
→ PolicyEngine evaluation
→ Approval workflow (if required)
→ ExecutionGate
→ Tool execution
→ unified runtime event logging

No new logic should bypass the interceptor or execution gate.

- `RuntimeContext` must be passed unchanged across adapters, the interceptor, and the LLM pipeline when available.
- Avoid adding framework-specific logic into `core/` modules.
- Any new runtime metadata should be added to `RuntimeContext`, not to ad‑hoc dictionaries.


## Change boundaries
- Prefer narrow edits that preserve current behavior.
- Do not refactor unrelated modules while addressing a focused task.
- Preserve demos and tests when making internal model changes.
- If a change affects both tool interception and the LLM pipeline, keep the shared contract compatible across both paths.

## LLM security layer
The LLM protection layer lives under `aisecops_interceptor/guard` and `aisecops_interceptor/llm`.

Responsibilities:
- detect prompt injection attempts
- detect secret leakage in model outputs
- ensure LLM calls pass through `GuardedLLMPipeline`

Do not move prompt‑layer security logic into framework adapters.


## Verification
- Use the project virtualenv at `./.venv`.
- Preferred test command: `./.venv/bin/python -m pytest -q`
- Preferred demo command: `./.venv/bin/python -m examples.agent_demo`
- If a task touches adapters, policy, interceptor, or runtime models, run at least the full pytest suite unless the user says otherwise.

### Additional verification
When modifying core runtime logic also verify:

- `python -m compileall aisecops_interceptor examples tests`
- runtime demo still executes
- there is only one `RuntimeContext` definition (`rg "^class RuntimeContext"`)

## Editing notes
- Use `apply_patch` for manual file edits.
- Prefer `rg` for code search.
- Update README only when behavior or public usage actually changes.
- Avoid expanding scope into packaging, dependency cleanup, or event-model redesign unless explicitly requested.

### Git workflow
- After completing a task that satisfies the acceptance criteria, stage **all current repository changes**, create a commit summarizing the change, and push the current branch unless the user says otherwise.
- Use small, focused commit messages that reflect the architectural step completed.

Recommended pattern:

```
git add -A
git commit -m "<short description of completed step>"
git push origin <current-branch>
```

Pushes should normally occur only after a logical milestone (for example: context unification, policy changes, interceptor changes, etc.), but once a milestone is complete the default is to push it.

If a task only inspects or verifies the codebase and does not modify files, **do not create a commit**.

## Session shutdown

When a material task is completed:

1. Update `.codex-handoff.md` if:
   - roadmap changed
   - release status changed
   - branch status changed
   - major features were added
   - ownership changed

2. Commit the handoff update with the completed task when appropriate.

## Response expectations
- When work is complete, report:
  1. changed files
  2. commands run
  3. test/demo results
  4. any remaining risks or assumptions


## Ownership

Claude Code owns:
- dashboard UI
- visualizations
- UX flows
- screenshots

Codex owns:
- runtime engine
- planning
- policy engine
- replay engine
- MCP integration
- local enforcement
- documentation
- release engineering

Do not modify dashboard UI unless explicitly instructed.


## Roadmap awareness

Current roadmap:

- v0.8.1: Agent Runtime Controls
- v0.9.0: Local Enforcement Mode
- v0.9.5: MCP Proxy Mode
- v1.0.0: Runtime Governance Platform

## Release progression

Completed milestones:

- v0.7.0: Replay Audit UI + Execution Graphs
- v0.8.0: Structured Plan Extraction
- v0.8.1: Agent Runtime Controls

Planned milestones:

- v0.9.0: Local Enforcement Mode
- v0.9.5: MCP Proxy Mode
- v1.0.0: Runtime Governance Platform

## Scope control

Prefer extending existing runtime models.

Avoid introducing parallel abstractions when:
- RuntimeContext already exists
- ExecutionPlan already exists
- RuntimeBudget already exists
- RuntimeUsage already exists

Extend canonical models instead.

## Architecture goals
The long‑term design goal is to keep AISecOps as a **framework‑agnostic AI security runtime**.

Adapters translate external agent frameworks into the repo’s runtime models:

Agent Framework → Adapter → RuntimeContext → Interceptor → Decision → Execution → Audit

Security enforcement must remain centralized in the interceptor and guard layers.
