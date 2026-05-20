# Show HN Submission Draft

---

## Title

**Show HN: AISecOps Interceptor – Runtime governance layer for AI agent tool calls (Python, open source)**

---

## Body

Most agent security tooling is still just prompt filtering. But once your agent is calling APIs,
restarting services, or sending emails, the threat model is different. The question is no longer
"was the prompt malicious?" — it's "what did the agent try to do, and should it have been allowed to?"

I built AISecOps Interceptor to sit between the agent runtime and tool execution, enforcing
governance at the moment that actually matters.

**The core idea: split decisioning from execution.**

Instead of letting the LLM drive directly to a tool call, the interceptor introduces an explicit
`plan → evaluate → execute` split. Every tool request passes through:

1. **Capability gate** — does this agent have permission to request this class of tool at all?
2. **Policy engine** — declarative YAML rules: allow / block / require-approval, with optional
   provenance conditions (e.g. deny `send_email` if the instruction originated from an unverified skill)
3. **Approval workflow** — holds execution until a human approves, if required
4. **Structured JSONL audit log** — every decision is persisted and replayable

**Provenance tracking** is the piece I haven't seen elsewhere. Every runtime event records where
the instruction came from — user prompt, memory, retrieval chunk, tool result, untrusted plugin.
Policy rules can be conditioned on that provenance, which gives you a meaningful defence against
retrieval poisoning and malicious plugin attacks.

The replay layer reconstructs full execution timelines from the JSONL audit log, including a React
forensics UI with provenance badges and an execution graph. Think EDR-style replay, for AI agents.

Works standalone or via thin adapters for LangGraph and OpenClaw. FastAPI wrapper included.
101 tests passing. Apache 2.0.

→ https://github.com/viplavfauzdar/aisecops-interceptor

Happy to discuss the architecture, the provenance model, or where this falls short.

---

## Posting notes

- **Post at:** Tuesday–Thursday, 8–10am US Eastern (peak HN traffic)
- **Watch for:** questions about how it compares to LangChain guardrails, Llama Guard, Rebuff
  — have short answers ready. Key differentiator: those are prompt/output filters; this is an
  execution control plane that runs at the tool-call boundary.
- **Pin a comment** shortly after posting with a quick demo command:
  `python -m examples.hack_the_agent_demo` — it's the fastest way to show the interceptor
  actually blocking something.
- **Don't edit the title** after posting — HN penalises that.

---

## Suggested first comment (pin immediately after posting)

> If you want to see it block something immediately, clone the repo and run:
>
> ```
> pip install -e .
> python -m examples.hack_the_agent_demo
> ```
>
> It runs four scenarios: a jailbreak blocked at the prompt guard, a provenance-aware policy
> block, a capability gate block, and an approval-required path. Takes about 30 seconds with
> no API key needed.

---

## Reddit variant (r/netsec)

**Title:** I built a runtime governance layer for AI agents — capability gates, provenance-aware policy, replayable audit log [open source]

**Body:** Same core content, but open with the threat model angle more explicitly for a security audience.
Lead with: "Indirect prompt injection via RAG, tool parameter manipulation, memory poisoning —
these aren't theoretical. Here's a runtime enforcement layer built around those specific threats."
