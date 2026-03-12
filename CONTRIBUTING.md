# Contributing

Thank you for contributing to **AISecOps Interceptor**.

This project focuses on building a runtime security layer for agentic systems and large language model (LLM) driven applications. Contributions should preserve the architectural principles defined in `AGENTS.md`.

---

# Development workflow

1. Clone the repository

```
git clone https://github.com/<your-org>/aisecops-interceptor.git
cd aisecops-interceptor
```

2. Create and activate the virtual environment

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Run the test suite

```
pytest -q
```

All tests must pass before submitting a contribution.

---

# Architectural guidelines

All contributions must follow the architecture defined in `AGENTS.md`.

Key rules:

- `RuntimeContext` is the canonical runtime metadata contract
- `RuntimeEvent` is the single event model for both LLM and tool execution
- adapters must remain thin
- policy logic must remain in the policy layer
- the interceptor orchestrates decisions and execution

Do **not** introduce duplicate runtime models.

---

# Code changes

When submitting code:

- keep changes small and focused
- avoid unrelated refactors
- maintain backwards compatibility unless a change is explicitly architectural
- update tests when behavior changes

If a new capability is added:

- add unit tests
- update README where necessary

---

# Git workflow

Follow the repository commit policy defined in `AGENTS.md`.

General rules:

- create **small logical commits**
- commit after a task is complete
- do **not push automatically** unless explicitly instructed

Typical commit:

```
git add -A
git commit -m "short description of completed step"
```

---

# Testing expectations

Before submitting changes run:

```
python -m compileall aisecops_interceptor examples tests
pytest -q
```

Both must succeed.

---

# Examples and demos

Examples must remain runnable:

```
python -m examples.agent_demo
```

If a feature affects runtime flow, update the demo accordingly.

---

# Documentation

When modifying architecture or runtime behavior:

- update `README.md`
- update `AGENTS.md` if architecture rules change

Documentation should remain concise and reflect the real repository state.

---

# Pull requests

Pull requests should include:

- description of the change
- architectural rationale
- confirmation that tests pass

Large architectural changes should be discussed before implementation.

---

# Design philosophy

AISecOps Interceptor aims to provide:

- runtime governance for agent systems
- policy-driven execution control
- unified runtime event auditing
- framework-agnostic integrations

Keep the system **simple, composable, and observable**.
