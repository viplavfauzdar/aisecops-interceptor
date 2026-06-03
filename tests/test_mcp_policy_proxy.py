import json

from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.mcp.adapter import capability_for_mcp_tool
from aisecops_interceptor.mcp.models import MCPInvocation
from aisecops_interceptor.mcp.proxy import MCPPolicyProxy, main
from aisecops_interceptor.replay.engine import AuditReplayEngine


def _policy_file(tmp_path, content: str = ""):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(content or "blocked_tools: []\n", encoding="utf-8")
    return policy_file


def test_mcp_invocation_creation() -> None:
    invocation = MCPInvocation(
        session_id="session-1",
        client_id="codex",
        server_name="filesystem",
        tool_name="filesystem.write",
        arguments={"path": "test.txt"},
    )

    assert invocation.session_id == "session-1"
    assert invocation.client_id == "codex"
    assert invocation.server_name == "filesystem"
    assert invocation.tool_name == "filesystem.write"
    assert invocation.arguments == {"path": "test.txt"}
    assert invocation.timestamp


def test_mcp_capability_mapping_known_and_unknown() -> None:
    assert capability_for_mcp_tool("filesystem.write") == ("filesystem.write", False)
    assert capability_for_mcp_tool("custom.tool") == ("custom.tool", True)


def test_mcp_policy_allow(tmp_path) -> None:
    audit_file = tmp_path / "mcp-audit.jsonl"
    proxy = MCPPolicyProxy(
        policy_path=str(_policy_file(tmp_path)),
        audit_log_path=str(audit_file),
    )

    decision = proxy.evaluate(
        MCPInvocation(
            session_id="session-1",
            client_id="codex",
            server_name="filesystem",
            tool_name="filesystem.read",
            arguments={"path": "README.md"},
        )
    )

    assert decision.allowed is True
    assert decision.capability == "filesystem.read"
    assert decision.trace_id


def test_mcp_policy_block(tmp_path) -> None:
    audit_file = tmp_path / "mcp-audit.jsonl"
    policy_file = _policy_file(tmp_path, "blocked_tools:\n  - filesystem.write\n")
    proxy = MCPPolicyProxy(policy_path=str(policy_file), audit_log_path=str(audit_file))

    decision = proxy.evaluate(
        MCPInvocation(
            session_id="session-1",
            client_id="codex",
            server_name="filesystem",
            tool_name="filesystem.write",
            arguments={"path": "test.txt"},
        )
    )

    assert decision.allowed is False
    assert "globally blocked" in decision.reason
    assert decision.capability == "filesystem.write"


def test_mcp_audit_event_creation(tmp_path) -> None:
    audit_file = tmp_path / "mcp-audit.jsonl"
    proxy = MCPPolicyProxy(
        policy_path=str(_policy_file(tmp_path)),
        audit_log_path=str(audit_file),
    )

    decision = proxy.evaluate(
        MCPInvocation(
            session_id="session-1",
            client_id="codex",
            server_name="filesystem",
            tool_name="filesystem.write",
            arguments={"path": "test.txt"},
        )
    )

    events = list(AuditLogger(log_path=str(audit_file)).persisted_events())
    mcp_events = [event for event in events if event.event_type == "mcp_policy_decision"]
    assert decision.allowed is True
    assert mcp_events
    assert mcp_events[-1].protocol == "mcp"
    assert mcp_events[-1].client_id == "codex"
    assert mcp_events[-1].server_name == "filesystem"
    assert mcp_events[-1].tool_name == "filesystem.write"
    assert mcp_events[-1].capability == "filesystem.write"
    assert mcp_events[-1].payload["decision"] == "allowed"


def test_mcp_replay_compatibility(tmp_path) -> None:
    audit_file = tmp_path / "mcp-audit.jsonl"
    proxy = MCPPolicyProxy(
        policy_path=str(_policy_file(tmp_path)),
        audit_log_path=str(audit_file),
    )
    decision = proxy.evaluate(
        MCPInvocation(
            session_id="session-1",
            client_id="codex",
            server_name="web",
            tool_name="web.fetch",
            arguments={"url": "https://example.com"},
        )
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, decision.trace_id)
    summary = AuditReplayEngine.summarize_timeline(timeline)

    assert timeline.entries[-1].event_type == "mcp_policy_decision"
    assert timeline.entries[-1].protocol == "mcp"
    assert summary.protocol == "mcp"
    assert summary.client_id == "codex"
    assert summary.server_name == "web"
    assert summary.capability == "web.fetch"
    assert summary.final_decision == "allowed"


def test_mcp_cli_output_allowed(tmp_path, capsys) -> None:
    audit_file = tmp_path / "mcp-audit.jsonl"
    policy_file = _policy_file(tmp_path)

    code = main(
        [
            "--policy",
            str(policy_file),
            "--audit-log",
            str(audit_file),
            "--client-id",
            "codex",
            "--server",
            "filesystem",
            "--tool",
            "filesystem.read",
            "--args",
            '{"path":"README.md"}',
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert captured.out.splitlines()[0] == "ALLOWED"


def test_mcp_cli_output_blocked(tmp_path, capsys) -> None:
    audit_file = tmp_path / "mcp-audit.jsonl"
    policy_file = _policy_file(tmp_path, "blocked_tools:\n  - filesystem.write\n")

    code = main(
        [
            "--policy",
            str(policy_file),
            "--audit-log",
            str(audit_file),
            "--client-id",
            "codex",
            "--server",
            "filesystem",
            "--tool",
            "filesystem.write",
            "--args",
            '{"path":"test.txt"}',
        ]
    )
    captured = capsys.readouterr()

    assert code == 3
    assert captured.out.splitlines()[0] == "BLOCKED"
    assert "globally blocked" in captured.out


def test_unknown_mcp_tool_is_preserved_and_audited(tmp_path) -> None:
    audit_file = tmp_path / "mcp-audit.jsonl"
    proxy = MCPPolicyProxy(
        policy_path=str(_policy_file(tmp_path)),
        audit_log_path=str(audit_file),
    )
    decision = proxy.evaluate(
        MCPInvocation(
            session_id="session-1",
            client_id="codex",
            server_name="custom",
            tool_name="custom.tool",
            arguments={},
        )
    )

    events = list(AuditLogger(log_path=str(audit_file)).persisted_events())
    mcp_event = [event for event in events if event.event_type == "mcp_policy_decision"][-1]
    assert decision.capability == "custom.tool"
    assert mcp_event.payload["unknown_tool"] is True
    assert "Unknown MCP tool" in mcp_event.payload["warning"]
