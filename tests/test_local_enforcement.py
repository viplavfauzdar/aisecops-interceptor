import json

from aisecops_interceptor.local.cli import main
from aisecops_interceptor.replay.engine import AuditReplayEngine


def _policy_file(tmp_path, content: str = ""):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(content or "blocked_tools: []\n", encoding="utf-8")
    return policy_file


def _run_local(tmp_path, *extra_args: str):
    audit_file = tmp_path / "audit.local.jsonl"
    policy_file = _policy_file(tmp_path)
    argv = [
        "--policy",
        str(policy_file),
        "--agent-name",
        "jeeves-local",
        "--tool-name",
        "read_customer",
        "--args",
        '{"customer_id":"123"}',
        "--audit-log",
        str(audit_file),
        "--dry-run",
        *extra_args,
    ]
    return main(argv), audit_file


def test_local_cli_dry_run_allow(tmp_path, capsys) -> None:
    code, _audit_file = _run_local(tmp_path)
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert code == 0
    assert payload["status"] == "dry_run"
    assert payload["decision"] == "allow"
    assert payload["data"]["would_allow"] is True


def test_local_cli_dry_run_block(tmp_path, capsys) -> None:
    audit_file = tmp_path / "audit.local.jsonl"
    policy_file = _policy_file(tmp_path, "blocked_tools:\n  - read_customer\n")

    code = main(
        [
            "--policy",
            str(policy_file),
            "--agent-name",
            "jeeves-local",
            "--tool-name",
            "read_customer",
            "--args",
            '{"customer_id":"123"}',
            "--audit-log",
            str(audit_file),
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert code == 0
    assert payload["status"] == "dry_run"
    assert payload["decision"] == "block"
    assert "globally blocked" in payload["reason"]


def test_local_audit_jsonl_created(tmp_path, capsys) -> None:
    code, audit_file = _run_local(tmp_path)
    capsys.readouterr()

    assert code == 0
    assert audit_file.exists()
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    assert lines
    event = json.loads(lines[0])
    assert event["trace_id"]
    assert event["event_id"].startswith("evt-")
    assert event["schema_version"] == "0.5.0"
    assert event["agent_name"] == "jeeves-local"
    assert event["tool_name"] == "read_customer"
    assert event["plan_id"]


def test_local_audit_event_is_replay_compatible(tmp_path, capsys) -> None:
    code, audit_file = _run_local(tmp_path)
    captured = capsys.readouterr()
    trace_id = json.loads(captured.out)["trace_id"]

    timeline = AuditReplayEngine().replay_trace(audit_file, trace_id)
    summary = AuditReplayEngine.summarize_timeline(timeline)

    assert code == 0
    assert summary.trace_id == trace_id
    assert summary.final_decision == "allowed"
    assert summary.tool_name == "read_customer"
    assert summary.budget_status == "within_budget"


def test_default_local_provenance_added(tmp_path, capsys) -> None:
    code, audit_file = _run_local(tmp_path)
    captured = capsys.readouterr()
    trace_id = json.loads(captured.out)["trace_id"]

    timeline = AuditReplayEngine().replay_trace(audit_file, trace_id)

    assert code == 0
    provenance = timeline.entries[0].provenance[0]
    assert provenance.source_type == "local_agent"
    assert provenance.source_name == "jeeves-local"
    assert provenance.trust_level == "internal"


def test_local_policy_file_is_honored(tmp_path, capsys) -> None:
    audit_file = tmp_path / "audit.local.jsonl"
    policy_file = _policy_file(
        tmp_path,
        "\n".join(
            [
                "rules:",
                "  - tool_name: read_customer",
                "    agent_name: jeeves-local",
                "    action: block",
            ]
        ),
    )

    code = main(
        [
            "--policy",
            str(policy_file),
            "--agent-name",
            "jeeves-local",
            "--tool-name",
            "read_customer",
            "--args",
            '{"customer_id":"123"}',
            "--audit-log",
            str(audit_file),
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert code == 0
    assert payload["decision"] == "block"
    assert "Rule blocked" in payload["reason"]


def test_local_runtime_budget_violation_blocks_execution(tmp_path, capsys) -> None:
    audit_file = tmp_path / "audit.local.jsonl"
    policy_file = _policy_file(
        tmp_path,
        "\n".join(
            [
                "agent_limits:",
                "  max_tool_calls: 20",
                "  max_depth: 5",
                "  max_runtime_seconds: 60",
                "  max_cost_usd: 0.005",
            ]
        ),
    )

    code = main(
        [
            "--policy",
            str(policy_file),
            "--agent-name",
            "jeeves-local",
            "--tool-name",
            "read_customer",
            "--args",
            '{"customer_id":"123"}',
            "--audit-log",
            str(audit_file),
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert code == 0
    assert payload["decision"] == "block"
    assert payload["reason"] == "cost_limit_exceeded"


def test_local_cli_malformed_args_returns_clean_error(tmp_path, capsys) -> None:
    audit_file = tmp_path / "audit.local.jsonl"
    policy_file = _policy_file(tmp_path)

    code = main(
        [
            "--policy",
            str(policy_file),
            "--agent-name",
            "jeeves-local",
            "--tool-name",
            "read_customer",
            "--args",
            "{bad-json}",
            "--audit-log",
            str(audit_file),
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    assert code == 2
    assert "Error: args must be valid JSON" in captured.err
    assert not audit_file.exists()
