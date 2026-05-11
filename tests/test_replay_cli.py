from __future__ import annotations

import json

from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.models import InstructionProvenance
from aisecops_interceptor.replay.cli import main


def test_replay_cli_prints_human_readable_timeline(tmp_path, capsys) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    logger.log(
        RuntimeEvent.audit_event(
            event_type="tool_blocked",
            decision="blocked",
            reason="unverified skill provenance",
            stage="tool",
            context=RuntimeContext(
                agent_name="demo-agent",
                tool_name="send_email",
                trace_id="run-123",
            ),
            execution_plan_id="plan-1",
            decision_stage="policy",
            provenance=[
                InstructionProvenance(
                    source_type="skill",
                    source_name="untrusted_openclaw_skill",
                    trust_level="unverified",
                )
            ],
        )
    )

    code = main(["--trace-id", "run-123", "--audit-file", str(audit_file)])
    captured = capsys.readouterr()

    assert code == 0
    assert "Trace: run-123" in captured.out
    assert "[1] tool_blocked" in captured.out
    assert "tool: send_email" in captured.out
    assert "Provenance:" in captured.out
    assert "- skill: untrusted_openclaw_skill (trust: unverified)" in captured.out


def test_replay_cli_returns_non_zero_for_missing_trace(tmp_path, capsys) -> None:
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text("", encoding="utf-8")

    code = main(["--trace-id", "run-missing", "--audit-file", str(audit_file)])
    captured = capsys.readouterr()

    assert code == 1
    assert "No audit events found" in captured.err


def test_replay_cli_reports_missing_audit_file(capsys, tmp_path) -> None:
    audit_file = tmp_path / "missing.jsonl"

    code = main(["--trace-id", "run-123", "--audit-file", str(audit_file)])
    captured = capsys.readouterr()

    assert code == 1
    assert "Audit file not found" in captured.err


def test_replay_cli_reports_recoverable_warnings(tmp_path, capsys) -> None:
    audit_file = tmp_path / "audit.jsonl"
    valid_line = json.dumps(
        RuntimeEvent.audit_event(
            event_type="prompt_allowed",
            decision="allowed",
            reason="Prompt accepted",
            stage="tool",
            context=RuntimeContext(
                agent_name="demo-agent",
                trace_id="run-123",
            ),
            decision_stage="input",
        ).to_dict()
    )
    audit_file.write_text(valid_line + "\n{bad-json}\n", encoding="utf-8")

    code = main(["--trace-id", "run-123", "--audit-file", str(audit_file)])
    captured = capsys.readouterr()

    assert code == 0
    assert "Warning: line 2" in captured.err
