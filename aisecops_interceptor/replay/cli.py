from __future__ import annotations

import argparse
import sys

from aisecops_interceptor.replay.engine import (
    AuditFileNotFoundError,
    AuditReplayEngine,
    ReplayTimeline,
    TraceNotFoundError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisecops-replay",
        description="Replay structured JSONL audit events for a single trace.",
    )
    parser.add_argument("--trace-id", required=True, help="Trace ID to replay")
    parser.add_argument("--audit-file", required=True, help="Path to the JSONL audit file")
    return parser


def _print_timeline(timeline: ReplayTimeline) -> None:
    print(f"Trace: {timeline.trace_id}")
    for index, entry in enumerate(timeline.entries, start=1):
        print()
        print(f"[{index}] {entry.event_type}")
        print(f"timestamp: {entry.timestamp}")
        print(f"stage: {entry.decision_stage or 'unknown'}")
        print(f"decision: {entry.decision}")
        if entry.agent_name:
            print(f"agent: {entry.agent_name}")
        if entry.tool_name:
            print(f"tool: {entry.tool_name}")
        if entry.execution_plan_id:
            print(f"execution_plan_id: {entry.execution_plan_id}")
        if entry.reason:
            print(f"reason: {entry.reason}")
        if entry.provenance:
            print("Provenance:")
            for item in entry.provenance:
                label = item.source_name or "unnamed"
                print(f"- {item.source_type}: {label} (trust: {item.trust_level})")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    engine = AuditReplayEngine()

    try:
        timeline = engine.replay_trace(args.audit_file, args.trace_id)
    except AuditFileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except TraceNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    _print_timeline(timeline)

    for warning in timeline.warnings:
        print(
            f"Warning: line {warning.line_number}: {warning.message}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
