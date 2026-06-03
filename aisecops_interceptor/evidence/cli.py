from __future__ import annotations

import argparse
import sys

from aisecops_interceptor.evidence.export import EvidenceExporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export AISecOps governance evidence for a trace.")
    parser.add_argument("--trace-id", required=True, help="Trace ID to export")
    parser.add_argument("--audit-log", required=True, help="Replay-compatible audit JSONL path")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Evidence output format")
    parser.add_argument("--output", help="Output file path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rendered = EvidenceExporter().export(
            audit_file=args.audit_log,
            trace_id=args.trace_id,
            output_format=args.format,
            output_path=args.output,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.output is None:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
