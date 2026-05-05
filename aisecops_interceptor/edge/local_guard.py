from __future__ import annotations

from aisecops_interceptor.guard.detectors import (
    detect_dangerous_input_patterns,
    detect_prompt_injection,
)
from aisecops_interceptor.guard.models import GuardFinding, GuardResult


def inspect(input_text: str) -> GuardResult:
    raw_findings = [
        *detect_prompt_injection(input_text),
        *detect_dangerous_input_patterns(input_text),
    ]

    findings = [
        GuardFinding(rule=rule, severity=severity, message=message)
        for rule, severity, message in raw_findings
    ]
    allowed = not any(finding.severity == "high" for finding in findings)
    return GuardResult(allowed=allowed, findings=findings)
