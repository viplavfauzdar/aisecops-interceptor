from .models import GuardFinding, GuardResult
from .detectors import detect_prompt_injection


def inspect_prompt(text: str) -> GuardResult:
    raw_findings = detect_prompt_injection(text)

    findings = [
        GuardFinding(rule=r, severity=s, message=m)
        for r, s, m in raw_findings
    ]

    allowed = not any(f.severity == "high" for f in findings)

    return GuardResult(allowed=allowed, findings=findings)
