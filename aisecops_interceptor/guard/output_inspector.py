from .models import GuardFinding, GuardResult
from .detectors import detect_secret_exfiltration


def inspect_output(text: str) -> GuardResult:
    raw_findings = detect_secret_exfiltration(text)

    findings = [
        GuardFinding(rule=r, severity=s, message=m)
        for r, s, m in raw_findings
    ]

    allowed = len(findings) == 0

    return GuardResult(allowed=allowed, findings=findings)
