import re

PROMPT_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"disregard the system prompt",
    r"override safety",
]

SECRET_EXFIL_PATTERNS = [
    r"api[_-]?key",
    r"private[_-]?key",
    r"password",
    r"secret",
]


def detect_prompt_injection(text: str):
    findings = []
    for p in PROMPT_INJECTION_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            findings.append(("prompt_injection", "high", f"Matched pattern: {p}"))
    return findings


def detect_secret_exfiltration(text: str):
    findings = []
    for p in SECRET_EXFIL_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            findings.append(("secret_request", "medium", f"Matched pattern: {p}"))
    return findings
