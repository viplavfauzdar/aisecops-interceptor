from __future__ import annotations

KNOWN_TOOL_CAPABILITIES: dict[str, str] = {
    "restart_service": "infra.restart",
    "read_customer": "customer.read",
    "send_email": "email.send",
    "filesystem_write": "filesystem.write",
    "write_file": "filesystem.write",
    "delete_file": "filesystem.delete",
    "shell_exec": "system.shell",
    "run_command": "system.shell",
    "trade_execute": "trade.execute",
    "payment_send": "payment.send",
}

_KNOWN_CAPABILITY_ALIASES: dict[str, str] = {
    tool_name.replace("_", "."): capability
    for tool_name, capability in KNOWN_TOOL_CAPABILITIES.items()
}
_KNOWN_CAPABILITY_ALIASES.update(
    {capability: capability for capability in KNOWN_TOOL_CAPABILITIES.values()}
)


def canonical_capability_for_tool(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    return KNOWN_TOOL_CAPABILITIES.get(tool_name)


def normalize_capability_name(capability: str) -> str:
    normalized = capability.strip()
    if not normalized:
        return normalized
    return _KNOWN_CAPABILITY_ALIASES.get(normalized, normalized)


def safe_capability_fallback(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    if not tool_name.replace("_", "").replace("-", "").replace(".", "").isalnum():
        return tool_name
    return tool_name.replace("_", ".")


def requested_capabilities_for_tool(
    tool_name: str | None,
    explicit_capabilities: list[str] | None = None,
) -> list[str]:
    canonical = canonical_capability_for_tool(tool_name)
    if canonical:
        return [canonical]
    if explicit_capabilities:
        return [normalize_capability_name(capability) for capability in explicit_capabilities]
    fallback = safe_capability_fallback(tool_name)
    return [fallback] if fallback else []
