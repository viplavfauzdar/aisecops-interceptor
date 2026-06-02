from __future__ import annotations


class CostEstimator:
    READ_COST_USD = 0.01
    WRITE_COST_USD = 0.05
    SHELL_COST_USD = 0.10
    RESTART_SERVICE_COST_USD = 0.15

    READ_PREFIXES = ("get_", "read_", "list_", "search_", "fetch_")
    WRITE_PREFIXES = ("create_", "update_", "write_", "send_", "delete_", "export_")

    def estimate_tool_cost_usd(self, tool_name: str | None) -> float:
        if not tool_name:
            return 0

        normalized = tool_name.lower()
        if normalized == "restart_service":
            return self.RESTART_SERVICE_COST_USD
        if normalized in {"shell_exec", "shell", "execute_shell"} or "shell" in normalized:
            return self.SHELL_COST_USD
        if normalized.startswith(self.READ_PREFIXES):
            return self.READ_COST_USD
        if normalized.startswith(self.WRITE_PREFIXES):
            return self.WRITE_COST_USD
        return self.READ_COST_USD
