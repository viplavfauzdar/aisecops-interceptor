class PolicyViolationError(Exception):
    """Raised when a tool call is blocked by policy."""


class ToolNotFoundError(Exception):
    """Raised when a tool is not present in the registry."""


class ApprovalRequiredError(Exception):
    """Raised when a tool call requires human approval before execution."""

    def __init__(self, message: str, *, approval_id: str) -> None:
        super().__init__(message)
        self.approval_id = approval_id
