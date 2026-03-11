from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from aisecops_interceptor.core.models import ApprovalRequest, ToolCall


class ApprovalStore:
    def __init__(self, store_path: str | None = None) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self.store_path = Path(store_path) if store_path else None

    def create_request(self, *, agent_name: str, tool_call: ToolCall, reason: str, risk_level: str = "high") -> ApprovalRequest:
        request = ApprovalRequest(
            approval_id=f"apr-{uuid4().hex[:12]}",
            agent_name=agent_name,
            tool_name=tool_call.name,
            arguments=tool_call.arguments,
            reason=reason,
            risk_level=risk_level,
        )
        self._requests[request.approval_id] = request
        self._persist(request)
        return request

    def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)

    def approve(self, approval_id: str, *, reviewed_by: str, note: str | None = None) -> ApprovalRequest:
        request = self._require(approval_id)
        request.status = "approved"
        request.reviewed_by = reviewed_by
        request.review_note = note
        request.reviewed_at = datetime.now(timezone.utc).isoformat()
        self._persist(request)
        return request

    def reject(self, approval_id: str, *, reviewed_by: str, note: str | None = None) -> ApprovalRequest:
        request = self._require(approval_id)
        request.status = "rejected"
        request.reviewed_by = reviewed_by
        request.review_note = note
        request.reviewed_at = datetime.now(timezone.utc).isoformat()
        self._persist(request)
        return request

    def is_approved(self, approval_id: str | None) -> bool:
        if approval_id is None:
            return False
        request = self._requests.get(approval_id)
        return bool(request and request.status == "approved")

    def list_requests(self) -> tuple[ApprovalRequest, ...]:
        return tuple(self._requests.values())

    def _require(self, approval_id: str) -> ApprovalRequest:
        request = self.get(approval_id)
        if request is None:
            raise KeyError(f"Approval request '{approval_id}' not found")
        return request

    def _persist(self, request: ApprovalRequest) -> None:
        if self.store_path is None:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self.store_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(request)) + "\n")
