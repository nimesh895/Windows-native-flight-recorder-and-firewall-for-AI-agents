from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HITLRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    tool_name: str
    arguments: Any
    reason: str
    risk_score: int
    severity: str
    created_at: float = Field(default_factory=lambda: time.time())
    timeout_seconds: float = 30.0
    status: str = "PENDING"  # PENDING, APPROVED, DENIED, TIMED_OUT


class HITLManager:
    """
    Coordinates asynchronous Human-In-The-Loop approval workflows:
    - AI agent proxy pauses on 'ask' action or risk threshold breach
    - Request broadcasted via WebSocket to Dashboard UI
    - User clicks 'Approve' or 'Deny' with 30s countdown timer
    - Resolves future back to proxy
    """

    def __init__(self, default_timeout: float = 30.0):
        self.default_timeout = default_timeout
        self._pending_requests: Dict[str, HITLRequest] = {}
        self._futures: Dict[str, asyncio.Future] = {}

    def get_pending(self) -> List[HITLRequest]:
        now = time.time()
        # Clean up timed-out requests
        active = []
        for req_id, req in list(self._pending_requests.items()):
            if req.status == "PENDING" and (now - req.created_at) > req.timeout_seconds:
                req.status = "TIMED_OUT"
                if req_id in self._futures and not self._futures[req_id].done():
                    self._futures[req_id].set_result(False)
            elif req.status == "PENDING":
                active.append(req)
        return active

    async def request_approval(
        self,
        session_id: str,
        tool_name: str,
        arguments: Any,
        reason: str,
        risk_score: int = 50,
        severity: str = "HIGH",
        timeout: Optional[float] = None,
    ) -> bool:
        loop = asyncio.get_running_loop()
        req = HITLRequest(
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            reason=reason,
            risk_score=risk_score,
            severity=severity,
            timeout_seconds=timeout or self.default_timeout,
        )

        future = loop.create_future()
        self._pending_requests[req.id] = req
        self._futures[req.id] = future

        try:
            approved = await asyncio.wait_for(future, timeout=req.timeout_seconds)
            return approved
        except asyncio.TimeoutError:
            req.status = "TIMED_OUT"
            return False
        finally:
            self._futures.pop(req.id, None)

    def resolve_request(self, request_id: str, approved: bool) -> bool:
        req = self._pending_requests.get(request_id)
        if not req or req.status != "PENDING":
            return False

        req.status = "APPROVED" if approved else "DENIED"
        fut = self._futures.get(request_id)
        if fut and not fut.done():
            fut.set_result(approved)
        return True


# Global singleton instance for proxy and dashboard server
GLOBAL_HITL_MANAGER = HITLManager()
