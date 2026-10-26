from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from agent_blackbox.security.crypto import canonical_json_bytes


GENESIS_HASH = "0" * 64


class AuditRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str
    event_type: str  # tool_call, tool_response, canary_trip, injection_alert, policy_block, system
    tool_name: Optional[str] = None
    arguments_redacted: Optional[Any] = None
    result_redacted: Optional[Any] = None
    decision: str = "ALLOWED"  # ALLOWED, BLOCKED, MONITORED
    reason: str = ""
    risk_score: int = 0
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    prev_hash: str = GENESIS_HASH
    record_hash: str = ""
    signature: str = ""

    def payload_for_hashing(self) -> bytes:
        """
        Extracts canonical data bytes representing the event content,
        excluding hash and signature fields.
        """
        core = {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "arguments_redacted": self.arguments_redacted,
            "result_redacted": self.result_redacted,
            "decision": self.decision,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "prev_hash": self.prev_hash,
        }
        return canonical_json_bytes(core)

    def compute_record_hash(self) -> str:
        """
        Computes SHA-256 hash chaining prev_hash and canonical event content.
        """
        data_bytes = self.payload_for_hashing()
        return hashlib.sha256(data_bytes).hexdigest()
