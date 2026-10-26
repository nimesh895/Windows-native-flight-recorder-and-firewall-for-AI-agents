from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from agent_blackbox.audit.models import AuditRecord, GENESIS_HASH
from agent_blackbox.security.crypto import KeyManager
from agent_blackbox.audit.anchoring import AuditAnchor


class VerificationResult(BaseModel):
    is_valid: bool
    total_records: int
    verified_records: int
    tampered_record_id: Optional[int] = None
    error_message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AuditVerifier:
    """
    Validates the end-to-end cryptographic integrity of the audit log.
    Ensures:
    1. Every record correctly points to the SHA-256 hash of the preceding record.
    2. Every record's hash matches its canonical content.
    3. Every record has a valid Ed25519 digital signature.
    """

    def __init__(self, db_path: str | Path, key_mgr: Optional[KeyManager] = None):
        self.db_path = Path(db_path)
        self.key_mgr = key_mgr or KeyManager()

    def verify(self, anchor_path: Optional[str | Path] = None) -> VerificationResult:
        if not self.db_path.exists():
            return VerificationResult(
                is_valid=False,
                total_records=0,
                verified_records=0,
                error_message=f"Database file does not exist: {self.db_path}",
            )

        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row

        try:
            cursor = conn.execute("SELECT * FROM audit_events ORDER BY id ASC")
            rows = cursor.fetchall()

            # 1. Truncation check against external anchor if provided
            if anchor_path:
                try:
                    anchor = AuditAnchor.load_from_file(anchor_path)
                except Exception as e:
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        verified_records=0,
                        error_message=f"Failed to load anchor file: {str(e)}",
                    )

                # Verify anchor signature
                if not self.key_mgr.verify(anchor.payload_bytes(), anchor.signature):
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        verified_records=0,
                        error_message="Anchor signature verification failed! The anchor file is invalid or forged.",
                    )

                # Check if database has been truncated
                if len(rows) < anchor.anchored_record_id:
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        verified_records=0,
                        tampered_record_id=anchor.anchored_record_id,
                        error_message=(
                            f"Audit log truncation detected! Anchored record #{anchor.anchored_record_id} "
                            f"(hash: {anchor.anchored_record_hash[:16]}...) is missing from the database. "
                            f"Database only contains {len(rows)} records."
                        ),
                        details={
                            "anchored_record_id": anchor.anchored_record_id,
                            "current_latest_id": len(rows),
                        },
                    )

            if not rows:
                return VerificationResult(
                    is_valid=True,
                    total_records=0,
                    verified_records=0,
                    error_message=None,
                )

            expected_prev_hash = GENESIS_HASH
            verified_count = 0

            for row in rows:
                row_id = row["id"]
                args = json.loads(row["arguments_redacted"]) if row["arguments_redacted"] else None
                res = json.loads(row["result_redacted"]) if row["result_redacted"] else None

                record = AuditRecord(
                    id=row_id,
                    timestamp=row["timestamp"],
                    session_id=row["session_id"],
                    event_type=row["event_type"],
                    tool_name=row["tool_name"],
                    arguments_redacted=args,
                    result_redacted=res,
                    decision=row["decision"],
                    reason=row["reason"],
                    risk_score=row["risk_score"],
                    severity=row["severity"],
                    prev_hash=row["prev_hash"],
                    record_hash=row["record_hash"],
                    signature=row["signature"],
                )

                # 1. Check hash chain link
                if record.prev_hash != expected_prev_hash:
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        verified_records=verified_count,
                        tampered_record_id=row_id,
                        error_message=f"Hash chain broken at record #{row_id}: prev_hash mismatch. Expected {expected_prev_hash}, found {record.prev_hash}",
                        details={"expected_prev_hash": expected_prev_hash, "found_prev_hash": record.prev_hash},
                    )

                # 2. Re-compute canonical hash
                computed_hash = record.compute_record_hash()
                if computed_hash != record.record_hash:
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        verified_records=verified_count,
                        tampered_record_id=row_id,
                        error_message=f"Row content tampered at record #{row_id}! Computed hash {computed_hash} does not match stored hash {record.record_hash}",
                        details={"computed_hash": computed_hash, "stored_hash": record.record_hash},
                    )

                # 3. Verify Ed25519 digital signature
                sig_valid = self.key_mgr.verify(record.record_hash.encode("utf-8"), record.signature)
                if not sig_valid:
                    return VerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        verified_records=verified_count,
                        tampered_record_id=row_id,
                        error_message=f"Invalid digital signature at record #{row_id}! Signature verification failed.",
                        details={"signature": record.signature},
                    )

                expected_prev_hash = record.record_hash
                verified_count += 1

            return VerificationResult(
                is_valid=True,
                total_records=len(rows),
                verified_records=verified_count,
                error_message=None,
            )

        finally:
            conn.close()
