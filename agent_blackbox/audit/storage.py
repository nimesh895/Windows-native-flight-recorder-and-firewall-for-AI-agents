from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_blackbox.audit.models import AuditRecord, GENESIS_HASH
from agent_blackbox.security.crypto import KeyManager
from agent_blackbox.security.redactor import SecretRedactor


class AuditStorage:
    """
    SQLite append-only audit log with cryptographic SHA-256 hash chaining
    and Ed25519 digital signatures.
    """

    def __init__(self, db_path: str | Path = "blackbox_audit.db", key_mgr: Optional[KeyManager] = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_mgr = key_mgr or KeyManager()
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    tool_name TEXT,
                    arguments_redacted TEXT,
                    result_redacted TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    risk_score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON audit_events(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON audit_events(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            # Store public key in metadata
            with open(self.key_mgr.public_path, "r", encoding="utf-8") as f:
                pub_pem = f.read()
            conn.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('public_key_pem', ?)", (pub_pem,))
            conn.commit()

    def get_latest_hash(self) -> str:
        """
        Retrieves the record_hash of the most recent audit entry, or GENESIS_HASH.
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("SELECT record_hash FROM audit_events ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return row["record_hash"]
            return GENESIS_HASH

    def append_event(
        self,
        session_id: str,
        event_type: str,
        tool_name: Optional[str] = None,
        arguments: Optional[Any] = None,
        result: Optional[Any] = None,
        decision: str = "ALLOWED",
        reason: str = "",
        risk_score: int = 0,
        severity: str = "INFO",
        timestamp: Optional[str] = None,
    ) -> AuditRecord:
        """
        Appends an event to the hash chain:
        1. Redacts secrets from arguments and result
        2. Retrieves previous hash
        3. Computes record hash
        4. Signs record hash with Ed25519
        5. Commits to SQLite
        """
        with self._lock:
            redacted_args = SecretRedactor.redact_data(arguments) if arguments is not None else None
            redacted_res = SecretRedactor.redact_data(result) if result is not None else None

            prev_hash = self.get_latest_hash()

            record = AuditRecord(
                session_id=session_id,
                event_type=event_type,
                tool_name=tool_name,
                arguments_redacted=redacted_args,
                result_redacted=redacted_res,
                decision=decision,
                reason=reason,
                risk_score=risk_score,
                severity=severity,
                prev_hash=prev_hash,
            )
            if timestamp:
                record.timestamp = timestamp

            # Compute hash
            record.record_hash = record.compute_record_hash()

            # Sign with Ed25519
            record.signature = self.key_mgr.sign(record.record_hash.encode("utf-8"))

            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO audit_events (
                        timestamp, session_id, event_type, tool_name,
                        arguments_redacted, result_redacted, decision, reason,
                        risk_score, severity, prev_hash, record_hash, signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.timestamp,
                        record.session_id,
                        record.event_type,
                        record.tool_name,
                        json.dumps(record.arguments_redacted) if record.arguments_redacted is not None else None,
                        json.dumps(record.result_redacted) if record.result_redacted is not None else None,
                        record.decision,
                        record.reason,
                        record.risk_score,
                        record.severity,
                        record.prev_hash,
                        record.record_hash,
                        record.signature,
                    ),
                )
                record.id = cursor.lastrowid
                conn.commit()

            return record

    def get_events(
        self,
        session_id: Optional[str] = None,
        min_severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditRecord]:
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_level = severity_order.get(min_severity.upper(), 0) if min_severity else 0

        query = "SELECT * FROM audit_events WHERE 1=1"
        params: List[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        results = []
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(query, params)
            for row in cursor.fetchall():
                sev = row["severity"]
                if severity_order.get(sev, 0) < min_level:
                    continue

                args = json.loads(row["arguments_redacted"]) if row["arguments_redacted"] else None
                res = json.loads(row["result_redacted"]) if row["result_redacted"] else None

                results.append(
                    AuditRecord(
                        id=row["id"],
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
                )

        return results

    def get_summary_stats(self) -> Dict[str, Any]:
        with self._lock, self._get_connection() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            blocked_events = conn.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'BLOCKED'").fetchone()[0]
            canary_events = conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type = 'canary_trip'").fetchone()[0]
            max_risk = conn.execute("SELECT COALESCE(MAX(risk_score), 0) FROM audit_events").fetchone()[0]
            avg_risk = conn.execute("SELECT COALESCE(AVG(risk_score), 0.0) FROM audit_events").fetchone()[0]
            sessions_count = conn.execute("SELECT COUNT(DISTINCT session_id) FROM audit_events").fetchone()[0]

            return {
                "total_events": total_events,
                "blocked_events": blocked_events,
                "canary_events": canary_events,
                "max_risk_score": max_risk,
                "avg_risk_score": round(avg_risk, 1),
                "total_sessions": sessions_count,
            }
