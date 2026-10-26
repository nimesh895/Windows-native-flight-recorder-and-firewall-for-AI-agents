from __future__ import annotations

import sqlite3
import pytest
from pathlib import Path
from agent_blackbox.security.crypto import KeyManager
from agent_blackbox.audit.storage import AuditStorage
from agent_blackbox.audit.verifier import AuditVerifier


def test_hashchain_valid_sequence(tmp_path):
    db_file = tmp_path / "test_audit.db"
    km = KeyManager(key_dir=tmp_path / "keys")
    storage = AuditStorage(db_path=db_file, key_mgr=km)

    # Append 5 events
    for i in range(5):
        storage.append_event(
            session_id="session-test",
            event_type="tool_call",
            tool_name="read_file",
            arguments={"path": f"file_{i}.txt"},
            decision="ALLOWED",
            reason=f"Event {i}",
        )

    verifier = AuditVerifier(db_path=db_file, key_mgr=km)
    result = verifier.verify()
    assert result.is_valid
    assert result.total_records == 5
    assert result.verified_records == 5


def test_tampering_row_content_fails_verify(tmp_path):
    db_file = tmp_path / "test_audit.db"
    km = KeyManager(key_dir=tmp_path / "keys")
    storage = AuditStorage(db_path=db_file, key_mgr=km)

    for i in range(3):
        storage.append_event(
            session_id="session-test",
            event_type="tool_call",
            tool_name="read_file",
            arguments={"path": f"file_{i}.txt"},
            decision="ALLOWED",
            reason="Original reason",
        )

    # Maliciously edit row #2 in SQLite directly
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE audit_events SET reason = 'Tampered Reason' WHERE id = 2")
    conn.commit()
    conn.close()

    # Verification must fail!
    verifier = AuditVerifier(db_path=db_file, key_mgr=km)
    result = verifier.verify()
    assert not result.is_valid
    assert result.tampered_record_id == 2
    assert "Row content tampered" in result.error_message


def test_tampering_prev_hash_fails_verify(tmp_path):
    db_file = tmp_path / "test_audit.db"
    km = KeyManager(key_dir=tmp_path / "keys")
    storage = AuditStorage(db_path=db_file, key_mgr=km)

    for i in range(3):
        storage.append_event(
            session_id="session-test",
            event_type="tool_call",
            tool_name="read_file",
            arguments={"path": f"file_{i}.txt"},
            decision="ALLOWED",
            reason="Original reason",
        )

    # Maliciously modify prev_hash of row #3
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE audit_events SET prev_hash = 'badhash' WHERE id = 3")
    conn.commit()
    conn.close()

    verifier = AuditVerifier(db_path=db_file, key_mgr=km)
    result = verifier.verify()
    assert not result.is_valid
    assert result.tampered_record_id == 3
    assert "Hash chain broken" in result.error_message
