from __future__ import annotations

import sqlite3
import pytest
from pathlib import Path

from agent_blackbox.security.crypto import KeyManager
from agent_blackbox.audit.storage import AuditStorage
from agent_blackbox.audit.verifier import AuditVerifier
from agent_blackbox.audit.anchoring import create_anchor, AuditAnchor


def test_anchor_export_and_verification(tmp_path):
    db_file = tmp_path / "anchor_test.db"
    key_dir = tmp_path / "keys"
    anchor_file = tmp_path / "test_anchor.json"

    km = KeyManager(key_dir=key_dir)
    storage = AuditStorage(db_path=db_file, key_mgr=km)

    # Append 5 events
    for i in range(5):
        storage.append_event(
            session_id="session-anchor",
            event_type="tool_call",
            tool_name="read_file",
            arguments={"path": f"doc_{i}.txt"},
            decision="ALLOWED",
        )

    # Export anchor
    anchor = create_anchor(storage=storage, output_path=anchor_file, key_mgr=km)
    assert anchor.anchored_record_id == 5
    assert len(anchor.anchored_record_hash) == 64
    assert len(anchor.signature) == 128
    assert anchor_file.exists()

    # Verify against anchor: must pass!
    verifier = AuditVerifier(db_path=db_file, key_mgr=km)
    res_valid = verifier.verify(anchor_path=anchor_file)
    assert res_valid.is_valid
    assert res_valid.verified_records == 5


def test_anchor_detects_log_truncation(tmp_path):
    db_file = tmp_path / "truncation_test.db"
    key_dir = tmp_path / "keys"
    anchor_file = tmp_path / "exported_anchor.json"

    km = KeyManager(key_dir=key_dir)
    storage = AuditStorage(db_path=db_file, key_mgr=km)

    for i in range(10):
        storage.append_event(
            session_id="session-trunc",
            event_type="tool_call",
            tool_name="read_file",
            arguments={"path": f"item_{i}.txt"},
            decision="ALLOWED",
        )

    # Export anchor at record #10
    create_anchor(storage=storage, output_path=anchor_file, key_mgr=km)

    # Attacker truncates the database by deleting the last 3 records (records 8, 9, 10)
    # The remaining records 1..7 have an internally consistent hash chain,
    # so standard verify() without an anchor would think it's valid!
    conn = sqlite3.connect(str(db_file))
    conn.execute("DELETE FROM audit_events WHERE id > 7")
    conn.commit()
    conn.close()

    verifier = AuditVerifier(db_path=db_file, key_mgr=km)

    # Verify without anchor passes because records 1..7 have unbroken links
    res_without_anchor = verifier.verify()
    assert res_without_anchor.is_valid

    # Verify WITH anchor MUST DETECT TRUNCATION!
    res_with_anchor = verifier.verify(anchor_path=anchor_file)
    assert not res_with_anchor.is_valid
    assert "truncation detected" in res_with_anchor.error_message.lower()
    assert res_with_anchor.tampered_record_id == 10
