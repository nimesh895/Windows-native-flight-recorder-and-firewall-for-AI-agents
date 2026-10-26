from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel

from agent_blackbox.security.crypto import KeyManager, canonical_json_bytes
from agent_blackbox.audit.storage import AuditStorage


class AuditAnchor(BaseModel):
    anchored_at: str
    anchored_record_id: int
    anchored_record_hash: str
    signature: str

    def payload_bytes(self) -> bytes:
        data = {
            "anchored_at": self.anchored_at,
            "anchored_record_id": self.anchored_record_id,
            "anchored_record_hash": self.anchored_record_hash,
        }
        return canonical_json_bytes(data)

    def save_to_file(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))

    @classmethod
    def load_from_file(cls, path: str | Path) -> AuditAnchor:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Anchor file not found: {p}")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


def create_anchor(
    storage: AuditStorage,
    output_path: str | Path = "blackbox_anchor.json",
    key_mgr: Optional[KeyManager] = None,
) -> AuditAnchor:
    """
    Exports the latest hash and record ID to an external anchor file, signed with Ed25519.
    """
    km = key_mgr or storage.key_mgr

    with storage._lock, storage._get_connection() as conn:
        cursor = conn.execute("SELECT id, record_hash FROM audit_events ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise RuntimeError("Cannot anchor empty database. Record at least one event first.")

        rec_id = row["id"]
        rec_hash = row["record_hash"]

    anchor = AuditAnchor(
        anchored_at=datetime.now(timezone.utc).isoformat(),
        anchored_record_id=rec_id,
        anchored_record_hash=rec_hash,
        signature="",
    )

    # Sign the anchor payload
    anchor.signature = km.sign(anchor.payload_bytes())
    anchor.save_to_file(output_path)
    return anchor
