from __future__ import annotations

import pytest
from pathlib import Path
from agent_blackbox.security.crypto import KeyManager, canonical_json_bytes


def test_key_generation_and_signing(tmp_path):
    km = KeyManager(key_dir=tmp_path)
    assert km.private_path.exists()
    assert km.public_path.exists()

    message = b"Audit event canonical payload: {action: allow}"
    signature = km.sign(message)
    assert isinstance(signature, str)
    assert len(signature) == 128  # Ed25519 signature is 64 bytes = 128 hex chars

    # Valid verification
    assert km.verify(message, signature)

    # Tampered message must fail
    assert not km.verify(b"Audit event canonical payload: {action: block}", signature)


def test_canonical_json():
    d1 = {"b": 2, "a": 1}
    d2 = {"a": 1, "b": 2}
    assert canonical_json_bytes(d1) == canonical_json_bytes(d2)
