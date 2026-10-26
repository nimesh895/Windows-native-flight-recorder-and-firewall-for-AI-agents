from __future__ import annotations

import pytest
from agent_blackbox.security.redactor import SecretRedactor


def test_redact_openai_key():
    raw_key = "sk-proj-abcdef1234567890abcdef1234567890"
    text = f"Using secret key: {raw_key} to query model"
    redacted, findings = SecretRedactor.redact_text(text)

    assert raw_key not in redacted
    assert "[REDACTED_SECRET:OPENAI_KEY:" in redacted
    assert len(findings) == 1
    assert findings[0]["type"] == "OPENAI_KEY"


def test_redact_anthropic_key():
    raw_key = "sk-ant-admin1234567890abcdef1234567890"
    text = f"api_token={raw_key}"
    redacted, findings = SecretRedactor.redact_text(text)

    assert raw_key not in redacted
    assert "[REDACTED_SECRET:ANTHROPIC_KEY:" in redacted


def test_redact_data_dictionary():
    payload = {
        "user": "alice",
        "api_key": "secret_token_12345678",
        "nested": {
            "token": "ghp_123456789012345678901234567890123456",
            "normal_field": "hello world",
        },
    }

    clean = SecretRedactor.redact_data(payload)
    assert clean["user"] == "alice"
    assert clean["nested"]["normal_field"] == "hello world"
    assert "secret_token_12345678" not in str(clean)
    assert "ghp_" not in str(clean)
