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
