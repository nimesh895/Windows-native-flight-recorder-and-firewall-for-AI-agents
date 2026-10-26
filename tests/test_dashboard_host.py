from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_blackbox.config import BlackboxConfig
from agent_blackbox.dashboard.server import create_dashboard_app


def test_dashboard_host_header_validation():
    cfg = BlackboxConfig()
    token = cfg.dashboard.session_token
    app = create_dashboard_app(cfg)
    client = TestClient(app)

    # 1. Valid host 127.0.0.1
    res_valid_ip = client.get(f"/?token={token}", headers={"Host": "127.0.0.1:8420"})
    assert res_valid_ip.status_code == 200

    # 2. Valid host localhost
    res_valid_local = client.get(f"/?token={token}", headers={"Host": "localhost:8420"})
    assert res_valid_local.status_code == 200

    # 3. Malicious host header (e.g. DNS rebinding / host header poisoning)
    res_evil = client.get(f"/?token={token}", headers={"Host": "evil.com"})
    assert res_evil.status_code == 403
    assert "Host header" in res_evil.json()["detail"]

    # 4. Another forbidden host
    res_attacker = client.get(f"/api/summary?token={token}", headers={"Host": "attacker.site:9999"})
    assert res_attacker.status_code == 403
    assert "Host header" in res_attacker.json()["detail"]
