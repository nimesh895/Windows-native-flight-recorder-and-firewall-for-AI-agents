from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_blackbox.config import BlackboxConfig
from agent_blackbox.dashboard.server import create_dashboard_app


def test_dashboard_host_header_validation():
    cfg = BlackboxConfig()
    token = cfg.dashboard.session_token
    # In production mode, testserver is NOT allowed
    app = create_dashboard_app(cfg, allow_testserver=False)
    client = TestClient(app)

    # 1. Default starlette client Host is 'testserver' -> MUST BE FORBIDDEN when allow_testserver=False
    res_testserver = client.get(f"/?token={token}")
    assert res_testserver.status_code == 403
    assert "Host header 'testserver' is not permitted" in res_testserver.json()["detail"]

    # 2. Valid host 127.0.0.1
    res_valid_ip = client.get(f"/?token={token}", headers={"Host": "127.0.0.1:8420"})
    assert res_valid_ip.status_code == 200

    # 3. Valid host localhost
    res_valid_local = client.get(f"/?token={token}", headers={"Host": "localhost:8420"})
    assert res_valid_local.status_code == 200

    # 4. Malicious host header (e.g. DNS rebinding / host header poisoning)
    res_evil = client.get(f"/?token={token}", headers={"Host": "evil.com"})
    assert res_evil.status_code == 403
    assert "Host header" in res_evil.json()["detail"]


def test_dashboard_testserver_explicit_flag():
    cfg = BlackboxConfig()
    token = cfg.dashboard.session_token
    # When explicit allow_testserver=True is provided, testserver passes
    app = create_dashboard_app(cfg, allow_testserver=True)
    client = TestClient(app)

    res = client.get(f"/?token={token}")
    assert res.status_code == 200


def test_dashboard_origin_checking_state_changing_requests():
    cfg = BlackboxConfig()
    token = cfg.dashboard.session_token
    app = create_dashboard_app(cfg, allow_testserver=True)
    client = TestClient(app)

    # 1. Cross-Origin state-changing POST from evil.com must be REJECTED (403)
    res_cross_origin = client.post(
        f"/api/simulate-tamper?token={token}",
        headers={
            "Host": "127.0.0.1:8420",
            "Origin": "http://evil.com",
        },
    )
    assert res_cross_origin.status_code == 403
    assert "Cross-origin" in res_cross_origin.json()["detail"]

    # 2. Same-origin POST from http://127.0.0.1:8420 is PERMITTED through security middleware
    res_same_origin = client.post(
        f"/api/simulate-tamper?token={token}",
        headers={
            "Host": "127.0.0.1:8420",
            "Origin": "http://127.0.0.1:8420",
        },
    )
    # Passed host and origin middleware (status is 200 or 401 if token checks pass)
    assert res_same_origin.status_code != 403

