from __future__ import annotations

import asyncio
import pytest
from starlette.testclient import TestClient

from agent_blackbox.config import BlackboxConfig
from agent_blackbox.dashboard.server import create_dashboard_app
from agent_blackbox.security.hitl import GLOBAL_HITL_MANAGER


def test_hitl_pending_and_resolution():
    cfg = BlackboxConfig()
    token = cfg.dashboard.session_token
    app = create_dashboard_app(cfg, allow_testserver=True)
    client = TestClient(app)

    # 1. Dispatch an approval request directly to HITL manager
    async def create_request():
        return await GLOBAL_HITL_MANAGER.request_approval(
            session_id="test-session",
            tool_name="delete_database",
            arguments={"db": "production.db"},
            reason="Destructive database drop",
            timeout=5.0,
        )

    # Run request concurrently
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(create_request())

    # Give event loop a cycle to register pending request
    loop.run_until_complete(asyncio.sleep(0.01))

    # Query pending via Dashboard API
    res_pending = client.get(f"/api/hitl/pending?token={token}")
    assert res_pending.status_code == 200
    pending_list = res_pending.json()
    assert len(pending_list) == 1
    req_id = pending_list[0]["id"]
    assert pending_list[0]["tool_name"] == "delete_database"

    # Resolve approval via Dashboard POST endpoint
    res_approve = client.post(
        f"/api/hitl/respond?token={token}",
        json={"request_id": req_id, "approved": True},
    )
    assert res_approve.status_code == 200
    assert res_approve.json()["approved"] is True

    # Complete the task
    approved_result = loop.run_until_complete(task)
    assert approved_result is True
    loop.close()


def test_hitl_timeout_denial():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Request with tiny 0.05s timeout
    async def timeout_test():
        return await GLOBAL_HITL_MANAGER.request_approval(
            session_id="test-session",
            tool_name="untrusted_action",
            arguments={},
            reason="Automated test timeout",
            timeout=0.05,
        )

    result = loop.run_until_complete(timeout_test())
    assert result is False  # Timed out requests must fail-closed (deny)
    loop.close()
