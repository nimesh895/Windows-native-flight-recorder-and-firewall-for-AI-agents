from __future__ import annotations

import json
import pytest
from agent_blackbox.config import BlackboxConfig, PolicyRule
from agent_blackbox.proxy.stdio_proxy import McpStdioProxy
from agent_blackbox.proxy.mcp_spec import JsonRpcRequest, parse_json_rpc


@pytest.mark.asyncio
async def test_proxy_blocks_call_clean_error(tmp_path):
    cfg = BlackboxConfig(
        mode="enforce",
        audit={"db_path": str(tmp_path / "proxy_audit.db"), "key_dir": str(tmp_path / "keys")},
        rules=[
            PolicyRule(
                name="DENY_DELETE",
                action="deny",
                tools=["delete_file"],
            )
        ],
    )
    proxy = McpStdioProxy(config=cfg, target_command=["dummy"])

    req = JsonRpcRequest(
        id=101,
        method="tools/call",
        params={"name": "delete_file", "arguments": {"path": "important.db"}},
    )
    raw_req_line = req.model_dump_json()

    # The proxy should block immediately and return a JSON-RPC error response line
    resp_line = await proxy.handle_agent_message(raw_req_line)
    assert resp_line is not None

    parsed_resp = parse_json_rpc(resp_line)
    assert parsed_resp.id == 101
    assert parsed_resp.error is not None
    assert parsed_resp.error.code == -32003
    assert "DENY_DELETE" in parsed_resp.error.message
