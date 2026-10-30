from __future__ import annotations

import sys
import uuid
import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from agent_blackbox.config import BlackboxConfig
from agent_blackbox.security.policy import PolicyEngine, PolicyDecision
from agent_blackbox.security.tool_pinning import ToolPinningManager
from agent_blackbox.audit.storage import AuditStorage
from agent_blackbox.proxy.mcp_spec import (
    JsonRpcRequest,
    JsonRpcResponse,
    JsonRpcError,
    parse_json_rpc,
    serialize_json_rpc,
)

logger = logging.getLogger("agent_blackbox.router")


class UpstreamServer:
    """
    Manages communication with an individual child MCP server subprocess.
    """

    def __init__(self, name: str, command: List[str]):
        self.name = name
        self.command = command
        self.process: Optional[asyncio.subprocess.Process] = None
        self.tools_catalog: List[Dict[str, Any]] = []

    async def start(self) -> None:
        logger.info("Spawning upstream MCP server [%s]: %s", self.name, " ".join(self.command))
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stop(self) -> None:
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=2.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

    async def send_request(self, request: JsonRpcRequest) -> Optional[JsonRpcResponse]:
        if not self.process or not self.process.stdin or not self.process.stdout:
            return None

        line = serialize_json_rpc(request)
        self.process.stdin.write(line.encode("utf-8"))
        await self.process.stdin.drain()

        # Read response line
        resp_line_bytes = await self.process.stdout.readline()
        if not resp_line_bytes:
            return None

        parsed = parse_json_rpc(resp_line_bytes.decode("utf-8").strip())
        if isinstance(parsed, JsonRpcResponse):
            return parsed
        return None


class McpRouterProxy:
    """
    Multi-Server MCP Router and Aggregating Proxy.
    The AI Agent connects to this single Blackbox instance, which:
    1. Manages N upstream MCP servers simultaneously.
    2. Aggregates tools/list across all servers into a unified catalog.
    3. Transparently routes tools/call to the correct upstream server.
    4. Enforces CROSS-SERVER security invariants:
       e.g., if Server A (filesystem) reads sensitive data, Server B (github/network)
       is blocked from exfiltrating it or accessing unseen domains.
    """

    def __init__(
        self,
        config: BlackboxConfig,
        servers_config: Dict[str, List[str]],  # server_name -> command_list
        session_id: Optional[str] = None,
        audit_storage: Optional[AuditStorage] = None,
    ):
        self.config = config
        self.servers_config = servers_config
        self.session_id = session_id or str(uuid.uuid4())
        self.audit_storage = audit_storage or AuditStorage(db_path=config.audit.db_path)
        self.policy_engine = PolicyEngine(config=config)
        self.tool_pinning_mgr = ToolPinningManager(enforce=(config.mode == "enforce"))

        self.upstreams: Dict[str, UpstreamServer] = {
            s_name: UpstreamServer(s_name, cmd) for s_name, cmd in servers_config.items()
        }
        # tool_name -> UpstreamServer
        self.tool_to_server_map: Dict[str, UpstreamServer] = {}

    async def start(self) -> None:
        """Launches all child MCP server processes."""
        for server in self.upstreams.values():
            await server.start()

        self.audit_storage.append_event(
            session_id=self.session_id,
            event_type="system",
            decision="ALLOWED",
            reason=f"Started Multi-Server MCP Router for {len(self.upstreams)} servers: {list(self.upstreams.keys())}",
            severity="INFO",
        )

    async def stop(self) -> None:
        """Stops all child MCP servers."""
        for server in self.upstreams.values():
            await server.stop()

    async def handle_request(self, req: JsonRpcRequest) -> JsonRpcResponse:
        method = req.method

        # 1. tools/list: Query all upstream servers and return unified aggregated tool list
        if method == "tools/list":
            aggregated_tools: List[Dict[str, Any]] = []
            self.tool_to_server_map.clear()

            for s_name, server in self.upstreams.items():
                resp = await server.send_request(req)
                if resp and isinstance(resp.result, dict) and "tools" in resp.result:
                    tools = resp.result.get("tools", [])
                    server.tools_catalog = tools
                    for t in tools:
                        t_name = t.get("name")
                        if t_name:
                            self.tool_to_server_map[t_name] = server
                            # Annotate tool description with server origin for transparency
                            aggregated_tools.append(t)

            # Check for rug-pull mutations & prompt injections on aggregated catalog
            rugpulls = self.tool_pinning_mgr.verify_tools_list(aggregated_tools)
            if rugpulls and self.config.mode == "enforce":
                self.audit_storage.append_event(
                    session_id=self.session_id,
                    event_type="rugpull_alert",
                    tool_name="tools/list",
                    result={"mutations": [r.model_dump() for r in rugpulls]},
                    decision="BLOCKED",
                    reason=f"Router detected tool rug-pull on '{rugpulls[0].tool_name}'",
                    risk_score=100,
                    severity="CRITICAL",
                )
                return JsonRpcResponse(
                    id=req.id,
                    error=JsonRpcError(
                        code=-32003,
                        message=f"AgentBlackbox Router Security Block: Tool description rug-pull for '{rugpulls[0].tool_name}'",
                    ),
                )

            self.audit_storage.append_event(
                session_id=self.session_id,
                event_type="tool_response",
                tool_name="tools/list",
                result={"aggregated_tool_count": len(aggregated_tools)},
                decision="ALLOWED",
                reason=f"Aggregated {len(aggregated_tools)} tools across {len(self.upstreams)} upstream servers",
                risk_score=0,
                severity="INFO",
            )

            return JsonRpcResponse(
                id=req.id,
                result={"tools": aggregated_tools},
            )

        # 2. tools/call: Evaluate policy with cross-server state, then route to appropriate server
        elif method == "tools/call" and isinstance(req.params, dict):
            tool_name = req.params.get("name", "")
            arguments = req.params.get("arguments", {})

            # Cross-server policy evaluation!
            # The PolicyEngine's SessionSequenceTracker preserves cross-server correlation
            # (e.g. Server 1 sensitive read blocks Server 2 network exfil)
            decision: PolicyDecision = self.policy_engine.evaluate_call(tool_name, arguments)

            if decision.is_blocked:
                self.audit_storage.append_event(
                    session_id=self.session_id,
                    event_type="tool_call",
                    tool_name=tool_name,
                    arguments=arguments,
                    decision="BLOCKED",
                    reason=decision.reason,
                    risk_score=decision.risk_score,
                    severity=decision.severity,
                )
                return JsonRpcResponse(
                    id=req.id,
                    error=JsonRpcError(
                        code=-32003,
                        message=f"AgentBlackbox Cross-Server Security Block: {decision.reason}",
                        data={"rule": decision.rule_name, "risk_score": decision.risk_score},
                    ),
                )

            # Route to target upstream server
            target_server = self.tool_to_server_map.get(tool_name)
            if not target_server:
                # If map empty, check upstreams directly
                for s in self.upstreams.values():
                    if any(t.get("name") == tool_name for t in s.tools_catalog):
                        target_server = s
                        break

            if not target_server:
                # Forward to first upstream or return method not found
                target_server = next(iter(self.upstreams.values()))

            upstream_resp = await target_server.send_request(req)
            if not upstream_resp:
                return JsonRpcResponse(
                    id=req.id,
                    error=JsonRpcError(code=-32603, message=f"Upstream server {target_server.name} did not respond"),
                )

            # Audit log execution
            self.audit_storage.append_event(
                session_id=self.session_id,
                event_type="tool_response",
                tool_name=tool_name,
                arguments=arguments,
                result=upstream_resp.result if upstream_resp.result is not None else (upstream_resp.error.model_dump() if upstream_resp.error else None),
                decision="ALLOWED",
                reason=f"Executed via router on upstream [{target_server.name}]",
                risk_score=decision.risk_score,
                severity=decision.severity,
            )

            return upstream_resp

        # 3. Default (initialize, ping, etc.): send to primary upstream
        else:
            primary = next(iter(self.upstreams.values()))
            resp = await primary.send_request(req)
            return resp or JsonRpcResponse(id=req.id, result={"status": "ok"})
