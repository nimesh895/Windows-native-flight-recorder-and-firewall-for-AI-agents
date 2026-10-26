from __future__ import annotations

import sys
import uuid
import asyncio
import logging
from typing import Any, Dict, List, Optional

from agent_blackbox.config import BlackboxConfig
from agent_blackbox.security.policy import PolicyEngine, PolicyDecision
from agent_blackbox.audit.storage import AuditStorage
from agent_blackbox.proxy.mcp_spec import (
    JsonRpcRequest,
    JsonRpcResponse,
    JsonRpcError,
    parse_json_rpc,
    serialize_json_rpc,
)

logger = logging.getLogger("agent_blackbox.proxy")


class McpStdioProxy:
    """
    Transparent Stdio passthrough firewall and flight recorder for MCP servers.
    Intercepts and logs tools/list and tools/call.
    Enforces security policies, trips canaries, and blocks malicious requests.
    """

    def __init__(
        self,
        config: BlackboxConfig,
        target_command: List[str],
        session_id: Optional[str] = None,
        audit_storage: Optional[AuditStorage] = None,
    ):
        self.config = config
        self.target_command = target_command
        self.session_id = session_id or str(uuid.uuid4())
        self.audit_storage = audit_storage or AuditStorage(db_path=config.audit.db_path)
        self.policy_engine = PolicyEngine(config=config)
        self.process: Optional[asyncio.subprocess.Process] = None
        self._pending_requests: Dict[Any, JsonRpcRequest] = {}

    async def start(self) -> None:
        """
        Launches the target real MCP server subprocess.
        """
        logger.info("Spawning target MCP server: %s", " ".join(self.target_command))
        self.process = await asyncio.create_subprocess_exec(
            *self.target_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Log session start
        self.audit_storage.append_event(
            session_id=self.session_id,
            event_type="system",
            decision="ALLOWED",
            reason=f"Started MCP Proxy session for command: {' '.join(self.target_command)}",
            severity="INFO",
        )

    async def stop(self) -> None:
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=3.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

    async def handle_agent_message(self, line: str) -> Optional[str]:
        """
        Processes an incoming line from the agent/IDE.
        Returns the response line to send back to the agent (if any),
        or None if forwarded to the child server asynchronously.
        """
        msg = parse_json_rpc(line)
        if not msg:
            # Pass through unparseable line to target server
            if self.process and self.process.stdin:
                self.process.stdin.write(line.encode("utf-8") + b"\n")
                await self.process.stdin.drain()
            return None

        if isinstance(msg, JsonRpcRequest):
            return await self._handle_request(msg, raw_line=line)
        elif isinstance(msg, JsonRpcResponse):
            # Agent sending response to server notification/request
            if self.process and self.process.stdin:
                self.process.stdin.write(line.encode("utf-8") + b"\n")
                await self.process.stdin.drain()
            return None

        return None

    async def _handle_request(self, req: JsonRpcRequest, raw_line: str) -> Optional[str]:
        method = req.method

        # 1. tools/call interception
        if method == "tools/call" and isinstance(req.params, dict):
            tool_name = req.params.get("name", "")
            arguments = req.params.get("arguments", {})

            # Policy evaluation
            decision: PolicyDecision = self.policy_engine.evaluate_call(tool_name, arguments)

            if decision.is_blocked:
                # Log blocked event
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

                # Return clean JSON-RPC error response to agent without contacting MCP server
                error_resp = JsonRpcResponse(
                    id=req.id,
                    error=JsonRpcError(
                        code=-32003,
                        message=f"AgentBlackbox Security Block: {decision.reason}",
                        data={
                            "rule": decision.rule_name,
                            "risk_score": decision.risk_score,
                            "severity": decision.severity,
                        },
                    ),
                )
                return serialize_json_rpc(error_resp)

            # Allowed or Monitored: Track request
            if req.id is not None:
                self._pending_requests[req.id] = req

            # Forward to child MCP server
            if self.process and self.process.stdin:
                self.process.stdin.write(raw_line.encode("utf-8") + b"\n")
                await self.process.stdin.drain()

            return None

        # 2. tools/list interception
        elif method == "tools/list":
            if req.id is not None:
                self._pending_requests[req.id] = req

            if self.process and self.process.stdin:
                self.process.stdin.write(raw_line.encode("utf-8") + b"\n")
                await self.process.stdin.drain()

            return None

        # 3. Default forward
        else:
            if req.id is not None:
                self._pending_requests[req.id] = req

            if self.process and self.process.stdin:
                self.process.stdin.write(raw_line.encode("utf-8") + b"\n")
                await self.process.stdin.drain()

            return None

    async def handle_server_message(self, line: str) -> Optional[str]:
        """
        Processes an incoming line from the target MCP server.
        Inspects responses, redacts secrets in logs, and scans for indirect injection.
        Returns line to forward to agent.
        """
        msg = parse_json_rpc(line)
        if not msg:
            return line + "\n"

        if isinstance(msg, JsonRpcResponse):
            req = self._pending_requests.pop(msg.id, None) if msg.id is not None else None

            if req and req.method == "tools/call" and isinstance(req.params, dict):
                tool_name = req.params.get("name", "")
                arguments = req.params.get("arguments", {})

                # Scan response for indirect prompt injection or leaked canaries
                canary_alerts = self.policy_engine.canary_mgr.check_arguments_and_payload(
                    tool_name=tool_name, arguments=None, response_data=msg.result
                )
                inj_alert = None
                if self.config.injection_scanner.enabled and self.config.injection_scanner.scan_tool_responses:
                    inj_alert = self.policy_engine.injection_scanner.scan_tool_response(msg.result)

                risk_score = 0
                severity = "INFO"
                reason = "Tool execution completed successfully"

                if canary_alerts:
                    severity = "CRITICAL"
                    risk_score = 100
                    reason = f"Canary leak in tool response: {canary_alerts[0].description}"
                elif inj_alert and inj_alert.is_flagged:
                    severity = inj_alert.severity
                    risk_score = inj_alert.risk_score
                    reason = f"Indirect injection in tool output: {'; '.join(inj_alert.matched_heuristics)}"

                # Log to hash-chained audit storage
                self.audit_storage.append_event(
                    session_id=self.session_id,
                    event_type="tool_response",
                    tool_name=tool_name,
                    arguments=arguments,
                    result=msg.result if msg.result is not None else (msg.error.model_dump() if msg.error else None),
                    decision="ALLOWED",
                    reason=reason,
                    risk_score=risk_score,
                    severity=severity,
                )

            elif req and req.method == "tools/list":
                # Scan tool list descriptions for poisoning
                if isinstance(msg.result, dict) and "tools" in msg.result:
                    tools_list = msg.result.get("tools", [])
                    poisoned_tools = []
                    for t in tools_list:
                        scan = self.policy_engine.injection_scanner.scan_tool_spec(t)
                        if scan.is_flagged:
                            poisoned_tools.append((t.get("name"), scan))

                    if poisoned_tools:
                        tool_names = [pt[0] for pt in poisoned_tools]
                        self.audit_storage.append_event(
                            session_id=self.session_id,
                            event_type="injection_alert",
                            tool_name="tools/list",
                            result={"poisoned_tools": tool_names},
                            decision="MONITORED",
                            reason=f"Poisoned tool description detected in tools/list: {', '.join(tool_names)}",
                            risk_score=85,
                            severity="HIGH",
                        )
                    else:
                        self.audit_storage.append_event(
                            session_id=self.session_id,
                            event_type="tool_response",
                            tool_name="tools/list",
                            result={"tool_count": len(tools_list)},
                            decision="ALLOWED",
                            reason=f"Enumerated {len(tools_list)} tools cleanly",
                            risk_score=0,
                            severity="INFO",
                        )

            return serialize_json_rpc(msg)

        return line + "\n"

    async def run_stdio(self) -> None:
        """
        Runs the full async stdio proxy loop:
        Agent (stdin) -> Proxy -> Server (process.stdin)
        Server (process.stdout) -> Proxy -> Agent (stdout)
        """
        await self.start()
        loop = asyncio.get_running_loop()

        # Non-blocking stdin reader for standard input
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        async def agent_to_server():
            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8").strip()
                if not line:
                    continue
                resp = await self.handle_agent_message(line)
                if resp:
                    sys.stdout.write(resp)
                    sys.stdout.flush()

        async def server_to_agent():
            if not self.process or not self.process.stdout:
                return
            while True:
                line_bytes = await self.process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8").strip()
                if not line:
                    continue
                out = await self.handle_server_message(line)
                if out:
                    sys.stdout.write(out)
                    sys.stdout.flush()

        try:
            await asyncio.gather(agent_to_server(), server_to_agent())
        finally:
            await self.stop()
