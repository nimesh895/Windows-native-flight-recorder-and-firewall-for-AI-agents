from __future__ import annotations

import os
import sys
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SUPPORTED_CLIENTS = {
    "claude-desktop": {
        "name": "Claude Desktop",
        "default_path": Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"
        if "APPDATA" in os.environ
        else Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
        "mcp_key": "mcpServers",
    },
    "cursor": {
        "name": "Cursor",
        "default_path": Path.home() / ".cursor" / "mcp.json",
        "mcp_key": "mcpServers",
    },
    "vscode": {
        "name": "VS Code",
        "default_path": Path.home() / ".vscode" / "mcp.json",
        "mcp_key": "mcpServers",
    },
}


class IdeConfigurator:
    """
    Automates discovering, backing up, and configuring Model Context Protocol (MCP)
    client configuration files to route through AgentBlackbox firewall proxy.
    """

    def __init__(self, policy_path: Optional[str | Path] = None):
        self.policy_path = Path(policy_path).resolve() if policy_path else (Path.cwd() / "blackbox_policy.yaml").resolve()

    @staticmethod
    def get_supported_clients() -> List[str]:
        return list(SUPPORTED_CLIENTS.keys())

    @classmethod
    def resolve_config_path(cls, client: str, custom_path: Optional[str | Path] = None) -> Path:
        client_key = client.lower().strip()
        if custom_path:
            return Path(custom_path).resolve()

        if client_key not in SUPPORTED_CLIENTS:
            raise ValueError(f"Unsupported client '{client}'. Choose from: {', '.join(SUPPORTED_CLIENTS.keys())}")

        return SUPPORTED_CLIENTS[client_key]["default_path"].resolve()

    @classmethod
    def backup_config(cls, config_path: Path) -> Optional[Path]:
        if not config_path.exists():
            return None
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = config_path.with_suffix(f".json.bak_{ts}")
        shutil.copy2(config_path, backup_path)
        return backup_path

    def wrap_config(self, client: str, custom_path: Optional[str | Path] = None) -> Dict[str, Any]:
        """
        Wraps every configured MCP server in the client's configuration file
        with the AgentBlackbox stdio proxy.
        """
        target_path = self.resolve_config_path(client, custom_path)
        mcp_key = SUPPORTED_CLIENTS[client.lower().strip()]["mcp_key"]

        if not target_path.exists():
            # Create parent directories and initialize empty structure
            target_path.parent.mkdir(parents=True, exist_ok=True)
            config_data: Dict[str, Any] = {mcp_key: {}}
            backup_file = None
        else:
            backup_file = self.backup_config(target_path)
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    config_data = json.load(f)
            except Exception:
                config_data = {mcp_key: {}}

        if mcp_key not in config_data or not isinstance(config_data[mcp_key], dict):
            config_data[mcp_key] = {}

        servers = config_data[mcp_key]
        modified_count = 0
        skipped_count = 0

        # We prefer using sys.executable -m agent_blackbox.cli if in a virtual environment,
        # or agent-blackbox if available globally.
        blackbox_cmd = "agent-blackbox"

        for s_name, s_spec in servers.items():
            if not isinstance(s_spec, dict):
                continue

            orig_cmd = s_spec.get("command", "")
            orig_args = s_spec.get("args", [])

            # Check if already wrapped
            if "agent-blackbox" in orig_cmd or "agent_blackbox" in str(orig_args) or "abb" == orig_cmd:
                skipped_count += 1
                continue

            # Wrap command:
            # command: "agent-blackbox"
            # args: ["proxy", "--config", "<policy>", "--", "<orig_cmd>", ...]
            wrapped_args = [
                "proxy",
                "--config",
                str(self.policy_path),
                "--",
                orig_cmd,
            ] + list(orig_args)

            s_spec["command"] = blackbox_cmd
            s_spec["args"] = wrapped_args
            modified_count += 1

        # Write updated config
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)

        return {
            "client": client,
            "target_path": str(target_path),
            "backup_file": str(backup_file) if backup_file else None,
            "modified_servers": modified_count,
            "skipped_servers": skipped_count,
            "total_servers": len(servers),
        }

    def unwrap_config(self, client: str, custom_path: Optional[str | Path] = None) -> Dict[str, Any]:
        """
        Removes the AgentBlackbox proxy wrapper and restores the original direct MCP commands.
        """
        target_path = self.resolve_config_path(client, custom_path)
        mcp_key = SUPPORTED_CLIENTS[client.lower().strip()]["mcp_key"]

        if not target_path.exists():
            return {
                "client": client,
                "target_path": str(target_path),
                "unwrapped_count": 0,
                "status": "File not found",
            }

        backup_file = self.backup_config(target_path)
        with open(target_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        servers = config_data.get(mcp_key, {})
        unwrapped_count = 0

        for s_name, s_spec in servers.items():
            if not isinstance(s_spec, dict):
                continue

            orig_cmd = s_spec.get("command", "")
            orig_args = s_spec.get("args", [])

            # If wrapped by agent-blackbox
            if ("agent-blackbox" in orig_cmd or "abb" == orig_cmd) and "--" in orig_args:
                idx = orig_args.index("--")
                # Remaining elements after '--' are the original command and args
                remaining = orig_args[idx + 1 :]
                if remaining:
                    s_spec["command"] = remaining[0]
                    s_spec["args"] = remaining[1:]
                    unwrapped_count += 1

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)

        return {
            "client": client,
            "target_path": str(target_path),
            "backup_file": str(backup_file) if backup_file else None,
            "unwrapped_count": unwrapped_count,
            "total_servers": len(servers),
        }
