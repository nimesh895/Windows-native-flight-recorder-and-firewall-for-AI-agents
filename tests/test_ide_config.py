from __future__ import annotations

import json
import pytest
from pathlib import Path

from agent_blackbox.integrations.ide_config import IdeConfigurator


def test_ide_config_wrap_and_unwrap(tmp_path):
    config_file = tmp_path / "claude_desktop_config.json"
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text("mode: enforce\n", encoding="utf-8")

    # Initial mock Claude desktop config
    initial_config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\workspace"],
            },
            "github": {
                "command": "docker",
                "args": ["run", "-i", "mcp/github"],
            },
        }
    }
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(initial_config, f, indent=2)

    configurator = IdeConfigurator(policy_path=policy_file)

    # 1. Wrap configuration
    wrap_res = configurator.wrap_config(client="claude-desktop", custom_path=config_file)
    assert wrap_res["modified_servers"] == 2
    assert wrap_res["backup_file"] is not None
    assert Path(wrap_res["backup_file"]).exists()

    # Read modified JSON
    with open(config_file, "r", encoding="utf-8") as f:
        wrapped_data = json.load(f)

    fs_server = wrapped_data["mcpServers"]["filesystem"]
    assert fs_server["command"] == "agent-blackbox"
    assert fs_server["args"][0] == "proxy"
    assert fs_server["args"][1] == "--config"
    assert fs_server["args"][2] == str(policy_file.resolve())
    assert fs_server["args"][3] == "--"
    assert fs_server["args"][4] == "npx"
    assert fs_server["args"][5:] == ["-y", "@modelcontextprotocol/server-filesystem", "C:\\workspace"]

    # 2. Re-wrapping should skip already wrapped servers
    wrap_again = configurator.wrap_config(client="claude-desktop", custom_path=config_file)
    assert wrap_again["modified_servers"] == 0
    assert wrap_again["skipped_servers"] == 2

    # 3. Unwrap configuration
    unwrap_res = configurator.unwrap_config(client="claude-desktop", custom_path=config_file)
    assert unwrap_res["unwrapped_count"] == 2

    # Verify original direct commands restored exactly
    with open(config_file, "r", encoding="utf-8") as f:
        restored_data = json.load(f)

    assert restored_data["mcpServers"]["filesystem"]["command"] == "npx"
    assert restored_data["mcpServers"]["filesystem"]["args"] == ["-y", "@modelcontextprotocol/server-filesystem", "C:\\workspace"]
    assert restored_data["mcpServers"]["github"]["command"] == "docker"
    assert restored_data["mcpServers"]["github"]["args"] == ["run", "-i", "mcp/github"]
