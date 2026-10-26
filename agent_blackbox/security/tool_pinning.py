from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agent_blackbox.security.crypto import canonical_json_bytes


class RugPullAlert(BaseModel):
    tool_name: str
    original_hash: str
    new_hash: str
    difference: str
    severity: str = "CRITICAL"


class ToolPinningManager:
    """
    Pins the cryptographic SHA-256 hash of MCP tool specifications
    (descriptions, names, parameter schemas) to detect dynamic 'rug-pull'
    attacks across tools/list calls.
    """

    def __init__(self, initial_pinned: Optional[Dict[str, str]] = None, enforce: bool = True):
        # tool_name -> sha256_hash
        self.pinned_hashes: Dict[str, str] = dict(initial_pinned or {})
        # tool_name -> cached canonical spec for diffing
        self.pinned_specs: Dict[str, Dict[str, Any]] = {}
        self.enforce = enforce

    @staticmethod
    def compute_spec_hash(tool_spec: Dict[str, Any]) -> str:
        """
        Computes SHA-256 of the canonical JSON of name, description, and inputSchema.
        """
        normalized = {
            "name": tool_spec.get("name", ""),
            "description": tool_spec.get("description", ""),
            "inputSchema": tool_spec.get("inputSchema", {}),
        }
        return hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()

    def pin_tools(self, tools: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Initializes or records the pinned hashes for a set of tools.
        """
        new_pinned = {}
        for tool in tools:
            name = tool.get("name")
            if not name:
                continue
            h = self.compute_spec_hash(tool)
            self.pinned_hashes[name] = h
            self.pinned_specs[name] = tool
            new_pinned[name] = h
        return new_pinned

    def verify_tools_list(self, tools: List[Dict[str, Any]], auto_pin_new: bool = True) -> List[RugPullAlert]:
        """
        Inspects tools returned by tools/list:
        - If tool was previously seen and its hash changed: raises RugPullAlert!
        - If tool is new and auto_pin_new=True: records initial hash.
        """
        alerts: List[RugPullAlert] = []

        for tool in tools:
            name = tool.get("name")
            if not name:
                continue

            current_hash = self.compute_spec_hash(tool)

            if name in self.pinned_hashes:
                expected_hash = self.pinned_hashes[name]
                if current_hash != expected_hash:
                    # Tool description or schema has changed!
                    old_spec = self.pinned_specs.get(name, {})
                    old_desc = old_spec.get("description", "")
                    new_desc = tool.get("description", "")

                    diff_msg = f"Description mutated from '{old_desc}' to '{new_desc}'"
                    alerts.append(
                        RugPullAlert(
                            tool_name=name,
                            original_hash=expected_hash,
                            new_hash=current_hash,
                            difference=diff_msg,
                            severity="CRITICAL",
                        )
                    )
            elif auto_pin_new:
                # First time seeing this tool
                self.pinned_hashes[name] = current_hash
                self.pinned_specs[name] = tool

        return alerts
