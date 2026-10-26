from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field
import yaml


class PolicyRule(BaseModel):
    name: str
    action: Literal["allow", "deny", "ask", "monitor"] = "deny"
    description: Optional[str] = None
    tools: List[str] = Field(default_factory=lambda: ["*"])
    argument_patterns: Dict[str, str] = Field(default_factory=dict)
    allowed_paths: List[str] = Field(default_factory=list)
    forbidden_paths: List[str] = Field(default_factory=list)
    block_ads: bool = True  # Block Windows Alternate Data Streams
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"


class CanaryConfig(BaseModel):
    enabled: bool = True
    honeyfiles: List[str] = Field(default_factory=list)
    tokens: List[str] = Field(default_factory=list)
    alert_severity: Literal["HIGH", "CRITICAL"] = "CRITICAL"


class InjectionScannerConfig(BaseModel):
    enabled: bool = True
    threshold_score: int = 50  # Risk score 0-100 threshold to flag
    scan_tool_descriptions: bool = True
    scan_tool_arguments: bool = True
    scan_tool_responses: bool = True
    alert_severity: Literal["MEDIUM", "HIGH", "CRITICAL"] = "HIGH"


class AuditConfig(BaseModel):
    db_path: str = "blackbox_audit.db"
    key_dir: str = ".blackbox_keys"
    private_key_file: str = "ed25519_private.pem"
    public_key_file: str = "ed25519_public.pem"
    redact_secrets: bool = True


class DashboardConfig(BaseModel):
    host: str = "127.0.0.1"  # Bound strictly to 127.0.0.1
    port: int = 8420
    session_token: str = Field(default_factory=lambda: secrets.token_hex(16))
    open_browser: bool = False


class BlackboxConfig(BaseModel):
    mode: Literal["monitor", "ask", "enforce"] = "enforce"
    fail_mode: Literal["fail-closed", "fail-open"] = "fail-closed"
    workspace_root: str = Field(default_factory=lambda: os.getcwd())
    rules: List[PolicyRule] = Field(default_factory=list)
    canaries: CanaryConfig = Field(default_factory=CanaryConfig)
    injection_scanner: InjectionScannerConfig = Field(default_factory=InjectionScannerConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)

    @classmethod
    def load_from_yaml(cls, path: str | Path) -> BlackboxConfig:
        filepath = Path(path)
        if not filepath.exists():
            return cls()
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)

    def save_to_yaml(self, path: str | Path) -> None:
        filepath = Path(path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.model_dump(), f, default_flow_style=False)
