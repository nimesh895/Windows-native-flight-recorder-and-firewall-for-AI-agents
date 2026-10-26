from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agent_blackbox.security.windows_path import WindowsPathNormalizer


class TripwireAlert(BaseModel):
    alert_type: str  # "canary_file" or "canary_token"
    canary_id: str
    target: str
    severity: str = "CRITICAL"
    description: str


class CanaryManager:
    """
    Deploys and tracks canary honeyfiles and fake tokens.
    Detects when an AI agent touches, reads, writes, or references a canary.
    """

    def __init__(self, honeyfiles: Optional[List[str]] = None, tokens: Optional[List[str]] = None):
        self.honeyfiles: List[str] = []
        self.tokens: List[str] = []

        if honeyfiles:
            for hf in honeyfiles:
                self.register_honeyfile(hf)

        if tokens:
            for tok in tokens:
                self.register_token(tok)

    def register_honeyfile(self, file_path: str | Path) -> str:
        """
        Registers a normalized honeyfile path.
        """
        norm_path = WindowsPathNormalizer.normalize(file_path).lower()
        if norm_path not in self.honeyfiles:
            self.honeyfiles.append(norm_path)
        return norm_path

    def register_token(self, token: str) -> None:
        """
        Registers a canary secret token.
        """
        clean_tok = token.strip()
        if clean_tok and clean_tok not in self.tokens:
            self.tokens.append(clean_tok)

    def deploy_honeyfiles(self, target_dir: str | Path) -> Dict[str, str]:
        """
        Deploys realistic honeyfiles with embedded canary tokens in target_dir.
        Returns a mapping of filename to canary token.
        """
        deploy_dir = Path(target_dir)
        deploy_dir.mkdir(parents=True, exist_ok=True)

        token_aws = f"AKIA_CANARY_{secrets.token_hex(8).upper()}"
        token_anthropic = f"sk-ant-canary-prod-{secrets.token_hex(16)}"
        token_db = f"postgres://dbadmin:{secrets.token_urlsafe(16)}@honey-db.internal:5432/production"

        self.register_token(token_aws)
        self.register_token(token_anthropic)
        self.register_token(token_db)

        files_created = {}

        # 1. AWS honeyfile
        aws_path = deploy_dir / "aws_credentials.honey.json"
        aws_data = {
            "default": {
                "aws_access_key_id": token_aws,
                "aws_secret_access_key": secrets.token_hex(20),
                "region": "us-east-1",
            }
        }
        with open(aws_path, "w", encoding="utf-8") as f:
            json.dump(aws_data, f, indent=2)
        norm_aws = self.register_honeyfile(aws_path)
        files_created["aws_credentials.honey.json"] = token_aws

        # 2. Environment honeyfile
        env_path = deploy_dir / ".env.canary"
        env_content = f"# Production Environment Secrets\nANTHROPIC_API_KEY={token_anthropic}\nDATABASE_URL={token_db}\n"
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(env_content)
        self.register_honeyfile(env_path)
        files_created[".env.canary"] = token_anthropic

        # 3. Honey passwords file
        passwords_path = deploy_dir / "passwords_backup.txt"
        pass_content = f"ADMIN_PORTAL=https://vpn.internal/login\nMASTER_KEY=CANARY_KEY_{secrets.token_hex(12)}\n"
        with open(passwords_path, "w", encoding="utf-8") as f:
            f.write(pass_content)
        self.register_honeyfile(passwords_path)
        files_created["passwords_backup.txt"] = "MASTER_KEY"

        return files_created

    def check_arguments_and_payload(self, tool_name: str, arguments: Any,
                                   response_data: Optional[Any] = None) -> List[TripwireAlert]:
        """
        Inspects tool arguments, paths, and response data for any canary trips.
        """
        alerts: List[TripwireAlert] = []

        # Convert arguments to string for token matching
        args_str = json.dumps(arguments, ensure_ascii=False) if arguments is not None else ""
        resp_str = json.dumps(response_data, ensure_ascii=False) if response_data is not None else ""

        # Check for canary tokens in arguments or responses
        for token in self.tokens:
            if token in args_str:
                alerts.append(TripwireAlert(
                    alert_type="canary_token",
                    canary_id=token[:10] + "...",
                    target=tool_name,
                    severity="CRITICAL",
                    description=f"Canary secret token detected in arguments of tool '{tool_name}'",
                ))
            if resp_str and token in resp_str:
                alerts.append(TripwireAlert(
                    alert_type="canary_token",
                    canary_id=token[:10] + "...",
                    target=tool_name,
                    severity="CRITICAL",
                    description=f"Canary secret token leaked in response of tool '{tool_name}'",
                ))

        # Check for honeyfile paths
        def scan_for_paths(item: Any):
            if isinstance(item, str):
                # If looks like a path or contains a filename
                try:
                    norm = WindowsPathNormalizer.normalize(item).lower()
                    for hf in self.honeyfiles:
                        if norm == hf or norm.endswith(Path(hf).name.lower()):
                            alerts.append(TripwireAlert(
                                alert_type="canary_file",
                                canary_id=Path(hf).name,
                                target=item,
                                severity="CRITICAL",
                                description=f"AI agent attempted to access canary honeyfile: {item}",
                            ))
                except Exception:
                    pass
            elif isinstance(item, dict):
                for v in item.values():
                    scan_for_paths(v)
            elif isinstance(item, list):
                for elem in item:
                    scan_for_paths(elem)

        if arguments:
            scan_for_paths(arguments)

        return alerts
