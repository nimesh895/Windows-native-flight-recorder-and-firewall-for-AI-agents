from __future__ import annotations

import json
import base64
import urllib.parse
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
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

    def _token_variants(self, token: str) -> List[str]:
        """
        Generates standard encoding variations for a canary token:
        - Raw token
        - Standard Base64
        - URL-safe Base64 (with and without padding)
        - URL-encoded (standard and quote_plus)
        """
        variants = {token}
        tok_bytes = token.encode("utf-8")

        # Base64 standard
        b64_std = base64.b64encode(tok_bytes).decode("utf-8")
        variants.add(b64_std)

        # Base64 urlsafe
        b64_url = base64.urlsafe_b64encode(tok_bytes).decode("utf-8")
        variants.add(b64_url)
        variants.add(b64_url.rstrip("="))

        # URL encoded
        url_enc = urllib.parse.quote(token, safe="")
        variants.add(url_enc)
        variants.add(urllib.parse.quote_plus(token))

        return [v for v in variants if v]

    def _extract_decoded_candidates(self, text: str) -> Set[str]:
        """
        Extracts candidate strings from URL decoding and Base64 decoding of embedded blobs.
        """
        candidates = {text}

        # 1. URL decoding
        try:
            unquoted = urllib.parse.unquote(text)
            if unquoted != text:
                candidates.add(unquoted)
        except Exception:
            pass

        # 2. Extract potential base64 sequences (min 16 chars)
        b64_regex = re.compile(r"\b([A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2})\b")
        for match in b64_regex.finditer(text):
            chunk = match.group(1)
            # Try standard b64 decode
            for pad in range(4):
                padded = chunk + ("=" * pad)
                try:
                    decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
                    if decoded and len(decoded) >= 8:
                        candidates.add(decoded)
                    break
                except Exception:
                    pass

        return candidates

    def check_arguments_and_payload(self, tool_name: str, arguments: Any,
                                   response_data: Optional[Any] = None) -> List[TripwireAlert]:
        """
        Inspects tool arguments, paths, and response data for any canary trips,
        including base64 and URL-encoded token variations.
        """
        alerts: List[TripwireAlert] = []

        # Convert arguments and response to string
        args_str = json.dumps(arguments, ensure_ascii=False) if arguments is not None else ""
        resp_str = json.dumps(response_data, ensure_ascii=False) if response_data is not None else ""

        args_candidates = self._extract_decoded_candidates(args_str) if args_str else set()
        resp_candidates = self._extract_decoded_candidates(resp_str) if resp_str else set()

        # Check for canary tokens across raw and decoded candidates
        for token in self.tokens:
            variants = self._token_variants(token)
            
            # Check in arguments
            triggered_arg = False
            for cand in args_candidates:
                for var in variants:
                    if var in cand:
                        alerts.append(TripwireAlert(
                            alert_type="canary_token",
                            canary_id=token[:10] + "...",
                            target=tool_name,
                            severity="CRITICAL",
                            description=f"Canary secret token (raw or encoded) detected in arguments of tool '{tool_name}'",
                        ))
                        triggered_arg = True
                        break
                if triggered_arg:
                    break

            # Check in response
            triggered_resp = False
            for cand in resp_candidates:
                for var in variants:
                    if var in cand:
                        alerts.append(TripwireAlert(
                            alert_type="canary_token",
                            canary_id=token[:10] + "...",
                            target=tool_name,
                            severity="CRITICAL",
                            description=f"Canary secret token (raw or encoded) leaked in response of tool '{tool_name}'",
                        ))
                        triggered_resp = True
                        break
                if triggered_resp:
                    break

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
