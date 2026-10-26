from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from agent_blackbox.security.windows_path import WindowsPathNormalizer


DEFAULT_SENSITIVE_FILE_PATTERNS = [
    r"(?i)\.env(?:\..*)?$",
    r"(?i)(?:credentials|passwords?|secrets?|tokens?)\.(?:json|ya?ml|txt|ini|conf)$",
    r"(?i)\.aws[\\/](?:credentials|config)$",
    r"(?i)\.ssh[\\/](?:id_rsa|id_ecdsa|id_ed25519)$",
    r"(?i).*\.(?:pem|key|pfx|p12)$",
    r"(?i).*honey.*",
]

NETWORK_TOOL_NAMES = {"http_request", "fetch", "curl", "send_request", "api_call", "download_file"}
FILE_READ_TOOL_NAMES = {"read_file", "view_file", "cat", "get_file_contents", "read_text_file"}


class SequenceViolation(BaseModel):
    is_blocked: bool = True
    domain: str
    trigger_sensitive_file: str
    severity: str = "CRITICAL"
    reason: str


class SessionSequenceTracker:
    """
    Enforces the session-level sequence invariant:
    After reading a sensitive file (e.g. .env, credentials, private keys),
    outbound requests to any domain not established *earlier* in the session are denied.
    """

    def __init__(
        self,
        sensitive_patterns: Optional[List[str]] = None,
        network_tools: Optional[Set[str]] = None,
        read_tools: Optional[Set[str]] = None,
    ):
        self.sensitive_patterns = [
            re.compile(p) for p in (sensitive_patterns or DEFAULT_SENSITIVE_FILE_PATTERNS)
        ]
        self.network_tools = network_tools or NETWORK_TOOL_NAMES
        self.read_tools = read_tools or FILE_READ_TOOL_NAMES

        # Tracks domains contacted BEFORE any sensitive file was read
        self.seen_domains: Set[str] = set()
        # Tracks sensitive files accessed in this session
        self.sensitive_files_accessed: List[str] = []

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        if not url:
            return None
        try:
            # Handle URLs missing scheme
            if "://" not in url:
                url = "http://" + url
            parsed = urlparse(url)
            return (parsed.hostname or "").lower()
        except Exception:
            return None

    def _is_sensitive_file(self, path_str: str) -> bool:
        if not path_str:
            return False
        norm = WindowsPathNormalizer.normalize(path_str)
        for pattern in self.sensitive_patterns:
            if pattern.search(norm) or pattern.search(path_str):
                return True
        return False

    def evaluate_call(self, tool_name: str, arguments: Any) -> Optional[SequenceViolation]:
        """
        Evaluates tool call against sequence rules.
        Returns a SequenceViolation if an exfiltration sequence is detected.
        """
        tool_lower = tool_name.lower()

        # 1. Outbound network call
        if tool_lower in self.network_tools and isinstance(arguments, dict):
            url = arguments.get("url") or arguments.get("endpoint") or ""
            domain = self.extract_domain(str(url))

            if domain:
                # If a sensitive file has already been read in this session
                if self.sensitive_files_accessed:
                    if domain not in self.seen_domains:
                        trigger_file = self.sensitive_files_accessed[-1]
                        return SequenceViolation(
                            is_blocked=True,
                            domain=domain,
                            trigger_sensitive_file=trigger_file,
                            severity="CRITICAL",
                            reason=(
                                f"Sequence violation: Outbound network request to unseen domain '{domain}' "
                                f"blocked after reading sensitive file '{trigger_file}'."
                            ),
                        )
                else:
                    # Sensitive files not yet touched: add to trusted seen domains
                    self.seen_domains.add(domain)

        # 2. File read call
        elif tool_lower in self.read_tools and isinstance(arguments, dict):
            path_val = str(arguments.get("path") or arguments.get("filepath") or arguments.get("filename") or "")
            if self._is_sensitive_file(path_val):
                if path_val not in self.sensitive_files_accessed:
                    self.sensitive_files_accessed.append(path_val)

        return None
