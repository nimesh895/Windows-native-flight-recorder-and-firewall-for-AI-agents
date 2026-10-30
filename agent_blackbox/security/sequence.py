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
    r"(?i)(?:^|[\\/])(?:id_rsa|id_ecdsa|id_ed25519|id_dsa)(?:\.pub)?$",
    r"(?i).*\.(?:pem|key|pfx|p12)$",
    r"(?i).*honey.*",
]

NETWORK_TOOL_NAMES = {"http_request", "fetch", "curl", "send_request", "api_call", "download_file"}
FILE_READ_TOOL_NAMES = {"read_file", "view_file", "cat", "get_file_contents", "read_text_file"}
FILE_WRITE_TOOL_NAMES = {"write_file", "save_file", "append_file", "create_file", "edit_file"}
SHELL_TOOL_NAMES = {"run_command", "execute_command", "bash", "powershell", "cmd", "terminal", "exec"}

DOMAIN_REGEX_IN_COMMAND = re.compile(
    r"(?i)(?:https?:\/\/|ftp:\/\/|(?<=\s))([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?::\d+)?(?=[\/\s\"'\?\&]|$)"
)


class SequenceViolation(BaseModel):
    is_blocked: bool = True
    domain: str
    trigger_sensitive_file: str
    severity: str = "CRITICAL"
    reason: str


class SessionSequenceTracker:
    """
    Enforces session-level sequencing invariants:
    1. After reading a sensitive file (.env, credentials, keys), outbound requests
       (via HTTP or shell commands) to domains not seen earlier in the session are denied.
    2. Optional strict domain allowlist mode: denies any outbound request to non-allowlisted domains.
    3. Monitored write_file after sensitive file access to prevent local exfiltration staging.
    4. Domain pre-seeding: allows whitelisting authorized endpoints prior to session execution.
    """

    def __init__(
        self,
        sensitive_patterns: Optional[List[str]] = None,
        network_tools: Optional[Set[str]] = None,
        read_tools: Optional[Set[str]] = None,
        write_tools: Optional[Set[str]] = None,
        shell_tools: Optional[Set[str]] = None,
        preseed_domains: Optional[List[str]] = None,
        domain_allowlist: Optional[List[str]] = None,
        allowlist_mode: bool = False,
        workspace_root: Optional[str] = None,
    ):
        self.sensitive_patterns = [
            re.compile(p) for p in (sensitive_patterns or DEFAULT_SENSITIVE_FILE_PATTERNS)
        ]
        self.network_tools = network_tools or NETWORK_TOOL_NAMES
        self.read_tools = read_tools or FILE_READ_TOOL_NAMES
        self.write_tools = write_tools or FILE_WRITE_TOOL_NAMES
        self.shell_tools = shell_tools or SHELL_TOOL_NAMES

        # Tracks domains contacted BEFORE any sensitive file was read (or pre-seeded)
        self.seen_domains: Set[str] = set()
        if preseed_domains:
            self.seed_domains(preseed_domains)

        # Allowlist mode configuration
        self.allowlist_mode = allowlist_mode
        self.domain_allowlist: Set[str] = set()
        if domain_allowlist:
            for d in domain_allowlist:
                clean_d = self.extract_domain(d) or d.lower().strip()
                self.domain_allowlist.add(clean_d)

        # Tracks sensitive files accessed in this session
        self.sensitive_files_accessed: List[str] = []
        self.workspace_root = workspace_root

    def seed_domains(self, domains: List[str]) -> None:
        """
        Pre-seeds domains as authorized / seen prior to session tool calls.
        """
        for d in domains:
            clean = self.extract_domain(d) or d.lower().strip()
            if clean:
                self.seen_domains.add(clean)
                if self.allowlist_mode:
                    self.domain_allowlist.add(clean)

    @staticmethod
    def extract_domain(url_or_host: str) -> Optional[str]:
        if not url_or_host:
            return None
        text = str(url_or_host).strip()
        try:
            if "://" not in text:
                text = "http://" + text
            parsed = urlparse(text)
            host = parsed.hostname or ""
            return host.lower() if host else None
        except Exception:
            return None

    def _extract_domains_from_shell_cmd(self, cmd_text: str) -> List[str]:
        domains = []
        matches = DOMAIN_REGEX_IN_COMMAND.finditer(cmd_text)
        for m in matches:
            candidate = m.group(1).lower()
            # Ignore common file extensions mistaken for domains
            if not candidate.endswith((".py", ".js", ".json", ".txt", ".md", ".exe", ".dll", ".ps1", ".yaml", ".yml")):
                domains.append(candidate)
        return domains

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
        Evaluates tool call against sequence rules across HTTP, shell, and write_file tools.
        """
        tool_lower = tool_name.lower()

        # 1. Outbound network tool (e.g. http_request, fetch)
        if tool_lower in self.network_tools and isinstance(arguments, dict):
            url = arguments.get("url") or arguments.get("endpoint") or ""
            domain = self.extract_domain(str(url))

            if domain:
                # Check strict allowlist mode
                if self.allowlist_mode and domain not in self.domain_allowlist:
                    return SequenceViolation(
                        is_blocked=True,
                        domain=domain,
                        trigger_sensitive_file="[ALLOWLIST_MODE]",
                        severity="CRITICAL",
                        reason=f"Domain allowlist violation: Outbound request to '{domain}' not in configured allowlist.",
                    )

                # Check sensitive sequence invariant
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
                    self.seen_domains.add(domain)

        # 2. Shell tool (e.g. run_command, bash, powershell)
        elif tool_lower in self.shell_tools and isinstance(arguments, dict):
            cmd_text = str(arguments.get("command") or arguments.get("cmd") or arguments.get("script") or "")
            detected_domains = self._extract_domains_from_shell_cmd(cmd_text)

            for d in detected_domains:
                if self.allowlist_mode and d not in self.domain_allowlist:
                    return SequenceViolation(
                        is_blocked=True,
                        domain=d,
                        trigger_sensitive_file="[ALLOWLIST_MODE]",
                        severity="CRITICAL",
                        reason=f"Domain allowlist violation: Shell command targets '{d}' not in configured allowlist.",
                    )

                if self.sensitive_files_accessed and d not in self.seen_domains:
                    trigger_file = self.sensitive_files_accessed[-1]
                    return SequenceViolation(
                        is_blocked=True,
                        domain=d,
                        trigger_sensitive_file=trigger_file,
                        severity="CRITICAL",
                        reason=(
                            f"Sequence violation: Shell command targeting unseen external domain '{d}' "
                            f"blocked after reading sensitive file '{trigger_file}'."
                        ),
                    )
                elif not self.sensitive_files_accessed:
                    self.seen_domains.add(d)

        # 3. File write tool (write_file, save_file) after sensitive file read
        elif tool_lower in self.write_tools and isinstance(arguments, dict):
            path_val = str(arguments.get("path") or arguments.get("filepath") or arguments.get("target") or "")
            if self.sensitive_files_accessed:
                norm_target = WindowsPathNormalizer.normalize(path_val).lower()
                # Check for suspicious external drop/staging paths
                suspicious_drops = ("public/", "temp/", "tmp/", "appdata/", "\\\\", "dropbox/", "desktop/")
                if any(drop in norm_target for drop in suspicious_drops):
                    trigger_file = self.sensitive_files_accessed[-1]
                    return SequenceViolation(
                        is_blocked=True,
                        domain="local_exfil_staging",
                        trigger_sensitive_file=trigger_file,
                        severity="HIGH",
                        reason=(
                            f"Sequence violation: Writing to staging location '{path_val}' "
                            f"blocked after reading sensitive file '{trigger_file}'."
                        ),
                    )

        # 4. File read tool
        elif tool_lower in self.read_tools and isinstance(arguments, dict):
            path_val = str(arguments.get("path") or arguments.get("filepath") or arguments.get("filename") or "")
            if self._is_sensitive_file(path_val):
                if path_val not in self.sensitive_files_accessed:
                    self.sensitive_files_accessed.append(path_val)

        return None
