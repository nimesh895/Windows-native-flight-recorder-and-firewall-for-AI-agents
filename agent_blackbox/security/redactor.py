from __future__ import annotations

import re
import hashlib
from typing import Any, Dict, List, Tuple, Union

SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("OPENAI_KEY", re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_\-]{20,})\b")),
    ("ANTHROPIC_KEY", re.compile(r"\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b")),
    ("AWS_KEY_ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("SLACK_TOKEN", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,})\b")),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "GENERIC_KEY_VALUE",
        re.compile(r"(?i)\b(password|passwd|secret|api_key|token|access_token|client_secret)\b\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\./+=]{8,})['\"]?"),
    ),
]


class SecretRedactor:
    """
    Scans and redacts sensitive credentials and secrets from text, arguments,
    and JSON payloads.
    Stores only the secret type and a truncated SHA-256 hash, NEVER the raw secret.
    """

    @staticmethod
    def hash_secret(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

    @classmethod
    def redact_text(cls, text: str) -> Tuple[str, List[Dict[str, str]]]:
        """
        Redacts detected secrets from a string.
        Returns (redacted_text, list_of_redaction_metadata).
        """
        if not text or not isinstance(text, str):
            return text, []

        redacted = text
        findings: List[Dict[str, str]] = []

        # 1. Private keys
        for key_type, pattern in SECRET_PATTERNS:
            if key_type == "GENERIC_KEY_VALUE":
                continue

            for match in pattern.finditer(redacted):
                raw_secret = match.group(0)
                sec_hash = cls.hash_secret(raw_secret)
                token_tag = f"[REDACTED_SECRET:{key_type}:{sec_hash}]"
                findings.append({"type": key_type, "hash": sec_hash})
                redacted = redacted.replace(raw_secret, token_tag)

        # 2. Key-value secrets (e.g. password = foo12345)
        for match in SECRET_PATTERNS[-1][1].finditer(redacted):
            key_name = match.group(1)
            raw_secret = match.group(2)
            if raw_secret.startswith("[REDACTED_SECRET:"):
                continue
            sec_hash = cls.hash_secret(raw_secret)
            token_tag = f"[REDACTED_SECRET:PARAM_{key_name.upper()}:{sec_hash}]"
            findings.append({"type": f"PARAM_{key_name.upper()}", "hash": sec_hash})
            # Replace only the value part
            old_str = match.group(0)
            new_str = old_str.replace(raw_secret, token_tag)
            redacted = redacted.replace(old_str, new_str)

        return redacted, findings

    @classmethod
    def redact_data(cls, data: Any) -> Any:
        """
        Recursively redacts secrets in dicts, lists, strings, and primitives.
        """
        if isinstance(data, str):
            redacted_str, _ = cls.redact_text(data)
            return redacted_str
        elif isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                # If key itself hints at credentials, mask value if non-empty string
                if isinstance(k, str) and any(kw in k.lower() for kw in ("password", "secret", "token", "apikey", "api_key", "credential")):
                    if isinstance(v, str) and v and not v.startswith("[REDACTED_SECRET:"):
                        sec_hash = cls.hash_secret(v)
                        new_dict[k] = f"[REDACTED_SECRET:KEY_{k.upper()}:{sec_hash}]"
                    else:
                        new_dict[k] = cls.redact_data(v)
                else:
                    new_dict[k] = cls.redact_data(v)
            return new_dict
        elif isinstance(data, list):
            return [cls.redact_data(item) for item in data]
        return data
