from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


# Common PowerShell dangerous cmdlet aliases
PS_ALIASES: Dict[str, str] = {
    "iwr": "Invoke-WebRequest",
    "wget": "Invoke-WebRequest",
    "curl": "Invoke-WebRequest",
    "irm": "Invoke-RestMethod",
    "iex": "Invoke-Expression",
    "icm": "Invoke-Command",
    "cat": "Get-Content",
    "gc": "Get-Content",
    "type": "Get-Content",
    "gci": "Get-ChildItem",
    "ls": "Get-ChildItem",
    "dir": "Get-ChildItem",
    "sc": "Set-Content",
    "ac": "Add-Content",
    "del": "Remove-Item",
    "rm": "Remove-Item",
    "rmdir": "Remove-Item",
    "rd": "Remove-Item",
    "kill": "Stop-Process",
    "saps": "Start-Process",
    "start": "Start-Process",
}

# Regex to detect string concatenation obfuscation: 'c'+'u'+'r'+'l'
CONCAT_REGEX = re.compile(r"['\"]([a-zA-Z0-9_\-\.\:\/]+)['\"]\s*\+\s*['\"]([a-zA-Z0-9_\-\.\:\/]+)['\"]")

# Regex to detect backtick escaping: i`e`x or c`u`r`l
BACKTICK_ESCAPE = re.compile(r"`([a-zA-Z])")

# Regex to detect variable expansion: $env:TEMP or $HOME
ENV_VAR_REGEX = re.compile(r"\$(?:env:)?([a-zA-Z0-9_]+)", re.IGNORECASE)


class ParsedCommandAST(BaseModel):
    raw_command: str
    deobfuscated_command: str
    invocations: List[str] = Field(default_factory=list)
    resolved_cmdlets: List[str] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_paths: List[str] = Field(default_factory=list)
    has_ads: bool = False
    has_encoded_payload: bool = False
    has_obfuscation: bool = False


class PowerShellASTDeconstructor:
    """
    Deconstructs, normalizes, and de-obfuscates PowerShell and Windows command lines:
    1. Removes backtick escape characters (e.g. i`e`x -> iex).
    2. Resolves string concatenation (e.g. 'down'+'load' -> 'download').
    3. Resolves cmdlet aliases (iwr -> Invoke-WebRequest, iex -> Invoke-Expression).
    4. Identifies Alternate Data Streams (ADS) execution (e.g. wmic ... :evil.ps1).
    5. Extracts command pipeline elements and parameter arguments.
    """

    @classmethod
    def deobfuscate_string(cls, text: str) -> Tuple[str, bool]:
        """
        Removes backticks and folds string concatenations.
        """
        has_obfuscation = False
        res = text

        # 1. Backtick removal in identifier context
        if "`" in res:
            new_res = BACKTICK_ESCAPE.sub(r"\1", res)
            if new_res != res:
                has_obfuscation = True
                res = new_res

        # 2. String concatenation folding
        while True:
            new_res = CONCAT_REGEX.sub(r"'\1\2'", res)
            if new_res == res:
                break
            has_obfuscation = True
            res = new_res

        # 3. Environment variable common replacements
        env_map = {
            "$env:temp": "C:/Temp",
            "$env:tmp": "C:/Temp",
            "$env:windir": "C:/Windows",
            "$env:systemroot": "C:/Windows",
        }
        for var, val in env_map.items():
            if var in res.lower():
                res = re.sub(re.escape(var), val, res, flags=re.IGNORECASE)

        return res, has_obfuscation

    @classmethod
    def parse_command(cls, raw_cmd: str) -> ParsedCommandAST:
        if not raw_cmd or not isinstance(raw_cmd, str):
            return ParsedCommandAST(raw_command="", deobfuscated_command="")

        deobfuscated, has_obf = cls.deobfuscate_string(raw_cmd)

        # Split on pipelines (|) and command separators (; and &)
        segments = re.split(r"[|;&]", deobfuscated)
        invocations = []
        resolved_cmdlets = []
        urls = []
        paths = []
        has_ads = False

        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue

            invocations.append(seg)
            tokens = seg.split()
            if not tokens:
                continue

            head = tokens[0].lower().rstrip(".exe")
            # Resolve alias
            resolved = PS_ALIASES.get(head, head)
            resolved_cmdlets.append(resolved)

            # Check tokens for URLs, paths, and ADS
            for tok in tokens[1:]:
                clean_tok = tok.strip("\"'()")
                # Check for URLs
                if clean_tok.startswith(("http://", "https://", "ftp://")):
                    urls.append(clean_tok)
                # Check for paths
                elif "\\" in clean_tok or "/" in clean_tok or clean_tok.endswith((".txt", ".ps1", ".exe", ".dll", ".bat", ".key")):
                    paths.append(clean_tok)

                # Check for Alternate Data Stream (file.txt:stream.ps1)
                if ":" in clean_tok and not clean_tok.startswith(("http:", "https:", "ftp:")):
                    parts = clean_tok.split(":")
                    if len(parts) >= 2 and len(parts[0]) > 1:  # Not just C:\
                        has_ads = True

        # Check for Base64 encoded flags (-e, -enc, -encodedcommand)
        has_encoded = bool(
            re.search(r"(?i)\b(?:powershell|pwsh)\b[^\n]*\s+-[eE](?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}", deobfuscated)
        )

        return ParsedCommandAST(
            raw_command=raw_cmd,
            deobfuscated_command=deobfuscated,
            invocations=invocations,
            resolved_cmdlets=resolved_cmdlets,
            extracted_urls=urls,
            extracted_paths=paths,
            has_ads=has_ads,
            has_encoded_payload=has_encoded,
            has_obfuscation=has_obf,
        )
