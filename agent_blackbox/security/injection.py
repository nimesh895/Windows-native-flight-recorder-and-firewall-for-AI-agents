from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HeuristicRule(BaseModel):
    id: str
    category: str
    weight: int
    pattern: re.Pattern
    description: str

    class Config:
        arbitrary_types_allowed = True


HEURISTIC_RULES: List[HeuristicRule] = [
    # 1. System Prompt Override & Instruction Suppression
    HeuristicRule(
        id="OVERRIDE_IGNORE_PREVIOUS",
        category="system_override",
        weight=40,
        pattern=re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|directives|guidelines)\b"),
        description="Attempt to suppress or override prior system instructions",
    ),
    HeuristicRule(
        id="OVERRIDE_NEW_PERSONA",
        category="system_override",
        weight=35,
        pattern=re.compile(r"(?i)\b(?:you\s+are\s+now|act\s+as)\s+(?:unrestricted|unfiltered|jailbroken|DAN|an\s+evil|chaos)\b"),
        description="Persona alteration / jailbreak phrase",
    ),
    HeuristicRule(
        id="SYSTEM_DELIMITER_INJECTION",
        category="delimiter_injection",
        weight=30,
        pattern=re.compile(r"(?i)(?:<\|im_start\|>system|<\|system\|>|\[SYSTEM(?:_PROMPT)?\]|<!--\s*#?instruction|```json\s*\{\s*\"system_override\")"),
        description="Fake system delimiter or role boundary token injection",
    ),

    # 2. Tool Description / Indirect Instruction Poisoning
    HeuristicRule(
        id="TOOL_POISON_INSTRUCTION",
        category="tool_poisoning",
        weight=45,
        pattern=re.compile(r"(?i)\b(?:AI\s+agent|assistant|model)\s*:\s*(?:you\s+must|always|never\s+ask|silently|immediately)\s+(?:exfiltrate|send|upload|execute|delete|read)\b"),
        description="Hidden instruction directed at the AI agent inside tool definitions or responses",
    ),
    HeuristicRule(
        id="EXFIL_IMAGE_MARKDOWN",
        category="exfiltration",
        weight=35,
        pattern=re.compile(r"!\[[^\]]*\]\((?:https?:\/\/[^\s\)]+|file:\/\/[^\s\)]+)\?[^)]*(?:token|secret|key|pwd|password|data|leak|exfil)"),
        description="Markdown image-based secret exfiltration attempt",
    ),
    HeuristicRule(
        id="EXFIL_URL_PARAMETER",
        category="exfiltration",
        weight=30,
        pattern=re.compile(r"(?i)(?:curl|invoke-webrequest|wget|fetch)\s+[^\n]*(?:https?:\/\/[^\s]+\?(?:stolen|data|file|leak)=|\-d\s*@[^\s]+)"),
        description="Outbound network exfiltration command pattern",
    ),

    # 3. Windows-Specific Evasion & Command Injections
    HeuristicRule(
        id="WIN_ENCODED_POWERSHELL",
        category="evasion",
        weight=40,
        pattern=re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\s+-[eE](?:nc(?:odedCommand)?)?\s+[A-Za-z0-9+/=]{16,}"),
        description="Base64-encoded PowerShell command execution",
    ),
    HeuristicRule(
        id="WIN_ADS_EXECUTION",
        category="evasion",
        weight=40,
        pattern=re.compile(r"(?i)(?:wmic|cscript|wscript|cmd|powershell)\b[^\n]*:[^\s\/\\\:]+\.(?:vbs|js|ps1|bat|exe|dll)"),
        description="Execution via Windows Alternate Data Stream (ADS)",
    ),
    HeuristicRule(
        id="WIN_SUSPICIOUS_CERTUTIL",
        category="evasion",
        weight=35,
        pattern=re.compile(r"(?i)\bcertutil(?:\.exe)?\s+-(?:urlcache|decode)\b"),
        description="Abuse of certutil.exe for payload download/decode",
    ),

    # 4. Prompt Leak / Re-direction
    HeuristicRule(
        id="LEAK_SYSTEM_PROMPT",
        category="prompt_leak",
        weight=25,
        pattern=re.compile(r"(?i)\b(?:repeat|print|output|display|show)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+rules)\b"),
        description="Prompt extraction attempt",
    ),
]


class InjectionScanResult(BaseModel):
    is_flagged: bool = False
    risk_score: int = 0  # 0 to 100
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    matched_heuristics: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)


class InjectionScanner:
    """
    Analyzes tool definitions, tool arguments, and tool output payloads
    for prompt injection, jailbreaks, hidden instructions, and indirect injection.
    """

    def __init__(self, threshold_score: int = 50):
        self.threshold_score = threshold_score
        self.rules = HEURISTIC_RULES

    def scan_text(self, text: str) -> InjectionScanResult:
        if not text or not isinstance(text, str):
            return InjectionScanResult()

        total_weight = 0
        matched = []
        categories = set()

        for rule in self.rules:
            if rule.pattern.search(text):
                total_weight += rule.weight
                matched.append(f"{rule.id}: {rule.description}")
                categories.add(rule.category)

        # Cap score at 100
        score = min(total_weight, 100)
        is_flagged = score >= self.threshold_score

        if score >= 75:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        elif score > 0:
            severity = "LOW"
        else:
            severity = "INFO"

        return InjectionScanResult(
            is_flagged=is_flagged,
            risk_score=score,
            severity=severity,
            matched_heuristics=matched,
            categories=list(categories),
        )

    def scan_tool_spec(self, tool_spec: Dict[str, Any]) -> InjectionScanResult:
        """
        Scans an MCP tool definition for poisoning (e.g. malicious instructions in tool descriptions).
        """
        texts = []
        name = tool_spec.get("name", "")
        desc = tool_spec.get("description", "")
        texts.append(f"{name} {desc}")

        params = tool_spec.get("inputSchema", {})
        if isinstance(params, dict):
            for prop_name, prop_val in params.get("properties", {}).items():
                if isinstance(prop_val, dict):
                    texts.append(prop_val.get("description", ""))

        full_text = "\n".join(texts)
        return self.scan_text(full_text)

    def scan_tool_call(self, tool_name: str, arguments: Any) -> InjectionScanResult:
        """
        Scans tool call arguments for injection attacks.
        """
        if isinstance(arguments, (dict, list)):
            import json
            text = json.dumps(arguments, ensure_ascii=False)
        else:
            text = str(arguments)
        return self.scan_text(f"{tool_name}: {text}")

    def scan_tool_response(self, response_data: Any) -> InjectionScanResult:
        """
        Scans tool output/response for indirect prompt injection attempts.
        """
        if isinstance(response_data, (dict, list)):
            import json
            text = json.dumps(response_data, ensure_ascii=False)
        else:
            text = str(response_data)
        return self.scan_text(text)
