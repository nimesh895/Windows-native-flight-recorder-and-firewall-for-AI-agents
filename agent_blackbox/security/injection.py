from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HeuristicRule(BaseModel):
    id: str
    category: str
    weight: int
    pattern: re.Pattern
    description: str

    model_config = {"arbitrary_types_allowed": True}


HEURISTIC_RULES: List[HeuristicRule] = [
    # 1. System Prompt Override & Instruction Suppression (English)
    HeuristicRule(
        id="OVERRIDE_IGNORE_PREVIOUS",
        category="system_override",
        weight=40,
        pattern=re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)?\s*(?:instructions|prompts|directives|guidelines|rules)\b"),
        description="Attempt to suppress or override prior system instructions",
    ),
    HeuristicRule(
        id="OVERRIDE_NEW_PERSONA",
        category="system_override",
        weight=40,
        pattern=re.compile(r"(?i)\b(?:you\s+are\s+now|act\s+as)\s+(?:in\s+developer\s+mode|unrestricted|unfiltered|jailbroken|DAN|an\s+evil|chaos|developer\s+mode|a\s+hacker)\b"),
        description="Persona alteration / jailbreak phrase",
    ),
    HeuristicRule(
        id="OVERRIDE_MULTILINGUAL",
        category="system_override",
        weight=40,
        pattern=re.compile(
            r"(?i)(?:"
            r"\b(?:ignora|olvida|descarta)\s+(?:todas\s+las\s+)?(?:instrucciones|directrices|reglas)\b|"  # Spanish
            r"\b(?:ignorez|oubliez)\s+(?:toutes\s+les\s+)?(?:instructions|directives|règles)\b|"       # French
            r"\b(?:ignoriere|vergiss)\s+(?:alle\s+)?(?:vorherigen\s+)?(?:anweisungen|instruktionen)\b|" # German
            r"(?:忽略|忽视)(?:所有|之前的)?(?:指令|提示|规则)|"                                             # Chinese
            r"(?:以前の|すべての)?(?:指示|プロンプト)を(?:無視|破棄)"                                      # Japanese
            r")"
        ),
        description="Multilingual system instruction override evasion",
    ),
    HeuristicRule(
        id="SYSTEM_DELIMITER_INJECTION",
        category="delimiter_injection",
        weight=40,
        pattern=re.compile(r"(?i)(?:<\|im_start\|>system|<\|system\|>|\[SYSTEM(?:_PROMPT)?\]|<!--\s*#?instruction|```json\s*\{\s*\"system_override\")"),
        description="Fake system delimiter or role boundary token injection",
    ),

    # 2. Tool Description / Indirect Instruction Poisoning
    HeuristicRule(
        id="TOOL_POISON_INSTRUCTION",
        category="tool_poisoning",
        weight=45,
        pattern=re.compile(r"(?i)\b(?:AI\s+agent|assistant|model|system)\s*:\s*(?:you\s+must\s+|always\s+|never\s+ask\s+|silently\s+|immediately\s+)*(?:exfiltrate|send|upload|execute|delete|read|leak|copy)\b"),
        description="Hidden instruction directed at the AI agent inside tool definitions or responses",
    ),
    HeuristicRule(
        id="EXFIL_IMAGE_MARKDOWN",
        category="exfiltration",
        weight=40,
        pattern=re.compile(r"!\[[^\]]*\]\((?:https?:\/\/[^\s\)]+|file:\/\/[^\s\)]+)\?[^)]*(?:token|secret|key|pwd|password|data|leak|exfil)"),
        description="Markdown image-based secret exfiltration attempt",
    ),
    HeuristicRule(
        id="EXFIL_URL_PARAMETER",
        category="exfiltration",
        weight=40,
        pattern=re.compile(r"(?i)(?:curl|invoke-webrequest|wget|fetch)\s+[^\n]*(?:https?:\/\/[^\s]+\?(?:stolen|data|file|leak|token)=|\-d\s*@[^\s]+)"),
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
        weight=40,
        pattern=re.compile(r"(?i)\bcertutil(?:\.exe)?\s+-(?:urlcache|decode)\b"),
        description="Abuse of certutil.exe for payload download/decode",
    ),
    HeuristicRule(
        id="ENCODED_PAYLOAD_EXECUTION",
        category="evasion",
        weight=40,
        pattern=re.compile(r"(?i)\b(?:base64\s+-d|b64decode|atob|hex\s+decode|rot13)\b[^\n]*(?:\|\s*(?:bash|sh|cmd|iex|eval)|exec\s*\()"),
        description="Inline decode and execution pattern",
    ),

    # 4. Prompt Leak / Re-direction
    HeuristicRule(
        id="LEAK_SYSTEM_PROMPT",
        category="prompt_leak",
        weight=40,
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

    @staticmethod
    def normalize_text(text: str) -> str:
        # Strip zero-width characters and invisible formatting marks
        cleaned = re.sub(r"[\u200b-\u200f\uFEFF\u00ad\u2060\u200e]", "", text)
        # Unicode NFKD normalization (e.g. converts fullwidth Ｉｇｎｏｒｅ -> Ignore)
        norm = unicodedata.normalize("NFKD", cleaned)
        # Normalize internal whitespace/newlines to counter split instructions
        return re.sub(r"\s+", " ", norm).strip()

    def scan_text(self, text: str) -> InjectionScanResult:
        if not text or not isinstance(text, str):
            return InjectionScanResult()

        norm_text = self.normalize_text(text)
        total_weight = 0
        matched = []
        categories = set()

        for rule in self.rules:
            if rule.pattern.search(text) or rule.pattern.search(norm_text):
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
