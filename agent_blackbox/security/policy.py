from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from agent_blackbox.config import BlackboxConfig, PolicyRule
from agent_blackbox.security.windows_path import WindowsPathNormalizer
from agent_blackbox.security.canaries import CanaryManager, TripwireAlert
from agent_blackbox.security.injection import InjectionScanner, InjectionScanResult
from agent_blackbox.security.sequence import SessionSequenceTracker, SequenceViolation
from agent_blackbox.security.entropy import EntropyScanner, HighEntropyFinding
from agent_blackbox.security.risk_accumulator import SessionRiskAccumulator

logger = logging.getLogger("agent_blackbox.policy")


class PolicyDecision(BaseModel):
    allowed: bool
    mode: str  # "monitor", "ask", "enforce"
    reason: str
    rule_name: Optional[str] = None
    risk_score: int = 0
    severity: str = "INFO"
    canary_alerts: List[TripwireAlert] = Field(default_factory=list)
    injection_alert: Optional[InjectionScanResult] = None
    entropy_findings: List[HighEntropyFinding] = Field(default_factory=list)
    cumulative_risk: Optional[Dict[str, Any]] = None
    normalized_arguments: Optional[Any] = None
    is_blocked: bool = False
    requires_approval: bool = False


class PolicyEngine:
    """
    Evaluates AI agent tool calls against security policies, canary tripwires,
    injection heuristics, and Windows-specific path restrictions.
    """

    def __init__(self, config: BlackboxConfig):
        self.config = config
        self.canary_mgr = CanaryManager(
            honeyfiles=config.canaries.honeyfiles,
            tokens=config.canaries.tokens,
        )
        self.injection_scanner = InjectionScanner(
            threshold_score=config.injection_scanner.threshold_score
        )
        self.sequence_tracker = SessionSequenceTracker()
        self.entropy_scanner = EntropyScanner()
        self.risk_accumulator = SessionRiskAccumulator()

    def _extract_paths(self, arguments: Any) -> List[Tuple[str, str]]:
        """
        Recursively extracts argument keys and potential path strings.
        Returns list of (param_name, path_value).
        """
        paths = []
        path_key_hints = ("path", "file", "dir", "dest", "source", "filepath", "target", "filename")

        if isinstance(arguments, dict):
            for k, v in arguments.items():
                if isinstance(v, str):
                    if any(hint in k.lower() for hint in path_key_hints) or "\\" in v or "/" in v or ":" in v:
                        paths.append((k, v))
                elif isinstance(v, (dict, list)):
                    paths.extend(self._extract_paths(v))
        elif isinstance(arguments, list):
            for item in arguments:
                paths.extend(self._extract_paths(item))

        return paths

    def evaluate_call(self, tool_name: str, arguments: Any) -> PolicyDecision:
        """
        Evaluates a tool call according to active configuration and rules.
        Guaranteed to obey fail-closed or fail-open on evaluation errors.
        Updates stateful cumulative session risk tracker with time-decay.
        """
        try:
            decision = self._evaluate_inner(tool_name, arguments)
            # Accumulate risk in stateful session tracker
            cum_risk = self.risk_accumulator.record_risk(
                tool_name=tool_name,
                delta_risk=decision.risk_score,
                reason=decision.reason,
            )
            decision.cumulative_risk = cum_risk

            # If cumulative risk exceeds quarantine threshold, enforce lockout
            if cum_risk["needs_quarantine"] and self.config.mode == "enforce":
                decision.allowed = False
                decision.is_blocked = True
                decision.severity = "CRITICAL"
                decision.reason = f"Cumulative session risk threshold exceeded ({cum_risk['cumulative_score']} pts): {decision.reason}"

            # Check if review/approval is needed
            if cum_risk["needs_review"] or decision.rule_name == "ASK":
                decision.requires_approval = True

            return decision
        except Exception as e:
            logger.exception("Error evaluating policy for tool %s: %s", tool_name, e)
            if self.config.fail_mode == "fail-closed":
                return PolicyDecision(
                    allowed=False,
                    is_blocked=True,
                    mode=self.config.mode,
                    reason=f"Policy evaluation failure [fail-closed active]: {str(e)}",
                    severity="CRITICAL",
                    risk_score=100,
                )
            else:
                return PolicyDecision(
                    allowed=True,
                    is_blocked=False,
                    mode=self.config.mode,
                    reason=f"Policy evaluation failure [fail-open permitted]: {str(e)}",
                    severity="HIGH",
                    risk_score=75,
                )

    def _evaluate_inner(self, tool_name: str, arguments: Any) -> PolicyDecision:
        mode = self.config.mode
        extracted_paths = self._extract_paths(arguments)

        # 1. Canary check
        canary_alerts = []
        if self.config.canaries.enabled:
            canary_alerts = self.canary_mgr.check_arguments_and_payload(tool_name, arguments)
            if canary_alerts:
                reason = f"Canary tripwire triggered: {canary_alerts[0].description}"
                is_blocked = (mode == "enforce")
                return PolicyDecision(
                    allowed=not is_blocked,
                    is_blocked=is_blocked,
                    mode=mode,
                    reason=reason,
                    rule_name="CANARY_TRIPWIRE",
                    risk_score=100,
                    severity="CRITICAL",
                    canary_alerts=canary_alerts,
                )

        # 1b. Session sequence check (e.g. sensitive read followed by unseen outbound domain)
        seq_alert = self.sequence_tracker.evaluate_call(tool_name, arguments)
        if seq_alert:
            is_blocked = (mode == "enforce")
            return PolicyDecision(
                allowed=not is_blocked,
                is_blocked=is_blocked,
                mode=mode,
                reason=seq_alert.reason,
                rule_name="SEQUENCE_SENSITIVE_READ_THEN_UNSEEN_OUTBOUND",
                risk_score=100,
                severity=seq_alert.severity,
            )

        # 2. Injection scanner check
        inj_alert = None
        if self.config.injection_scanner.enabled and self.config.injection_scanner.scan_tool_arguments:
            inj_alert = self.injection_scanner.scan_tool_call(tool_name, arguments)
            if inj_alert.is_flagged:
                reason = f"Prompt injection heuristic triggered: {'; '.join(inj_alert.matched_heuristics)}"
                is_blocked = (mode == "enforce")
                return PolicyDecision(
                    allowed=not is_blocked,
                    is_blocked=is_blocked,
                    mode=mode,
                    reason=reason,
                    rule_name="INJECTION_HEURISTIC",
                    risk_score=inj_alert.risk_score,
                    severity=inj_alert.severity,
                    injection_alert=inj_alert,
                )

        # 2b. Zero-day high entropy credential scan
        import json
        args_json = json.dumps(arguments, ensure_ascii=False) if arguments is not None else ""
        entropy_hits = self.entropy_scanner.scan_string(args_json)
        if entropy_hits:
            top_hit = entropy_hits[0]
            if top_hit.risk_level == "CRITICAL":
                reason = f"High-entropy credential detected in arguments ({top_hit.entropy} bits/char): {top_hit.token[:8]}..."
                is_blocked = (mode == "enforce")
                return PolicyDecision(
                    allowed=not is_blocked,
                    is_blocked=is_blocked,
                    mode=mode,
                    reason=reason,
                    rule_name="HIGH_ENTROPY_CREDENTIAL",
                    risk_score=85,
                    severity="HIGH",
                    entropy_findings=entropy_hits,
                )

        # 3. Path normalization & ADS detection
        for param_name, raw_path in extracted_paths:
            has_ads, base_path, stream_name = WindowsPathNormalizer.detect_alternate_data_stream(raw_path)
            if has_ads and stream_name != "$DATA":
                reason = f"Alternate Data Stream (ADS) access detected in '{param_name}': {raw_path}"
                is_blocked = (mode == "enforce")
                return PolicyDecision(
                    allowed=not is_blocked,
                    is_blocked=is_blocked,
                    mode=mode,
                    reason=reason,
                    rule_name="WINDOWS_BLOCK_ADS",
                    risk_score=90,
                    severity="HIGH",
                )

        # 4. Check policy rules
        for rule in self.config.rules:
            # Check tool match
            if not self._tool_matches(tool_name, rule.tools):
                continue

            # Check argument patterns
            if rule.argument_patterns and isinstance(arguments, dict):
                pattern_mismatch = False
                for arg_key, regex_str in rule.argument_patterns.items():
                    val = str(arguments.get(arg_key, ""))
                    if not re.search(regex_str, val, re.IGNORECASE):
                        pattern_mismatch = True
                        break
                if pattern_mismatch:
                    continue

            # Check forbidden paths
            if rule.forbidden_paths and extracted_paths:
                for _, path_val in extracted_paths:
                    for forbidden in rule.forbidden_paths:
                        if WindowsPathNormalizer.is_subpath_of(path_val, forbidden) or \
                           WindowsPathNormalizer.matches_pattern(path_val, forbidden):
                            reason = f"Rule '{rule.name}' denied access to forbidden path: {path_val}"
                            is_blocked = (mode == "enforce" and rule.action == "deny")
                            return PolicyDecision(
                                allowed=not is_blocked,
                                is_blocked=is_blocked,
                                mode=mode,
                                reason=reason,
                                rule_name=rule.name,
                                risk_score=85,
                                severity=rule.severity,
                            )

            # Check allowed paths constraint (if specified, anything outside is denied)
            if rule.allowed_paths and extracted_paths:
                for _, path_val in extracted_paths:
                    inside_allowed = any(
                        WindowsPathNormalizer.is_subpath_of(path_val, allowed_p)
                        for allowed_p in rule.allowed_paths
                    )
                    if not inside_allowed:
                        reason = f"Rule '{rule.name}' blocked path outside allowed scope: {path_val}"
                        is_blocked = (mode == "enforce")
                        return PolicyDecision(
                            allowed=not is_blocked,
                            is_blocked=is_blocked,
                            mode=mode,
                            reason=reason,
                            rule_name=rule.name,
                            risk_score=70,
                            severity=rule.severity,
                        )

            # Action matching
            if rule.action == "deny":
                reason = f"Rule '{rule.name}' explicitly denied tool '{tool_name}'"
                is_blocked = (mode == "enforce")
                return PolicyDecision(
                    allowed=not is_blocked,
                    is_blocked=is_blocked,
                    mode=mode,
                    reason=reason,
                    rule_name=rule.name,
                    risk_score=60,
                    severity=rule.severity,
                )
            elif rule.action == "ask":
                reason = f"Rule '{rule.name}' requires interactive confirmation for tool '{tool_name}'"
                # If running headless without prompt interface, ask defaults to block in enforce mode
                is_blocked = (mode == "enforce")
                return PolicyDecision(
                    allowed=not is_blocked,
                    is_blocked=is_blocked,
                    mode=mode,
                    reason=reason,
                    rule_name=rule.name,
                    risk_score=40,
                    severity="MEDIUM",
                )
            elif rule.action == "allow":
                return PolicyDecision(
                    allowed=True,
                    is_blocked=False,
                    mode=mode,
                    reason=f"Rule '{rule.name}' explicitly permitted call",
                    rule_name=rule.name,
                    risk_score=0,
                    severity="INFO",
                )

        # Default permit if no deny rule triggered
        return PolicyDecision(
            allowed=True,
            is_blocked=False,
            mode=mode,
            reason="Call passed all security policy checks",
            risk_score=0,
            severity="INFO",
        )

    def _tool_matches(self, tool_name: str, tool_patterns: List[str]) -> bool:
        for pat in tool_patterns:
            if pat == "*" or pat.lower() == tool_name.lower():
                return True
            if "*" in pat:
                regex = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
                if re.match(regex, tool_name, re.IGNORECASE):
                    return True
        return False
