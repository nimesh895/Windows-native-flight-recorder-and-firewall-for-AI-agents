from __future__ import annotations

import time
import pytest
from agent_blackbox.security.risk_accumulator import SessionRiskAccumulator


def test_session_risk_accumulation_and_threshold():
    acc = SessionRiskAccumulator(half_life_seconds=300.0, review_threshold=80, quarantine_threshold=150)
    t0 = 1000.0

    # 1. First event: low risk probe (+30)
    res1 = acc.record_risk("read_file", 30, reason="System dir probe", event_time=t0)
    assert res1["cumulative_score"] == 30.0
    assert not res1["needs_review"]
    assert not res1["needs_quarantine"]

    # 2. Second event 10 seconds later: (+30)
    res2 = acc.record_risk("read_file", 30, reason="Sensitive env read", event_time=t0 + 10)
    assert res2["cumulative_score"] > 55.0
    assert not res2["needs_review"]

    # 3. Third event 20 seconds later: (+30) -> cumulative passes review threshold (80)
    res3 = acc.record_risk("http_request", 30, reason="Unseen external endpoint", event_time=t0 + 20)
    assert res3["cumulative_score"] > 80.0
    assert res3["needs_review"] is True

    # 4. Fourth event: (+70) -> cumulative passes quarantine threshold (150)
    res4 = acc.record_risk("run_command", 70, reason="PowerShell execution", event_time=t0 + 30)
    assert res4["cumulative_score"] >= 150.0
    assert res4["needs_quarantine"] is True


def test_session_risk_exponential_decay():
    acc = SessionRiskAccumulator(half_life_seconds=100.0)
    t0 = 1000.0

    acc.record_risk("test_tool", 100, event_time=t0)
    assert acc.current_score == 100.0

    # After 1 half-life (100 seconds), decayed score must be approximately 50.0
    decayed = acc.get_decayed_score(current_time=t0 + 100.0)
    assert 49.0 <= decayed <= 51.0

    # After 2 half-lives (200 seconds), decayed score must be approximately 25.0
    decayed_2 = acc.get_decayed_score(current_time=t0 + 200.0)
    assert 24.0 <= decayed_2 <= 26.0
