from __future__ import annotations

import pytest
from agent_blackbox.config import BlackboxConfig, PolicyRule
from agent_blackbox.security.policy import PolicyEngine


def test_policy_enforce_blocks_forbidden_path():
    cfg = BlackboxConfig(
        mode="enforce",
        fail_mode="fail-closed",
        rules=[
            PolicyRule(
                name="BLOCK_WINDOWS",
                action="deny",
                tools=["read_file"],
                forbidden_paths=[r"C:\Windows\System32"],
            )
        ],
    )
    engine = PolicyEngine(cfg)
    decision = engine.evaluate_call("read_file", {"path": r"C:\Windows\System32\drivers\etc\hosts"})
    assert not decision.allowed
    assert decision.is_blocked
    assert "BLOCK_WINDOWS" in decision.reason


def test_policy_monitor_mode_permits_but_flags():
    cfg = BlackboxConfig(
        mode="monitor",
        rules=[
            PolicyRule(
                name="BLOCK_WINDOWS",
                action="deny",
                tools=["read_file"],
                forbidden_paths=[r"C:\Windows\System32"],
            )
        ],
    )
    engine = PolicyEngine(cfg)
    decision = engine.evaluate_call("read_file", {"path": r"C:\Windows\System32\drivers\etc\hosts"})
    # In monitor mode, call is permitted so execution continues, but flagged with risk
    assert decision.allowed
    assert not decision.is_blocked
    assert decision.risk_score > 0


def test_policy_fail_closed_on_error(monkeypatch):
    cfg = BlackboxConfig(mode="enforce", fail_mode="fail-closed")
    engine = PolicyEngine(cfg)

    # Force internal error
    def mock_eval(*args, **kwargs):
        raise RuntimeError("Unexpected policy crash")

    monkeypatch.setattr(engine, "_evaluate_inner", mock_eval)

    decision = engine.evaluate_call("read_file", {"path": "test.txt"})
    assert not decision.allowed
    assert decision.is_blocked
    assert "fail-closed" in decision.reason
