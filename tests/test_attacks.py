from __future__ import annotations

import pytest
from pathlib import Path
from agent_blackbox.demos.attack_runner import AttackDemoRunner


def test_five_attack_scenarios_neutralized(tmp_path):
    db_file = tmp_path / "test_demo_attacks.db"
    runner = AttackDemoRunner(db_path=str(db_file))
    summary = runner.run_all()

    # All attacks must be neutralized / flagged
    assert summary["scenarios_tested"] >= 5
    assert summary["neutralized_count"] == summary["scenarios_tested"]
    # Cryptographic integrity of the log must be verified
    assert summary["chain_valid"] is True
