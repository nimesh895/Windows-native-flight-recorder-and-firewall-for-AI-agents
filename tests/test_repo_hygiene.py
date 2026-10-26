from __future__ import annotations

import pytest
from pathlib import Path
from scripts.repo_hygiene_scanner import scan_workspace


def test_repo_hygiene_scan_reports_findings():
    repo_root = Path(__file__).parent.parent
    findings = scan_workspace(repo_root)

    # The scanner should run cleanly and return a list of findings
    assert isinstance(findings, list)

    # Ensure no real private keys or personal usernames leaked in production source
    critical_leaks = [
        f for f in findings
        if f["rule"] in ("REAL_LOOKING_PRIVATE_KEY", "PERSONAL_DATA_USER_NAME")
        and "test" not in f["file"].lower()
        and "scanner" not in f["file"].lower()
    ]
    assert len(critical_leaks) == 0, f"Critical leaks found: {critical_leaks}"
