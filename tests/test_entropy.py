from __future__ import annotations

import pytest
from agent_blackbox.security.entropy import EntropyScanner


def test_entropy_scanner_high_entropy_token():
    scanner = EntropyScanner(threshold_entropy=4.2, min_length=18)

    # High entropy random base64 secret (e.g. JWT or private secret)
    random_secret = "k7$J#9mQ!vL2*pW8&xZ4^rT1@yB6"
    findings = scanner.scan_string(f"api_auth_token: {random_secret}")

    assert len(findings) >= 1
    assert findings[0].token == random_secret
    assert findings[0].entropy >= 4.2
    assert findings[0].risk_level in ("HIGH", "CRITICAL")


def test_entropy_scanner_ignores_benign_text():
    scanner = EntropyScanner(threshold_entropy=4.2, min_length=18)

    # Standard English sentences or file paths have low Shannon entropy (~3.0-3.8)
    benign_text = "This is a regular English sentence describing normal system behavior."
    findings = scanner.scan_string(benign_text)
    assert len(findings) == 0
