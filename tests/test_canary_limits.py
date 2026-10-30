from __future__ import annotations

import zlib
import gzip
import pytest
from agent_blackbox.security.canaries import CanaryManager


def test_canary_hex_evasion_defeated():
    """
    Validates that raw hex encoding (e.g. '414b4941...' for 'AKIA...')
    is now unpacked by RecursiveUnpacker and successfully caught by the canary detector.
    """
    raw_token = "AKIA_CANARY_TOKEN_9999"
    mgr = CanaryManager(tokens=[raw_token])

    # Convert token to continuous hex representation
    hex_payload = raw_token.encode("utf-8").hex()

    alerts = mgr.check_arguments_and_payload("http_request", {"body": hex_payload})

    assert len(alerts) >= 1
    assert alerts[0].severity == "CRITICAL"
    assert "Canary secret token" in alerts[0].description


def test_canary_chunked_evasion_defeated():
    """
    Validates that chunking an exfiltrated token across separate JSON parameters
    is reassembled by RecursiveUnpacker and caught.
    """
    raw_token = "AKIA_CANARY_TOKEN_9999"
    mgr = CanaryManager(tokens=[raw_token])

    half = len(raw_token) // 2
    part1 = raw_token[:half]
    part2 = raw_token[half:]

    # Parameters separated into two disconnected chunks
    chunked_payload = {
        "chunk_a": part1,
        "chunk_b": part2,
    }

    alerts = mgr.check_arguments_and_payload("http_request", chunked_payload)

    assert len(alerts) >= 1
    assert alerts[0].severity == "CRITICAL"


def test_canary_compressed_evasion_defeated():
    """
    Validates that compressed binary streams (e.g. zlib/gzip) packed into strings
    or base64 are uncompressed by RecursiveUnpacker and caught.
    """
    import base64
    raw_token = "AKIA_CANARY_TOKEN_9999"
    mgr = CanaryManager(tokens=[raw_token])

    # Compress the token with zlib and encode as base64
    compressed_bytes = zlib.compress(raw_token.encode("utf-8"))
    b64_compressed = base64.b64encode(compressed_bytes).decode("utf-8")

    alerts = mgr.check_arguments_and_payload("http_request", {"raw_bytes": b64_compressed})

    assert len(alerts) >= 1
    assert alerts[0].severity == "CRITICAL"
