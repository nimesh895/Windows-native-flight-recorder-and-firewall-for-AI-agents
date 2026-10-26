from __future__ import annotations

import zlib
import gzip
import pytest
from agent_blackbox.security.canaries import CanaryManager


def test_canary_hex_evasion_known_limit():
    """
    Known Limit Documentation:
    Raw hex encoding (e.g. '414b4941...' for 'AKIA...') avoids naive token pattern
    matching unless a dedicated arbitrary hex-string decoder is run.
    This test documents the current behavior: raw hex strings currently bypass
    single-token regex filters.
    """
    raw_token = "AKIA_CANARY_TOKEN_9999"
    mgr = CanaryManager(tokens=[raw_token])

    # Convert token to continuous hex representation
    hex_payload = raw_token.encode("utf-8").hex()

    alerts = mgr.check_arguments_and_payload("http_request", {"body": hex_payload})

    # Document current behavior: hex bypasses standard string & b64 decoders
    assert len(alerts) == 0, (
        "Known limit: Raw hex encoding currently bypasses canary regex detector."
    )


def test_canary_chunked_evasion_known_limit():
    """
    Known Limit Documentation:
    Chunking an exfiltrated token across separate JSON parameters or separate messages
    (e.g., param1='AKIA_CANARY_', param2='TOKEN_9999') avoids contiguous substring
    matching in single-parameter evaluators.
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

    # Document current behavior: split chunks do not trigger contiguous token tripwire
    assert len(alerts) == 0, (
        "Known limit: Chunked parameter splitting currently bypasses contiguous token inspection."
    )


def test_canary_compressed_evasion_known_limit():
    """
    Known Limit Documentation:
    Compressed binary streams (e.g., gzip, zlib, deflate) obfuscate ASCII tokens.
    Without an active decompression and stream unpacking layer, compressed payloads
    bypass raw text inspection.
    """
    raw_token = "AKIA_CANARY_TOKEN_9999"
    mgr = CanaryManager(tokens=[raw_token])

    # Compress the token with zlib and gzip
    compressed_bytes = zlib.compress(raw_token.encode("utf-8"))
    compressed_repr = str(compressed_bytes)

    alerts = mgr.check_arguments_and_payload("http_request", {"raw_bytes": compressed_repr})

    # Document current behavior: compressed binary streams bypass text inspection
    assert len(alerts) == 0, (
        "Known limit: Compressed streams (zlib/gzip) bypass raw text inspection."
    )
