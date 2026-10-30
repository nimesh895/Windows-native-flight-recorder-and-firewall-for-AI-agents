from __future__ import annotations

import pytest
import zlib
import gzip
import base64
from agent_blackbox.security.unpacker import RecursiveUnpacker


def test_recursive_unpacker_hex():
    token = "SUPER_SECRET_CANARY_HEX_TOKEN"
    hex_str = token.encode("utf-8").hex()

    unpacked = RecursiveUnpacker.unpack_string(f"data_payload: {hex_str}")
    assert any(token in item for item in unpacked)


def test_recursive_unpacker_base64_and_zlib():
    token = "AKIA_COMPRESSED_AND_B64_KEY"
    compressed = zlib.compress(token.encode("utf-8"))
    b64_compressed = base64.b64encode(compressed).decode("utf-8")

    unpacked = RecursiveUnpacker.unpack_string(b64_compressed)
    assert any(token in item for item in unpacked)


def test_cross_parameter_chunk_reassembly():
    token = "AKIA_CHUNKED_TOKEN_12345"
    half = len(token) // 2
    args = {
        "part_1": token[:half],
        "part_2": token[half:],
    }

    candidates = RecursiveUnpacker.extract_all_payload_candidates(args)
    assert any(token in item for item in candidates)
