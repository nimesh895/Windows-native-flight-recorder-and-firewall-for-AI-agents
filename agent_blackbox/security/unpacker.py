from __future__ import annotations

import re
import zlib
import gzip
import base64
import urllib.parse
from typing import Any, Dict, List, Set, Tuple


HEX_REGEX = re.compile(r"\b([0-9a-fA-F]{16,})\b")
B64_REGEX = re.compile(r"\b([A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2})\b")


class RecursiveUnpacker:
    """
    Recursively inspects and unpacks obfuscated strings and payloads:
    - Hex decoding
    - Base64 & URL-safe Base64 decoding
    - URL percent-decoding
    - Zlib and Gzip decompression
    - Nested combinations (e.g. gzip -> base64 -> hex)
    - Cross-parameter concatenation (defeating chunked token splitting)
    """

    MAX_DEPTH = 4
    MAX_UNPACKED_BYTES = 500_000  # Prevent decompression bomb abuse

    @classmethod
    def try_decode_hex(cls, text: str) -> List[str]:
        results = []
        for match in HEX_REGEX.finditer(text):
            chunk = match.group(1)
            if len(chunk) % 2 != 0:
                continue
            try:
                decoded_bytes = bytes.fromhex(chunk)
                # Attempt to decode as utf-8 or ascii
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_text) >= 6:
                    results.append(decoded_text)
            except Exception:
                pass
        return results

    @classmethod
    def try_decode_base64(cls, text: str) -> List[Tuple[str, bytes]]:
        results = []
        for match in B64_REGEX.finditer(text):
            chunk = match.group(1)
            for pad in range(4):
                padded = chunk + ("=" * pad)
                try:
                    # Try standard and urlsafe
                    raw_bytes = base64.b64decode(padded, validate=False)
                    if len(raw_bytes) >= 6:
                        text_val = raw_bytes.decode("utf-8", errors="ignore")
                        results.append((text_val, raw_bytes))
                    break
                except Exception:
                    pass
        return results

    @classmethod
    def try_decompress(cls, raw_bytes: bytes) -> List[str]:
        results = []
        if len(raw_bytes) > cls.MAX_UNPACKED_BYTES:
            return results

        # Try zlib
        try:
            decomp = zlib.decompress(raw_bytes)
            if decomp:
                results.append(decomp.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        # Try gzip
        try:
            decomp = gzip.decompress(raw_bytes)
            if decomp:
                results.append(decomp.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        return results

    @classmethod
    def unpack_string(cls, text: str, depth: int = 0) -> Set[str]:
        """
        Recursively unpacks a text string, returning all extracted candidate strings.
        """
        if not text or not isinstance(text, str) or depth >= cls.MAX_DEPTH:
            return set()

        candidates: Set[str] = {text}

        # 1. URL unquote
        try:
            unquoted = urllib.parse.unquote(text)
            if unquoted != text:
                candidates.add(unquoted)
                candidates.update(cls.unpack_string(unquoted, depth + 1))
        except Exception:
            pass

        # 2. Hex decoding
        for hex_decoded in cls.try_decode_hex(text):
            candidates.add(hex_decoded)
            candidates.update(cls.unpack_string(hex_decoded, depth + 1))

        # 3. Base64 & Decompression
        for b64_text, b64_bytes in cls.try_decode_base64(text):
            if b64_text and b64_text != text:
                candidates.add(b64_text)
                candidates.update(cls.unpack_string(b64_text, depth + 1))

            # Attempt decompression on the raw decoded bytes
            for decompressed in cls.try_decompress(b64_bytes):
                candidates.add(decompressed)
                candidates.update(cls.unpack_string(decompressed, depth + 1))

        return candidates

    @classmethod
    def extract_all_payload_candidates(cls, arguments: Any) -> Set[str]:
        """
        Extracts all strings from arbitrary nested dict/list arguments,
        generates recursive un-packings, AND builds cross-parameter concatenations
        to detect chunked parameter splitting.
        """
        raw_strings: List[str] = []

        def collect_strings(item: Any):
            if isinstance(item, str):
                raw_strings.append(item)
            elif isinstance(item, dict):
                for v in item.values():
                    collect_strings(v)
            elif isinstance(item, (list, tuple, set)):
                for elem in item:
                    collect_strings(elem)

        collect_strings(arguments)

        candidates: Set[str] = set()

        # 1. Unpack each individual string
        for s in raw_strings:
            candidates.update(cls.unpack_string(s))

        # 2. Cross-parameter concatenated candidate (defeats chunked token evasion)
        if len(raw_strings) > 1:
            joined = "".join(raw_strings)
            candidates.update(cls.unpack_string(joined))
            # Also try joined with space
            spaced = " ".join(raw_strings)
            candidates.update(cls.unpack_string(spaced))

        return candidates
