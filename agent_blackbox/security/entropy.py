from __future__ import annotations

import math
import re
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


TOKEN_REGEX = re.compile(r"[A-Za-z0-9_\-\./+=]{16,}")


class HighEntropyFinding(BaseModel):
    token: str
    entropy: float
    length: int
    char_types: int
    risk_level: str  # MEDIUM, HIGH, CRITICAL


class EntropyScanner:
    """
    Shannon Entropy analyzer to detect zero-day API keys, encrypted blobs,
    and untemplated credentials without relying exclusively on fixed regex prefixes.
    """

    def __init__(self, threshold_entropy: float = 4.2, min_length: int = 18):
        self.threshold_entropy = threshold_entropy
        self.min_length = min_length

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """
        Calculates Shannon Entropy in bits per character:
        H(X) = - sum( p(x) * log2(p(x)) )
        """
        if not data:
            return 0.0

        length = len(data)
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return round(entropy, 3)

    @staticmethod
    def count_character_classes(data: str) -> int:
        """Counts how many distinct character classes (lower, upper, digits, symbols) appear."""
        classes = 0
        if any(c.islower() for c in data):
            classes += 1
        if any(c.isupper() for c in data):
            classes += 1
        if any(c.isdigit() for c in data):
            classes += 1
        if any(not c.isalnum() for c in data):
            classes += 1
        return classes

    def scan_string(self, text: str) -> List[HighEntropyFinding]:
        """
        Scans a string for isolated high-entropy tokens.
        """
        if not text or not isinstance(text, str):
            return []

        findings: List[HighEntropyFinding] = []
        matches = TOKEN_REGEX.finditer(text)

        for match in matches:
            token = match.group(0)
            if len(token) < self.min_length:
                continue

            # Ignore common known benign strings (e.g. standard file paths, repetitive patterns)
            if token.lower().startswith(("http://", "https://", "application/", "text/plain")):
                continue

            entropy = self.calculate_shannon_entropy(token)
            char_classes = self.count_character_classes(token)

            # High entropy with at least 3 character classes indicates strong credential likelihood
            if entropy >= self.threshold_entropy and char_classes >= 3:
                if entropy >= 4.8 and len(token) >= 28:
                    risk = "CRITICAL"
                elif entropy >= 4.4:
                    risk = "HIGH"
                else:
                    risk = "MEDIUM"

                findings.append(
                    HighEntropyFinding(
                        token=token,
                        entropy=entropy,
                        length=len(token),
                        char_types=char_classes,
                        risk_level=risk,
                    )
                )

        return findings
