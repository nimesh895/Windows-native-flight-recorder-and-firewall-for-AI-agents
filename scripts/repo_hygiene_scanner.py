from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple


# Regex patterns to search for
PATTERNS = {
    "PERSONAL_DATA_USER_NAME": re.compile(r"(?i)\b(?:Nime\$H|nimesh)\b"),
    "PERSONAL_DATA_EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "ABSOLUTE_PATH_WINDOWS": re.compile(r"\b(?:[a-zA-Z]:\\(?:users|projects|windows|temp|appdata)[^\s\"';,\)]*)", re.IGNORECASE),
    "ABSOLUTE_PATH_UNIX": re.compile(r"\b(?:\/(?:home|users|var|tmp|etc)\/[^\s\"';,\)]*)", re.IGNORECASE),
    "REAL_LOOKING_SECRET_OPENAI": re.compile(r"\bsk-[a-zA-Z0-9]{32,}\b"),
    "REAL_LOOKING_SECRET_AWS": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "REAL_LOOKING_PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}

EXCLUDED_EXTS = {".pyc", ".db", ".sqlite", ".png", ".jpg", ".ico"}
EXCLUDED_DIRS = {".git", ".venv", "__pycache__", "node_modules"}


def scan_file(filepath: Path) -> List[Dict[str, str]]:
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()
    for line_no, line in enumerate(lines, 1):
        for rule_name, regex in PATTERNS.items():
            matches = regex.finditer(line)
            for m in matches:
                matched_text = m.group(0)
                # Ignore deliberate regex definitions in the scanner itself or redactor pattern definitions
                if "re.compile" in line or "SECRET_PATTERNS" in line or "PATTERNS" in line:
                    continue
                # Ignore generic example domains in docs/tests
                if rule_name == "PERSONAL_DATA_EMAIL" and any(d in matched_text.lower() for d in ["example.com", "your-org", "attacker.org", "internal"]):
                    continue

                findings.append({
                    "file": str(filepath),
                    "line": line_no,
                    "rule": rule_name,
                    "match": matched_text[:60],
                    "snippet": line.strip()[:100],
                })
    return findings


def scan_workspace(root_dir: str | Path) -> List[Dict[str, str]]:
    root = Path(root_dir)
    all_findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for f in filenames:
            ext = Path(f).suffix.lower()
            if ext in EXCLUDED_EXTS:
                continue
            fpath = Path(dirpath) / f
            all_findings.extend(scan_file(fpath))
    return all_findings


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = scan_workspace(target)
    print(f"Total findings: {len(results)}")
    for r in results:
        print(f"[{r['rule']}] {r['file']}:{r['line']} -> {r['match']}")
