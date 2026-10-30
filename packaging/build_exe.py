"""
Build script to compile AgentBlackbox into a standalone Windows executable.
Usage: python packaging/build_exe.py
"""

from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path


def build():
    root = Path(__file__).parent.parent.resolve()
    spec_path = root / "packaging" / "agent_blackbox.spec"

    print("=" * 60)
    print("AGENTBLACKBOX WINDOWS STANDALONE EXECUTABLE BUILDER")
    print("=" * 60)
    print(f"Project root: {root}")
    print(f"Spec file:    {spec_path}")

    # Verify key asset files exist
    index_file = root / "agent_blackbox" / "dashboard" / "static" / "index.html"
    policy_file = root / "policies" / "default_policy.yaml"
    corpus_file = root / "agent_blackbox" / "security" / "corpus" / "injection_corpus.json"

    for asset in [index_file, policy_file, corpus_file]:
        if not asset.exists():
            raise FileNotFoundError(f"Missing required bundle asset: {asset}")

    # Build command
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_path),
    ]

    print(f"\n[+] Executing PyInstaller command:\n    {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd, check=True, cwd=str(root))
        dist_exe = root / "dist" / "agent-blackbox.exe"
        print(f"\n[+] SUCCESS: Standalone executable created at:")
        print(f"    -> {dist_exe}")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"\n[-] Build failed with exit code: {e.returncode}")
        return e.returncode
    except FileNotFoundError:
        print("\n[-] PyInstaller is not installed in the current environment.")
        print("    Install it with: pip install pyinstaller")
        return 1


if __name__ == "__main__":
    sys.exit(build())
