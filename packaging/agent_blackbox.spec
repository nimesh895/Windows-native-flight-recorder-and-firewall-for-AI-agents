# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Specification for AgentBlackbox Windows Native Standalone Binary.
Produces a single, self-contained agent-blackbox.exe executable.
"""

from pathlib import Path
import sys

block_cipher = None
project_root = Path.cwd().resolve()

added_files = [
    (str(project_root / "agent_blackbox" / "dashboard" / "static" / "index.html"), "agent_blackbox/dashboard/static"),
    (str(project_root / "policies" / "default_policy.yaml"), "policies"),
    (str(project_root / "agent_blackbox" / "security" / "corpus" / "injection_corpus.json"), "agent_blackbox/security/corpus"),
]

hidden_imports = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "fastapi",
    "pydantic",
    "pyyaml",
    "cryptography",
    "sqlite3",
]

a = Analysis(
    [str(project_root / "agent_blackbox" / "cli.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "notebook", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="agent-blackbox",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
