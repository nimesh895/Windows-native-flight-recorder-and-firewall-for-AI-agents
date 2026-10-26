from __future__ import annotations

import pytest
from pathlib import Path
from agent_blackbox.security.windows_path import WindowsPathNormalizer


def test_ads_detection():
    # Regular path
    has_ads, base, stream = WindowsPathNormalizer.detect_alternate_data_stream("C:\\data\\file.txt")
    assert not has_ads
    assert stream is None

    # ADS payload
    has_ads, base, stream = WindowsPathNormalizer.detect_alternate_data_stream("C:\\data\\file.txt:hidden.ps1")
    assert has_ads
    assert base == "C:\\data\\file.txt"
    assert stream == "hidden.ps1"

    # Default data stream specifier
    has_ads, base, stream = WindowsPathNormalizer.detect_alternate_data_stream("file.txt::$DATA")
    assert has_ads
    assert stream == "$DATA"


def test_path_normalization_traversal():
    norm = WindowsPathNormalizer.normalize(r"C:\workspace\subfolder\..\file.txt")
    assert "subfolder" not in norm
    assert norm.endswith("file.txt")
    assert "\\" not in norm  # Forward slashes standard


def test_case_insensitivity_and_containment():
    parent = r"C:\MyProjects\AgentBlackbox"
    child = r"c:\myprojects\agentblackbox\src\main.py"
    outside = r"C:\Windows\System32\calc.exe"

    assert WindowsPathNormalizer.is_subpath_of(child, parent)
    assert not WindowsPathNormalizer.is_subpath_of(outside, parent)


def test_unc_prefix_stripping():
    norm = WindowsPathNormalizer.normalize(r"\\?\C:\Windows\System32")
    assert not norm.startswith(r"\\?\")
    assert "windows/system32" in norm.lower()
