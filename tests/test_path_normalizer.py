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


def test_nonexistent_path_resolves_nearest_parent(tmp_path):
    existing_dir = tmp_path / "real_dir"
    existing_dir.mkdir()

    # Non-existent target file inside existing parent
    target = existing_dir / "does_not_exist.txt"
    norm = WindowsPathNormalizer.normalize(target)
    
    expected_parent_norm = WindowsPathNormalizer.normalize(existing_dir)
    assert norm.startswith(expected_parent_norm)
    assert norm.endswith("does_not_exist.txt")

    # Non-existent multi-level nested child
    deep_target = existing_dir / "nonexistent_sub" / "leaf.txt"
    deep_norm = WindowsPathNormalizer.normalize(deep_target)
    assert deep_norm.startswith(expected_parent_norm)
    assert deep_norm.endswith("nonexistent_sub/leaf.txt")


def test_symlink_and_junction_resolution(tmp_path):
    real_target_dir = tmp_path / "real_target"
    real_target_dir.mkdir()
    link_dir = tmp_path / "link_to_target"

    try:
        # Create directory symlink (or junction if supported)
        link_dir.symlink_to(real_target_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        # On Windows without Developer Mode, creating symlinks can raise OSError; skip if OS privilege restricts
        pytest.skip("Symlink creation requires Developer Mode or SeCreateSymbolicLinkPrivilege")

    # Access a non-existent file through the symlink directory
    file_via_link = link_dir / "sub_nonexistent.txt"
    norm_result = WindowsPathNormalizer.normalize(file_via_link)

    # Must resolve through the link to the real target directory!
    real_norm = WindowsPathNormalizer.normalize(real_target_dir)
    assert norm_result.startswith(real_norm)
    assert "link_to_target" not in norm_result
    assert norm_result.endswith("sub_nonexistent.txt")

