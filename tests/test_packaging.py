from __future__ import annotations

import pytest
from pathlib import Path


def test_packaging_assets_and_spec_exist():
    root = Path(__file__).parent.parent
    spec_file = root / "packaging" / "agent_blackbox.spec"
    builder_script = root / "packaging" / "build_exe.py"

    assert spec_file.exists(), "Packaging spec file missing"
    assert builder_script.exists(), "Executable builder script missing"

    # Verify that spec file includes static html dashboard and policies
    spec_content = spec_file.read_text(encoding="utf-8")
    assert "agent_blackbox/dashboard/static" in spec_content
    assert "default_policy.yaml" in spec_content
    assert "injection_corpus.json" in spec_content
