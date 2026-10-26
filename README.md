# 🛡️ AgentBlackbox
### Windows-Native "Flight Recorder & Firewall" for AI Agents & MCP Servers

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows Native](https://img.shields.io/badge/platform-Windows%20Native-0078D4.svg)](https://microsoft.com)

**AgentBlackbox** is an in-process, user-mode security firewall and cryptographic flight recorder for AI agents (Claude Desktop, VS Code Copilot, Cursor, Windsurf, custom agents) communicating with Model Context Protocol (MCP) servers.

It requires **no drivers, no administrative privileges, and no background services**.

---

## 🏗️ Architecture

```
 AI Agent / IDE (Claude, Copilot, Cursor)
                     │
              stdio (JSON-RPC 2.0)
                     ▼
       ┌───────────────────────────────┐
       │   AgentBlackbox Stdio Proxy   │
       └──────────────┬────────────────┘
                      │
  ┌───────────────────┼───────────────────┐
  │                   │                   │
  ▼                   ▼                   ▼
[ Policy Engine ]   [ Canary Detector ] [ Injection Scanner ]
  • YAML rules        • Honeyfiles        • Heuristics (0-100)
  • Windows Path      • Tripwire tokens   • Indirect prompt
    Normalizer                            injection
  • ADS Blocker
  • Redactor
                      │
                      ▼
     ┌───────────────────────────────────┐
     │ Hash-Chained Audit Log (SQLite)   │
     │   • SHA-256 Hash Chain            │
     │   • Ed25519 Cryptographic Signs   │
     │   • Zero Raw Secret Persistence   │
     └────────────────┬──────────────────┘
                      │
                      ▼
     ┌───────────────────────────────────┐
     │   Localhost Dashboard (FastAPI)   │
     │   • Bound strictly to 127.0.0.1   │
     │   • Session Token Protected       │
     │   • Timeline, Replay, Risk Score  │
     └───────────────────────────────────┘
```

---

## ⚙️ Windows-Specific Hardening

Standard agent firewalls fail on Windows due to OS filesystem quirks. AgentBlackbox natively addresses each:

1. **8.3 Short Filenames (`PROGRA~1`)**: Converts short aliases to canonical paths via Win32 `GetLongPathNameW` before evaluation.
2. **Alternate Data Streams (ADS)**: Detects and rejects hidden execution streams (`payload.txt:evil.ps1` or `::$DATA`).
3. **Case-Insensitive Traversal**: Canonicalizes paths and lowercases matching keys to prevent evasion via casing tricks (`C:\Windows` vs `c:\windows`).
4. **UNC & Extended Length Paths**: Resolves `\\?\` and `\\.\` prefixes to standard local representations.
5. **Zero Raw Secret Leakage**: Detects API keys (OpenAI, Anthropic, GitHub, AWS, JWTs) and replaces them with `[REDACTED_SECRET:<type>:<hash>]`.
6. **Strict Localhost Binding**: Dashboard binds strictly to `127.0.0.1` (never `0.0.0.0`) with a high-entropy session token.
7. **Explicit Fail-Closed / Fail-Open Choice**: If the security engine encounters an internal failure, calls are safely blocked by default (`fail-closed`).

---

## 🚀 Quickstart (Under 10 Minutes)

### 1. Installation

```powershell
# Clone the repository
git clone https://github.com/your-org/agent-blackbox.git
cd agent-blackbox

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package in development mode
pip install -e .
```

### 2. Initialize Policy & Keys

Generate the default security policy YAML and your cryptographic Ed25519 keypair:

```powershell
agent-blackbox init
```

Outputs:
- `blackbox_policy.yaml`: Default security rules
- `.blackbox_keys/ed25519_private.pem`: Private signing key
- `.blackbox_keys/ed25519_public.pem`: Public verification key

### 3. Deploy Canary Honeyfiles

Deploy realistic honeyfiles and tripwires into a test directory:

```powershell
agent-blackbox canary --deploy .\canary_sandbox
```

---

## 🛡️ Usage

### Run as Stdio Proxy Wrapping an MCP Server

In your AI Agent configuration (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "agent-blackbox",
      "args": [
        "proxy",
        "--config", "blackbox_policy.yaml",
        "--",
        "python", "-m", "my_real_mcp_server"
      ]
    }
  }
}
```

If the agent attempts to read `C:\Windows\System32` or access a honeyfile, the firewall intercepts the call and returns a clean JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32003,
    "message": "AgentBlackbox Security Block: Rule 'BLOCK_WINDOWS_SYSTEM_DIRS' denied access to forbidden path",
    "data": { "rule": "BLOCK_WINDOWS_SYSTEM_DIRS", "risk_score": 85, "severity": "HIGH" }
  }
}
```

---

## 🔒 Cryptographic Verification

Verify that the SQLite audit log has not been tampered with, deleted from, or altered:

```powershell
agent-blackbox verify --db blackbox_audit.db
```

Output:
```text
============================================================
AGENTBLACKBOX CRYPTOGRAPHIC INTEGRITY VERIFICATION
============================================================
Database:          blackbox_audit.db
Total Records:     24
Verified Records:  24

[+] SUCCESS: Hash chain and Ed25519 signatures are 100% VALID.
    No records have been modified, inserted, deleted, or reordered.
```

---

## 📊 Localhost Dashboard

Launch the web timeline and session inspector:

```powershell
agent-blackbox dashboard --port 8420
```

Open the printed URL in your browser: `http://127.0.0.1:8420/?token=<SESSION_TOKEN>`

Features:
- **Live Event Stream**: Real-time flight recorder of tool invocations
- **Session Risk Score**: Dynamic score (0-100) reflecting agent behavior
- **Redacted Replay**: Inspect tool parameters and results without secret exposure
- **Chain Verification**: One-click live audit log cryptographic validation
- **Interactive Tamper Simulation**: Test button that proves verify catches SQLite row edits

---

## 🧪 Simulated Attack Suite (Phase 7)

Run the 5 harmless simulated attack scenarios to verify all defense mechanisms:

```powershell
agent-blackbox demo
```

Scenarios executed:
1. `ATTACK_1_PATH_TRAVERSAL`: Traversal dots & 8.3 short name evasion to Windows system dirs.
2. `ATTACK_2_CANARY_TRIPWIRE`: Attempted read of planted `aws_credentials.honey.json`.
3. `ATTACK_3_INDIRECT_INJECTION`: Tool output containing hidden prompt override directives.
4. `ATTACK_4_SECRET_EXFILTRATION`: Secret API key exfiltration via HTTP parameters.
5. `ATTACK_5_WINDOWS_ADS_EVASION`: Execution/writing to NTFS Alternate Data Streams (`:stream`).

Produces a detailed markdown audit report in `ATTACK_REPORT.md`.

---

## 📋 Running Tests

```powershell
pytest -v
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
