# AgentBlackbox Threat Model

## 1. System Overview
**AgentBlackbox** is an in-process, user-mode security firewall and cryptographic flight recorder for AI agents and Model Context Protocol (MCP) servers on Windows.

```
AI Agent / IDE (Client)
        ▲
        │ stdio JSON-RPC 2.0
        ▼
[ AgentBlackbox Proxy ] ──► [ Policy Engine + Path Normalizer + ADS Detector ]
        │               ──► [ Canary Tripwires + Injection Scanner ]
        │               ──► [ Secret Redactor ]
        ▼               ──► [ Hash-Chained SQLite Log + Ed25519 Signatures ]
Real MCP Server (Subprocess)
        ▲
        │ Localhost only (127.0.0.1)
        ▼
[ Localhost Dashboard ] (Session Token Authenticated)
```

---

## 2. Trust Boundaries & Adversaries

### 2.1 Adversaries
1. **Compromised / Prompt-Injected AI Model**:
   An LLM manipulated by untrusted documents, indirect prompt injection, or malicious web browsing into calling tools outside its intended scope.
2. **Untrusted Tool Outputs / Poisoned Server**:
   A third-party MCP server returning malicious prompt injection payloads or trying to leak secrets through simulated tool responses.
3. **Malicious Workspace Payloads**:
   Repositories with poisoned `README.md` or hidden scripts designed to trick developer AI assistants into reading credentials or executing code.
4. **Post-Breach Tampering (Forensics Evasion)**:
   An attacker attempting to alter, delete, or re-order audit logs in SQLite to conceal unauthorized tool usage.

---

## 3. Windows-Specific Attack Vectors & Defenses

| Attack Vector | Windows Mechanism | Vulnerability in Standard Firewalls | AgentBlackbox Defense |
|---|---|---|---|
| **8.3 Short Filenames** | NTFS creates short names (e.g. `PROGRA~1`, `SECRET~1.TXT`) | Firewalls checking `C:\Program Files` miss access via `C:\PROGRA~1` | `WindowsPathNormalizer.resolve_8dot3_path()` calls Windows `GetLongPathNameW` before policy evaluation. |
| **Alternate Data Streams (ADS)** | NTFS supports secondary streams (`file.txt:evil.exe`, `dir:$DATA`) | Path filters look for `file.txt` extension; stream executes undetected | `WindowsPathNormalizer.detect_alternate_data_stream()` isolates stream tags and blocks ADS payloads. |
| **Directory Traversal** | `..\..\Windows\System32` or `C:/foo/../bar` | Relative path checks fail on traversal dots | Canonical resolution to absolute path before comparison against allowed and forbidden zones. |
| **Case Sensitivity Bypass** | Windows filesystem is case-insensitive (`c:\windows` == `C:\WINDOWS`) | Case-sensitive string matching permits evasion | Complete lowercased canonical string comparison. |
| **UNC & Extended Prefixes** | `\\?\C:\foo` or `\\.\` bypasses MAX_PATH and standard checks | String filters expecting drive letters miss `\\?\` | Normalization strips and standardizes device and UNC prefixes. |
| **Credential Leakage in Logs** | Raw API keys captured in audit databases | Stolen SQLite file exposes developer credentials | `SecretRedactor` converts credentials to SHA-256 hashes (`[REDACTED_SECRET:<type>:<hash>]`); raw values never touch disk. |
| **Audit Log Tampering** | Attacker edits SQLite rows to hide exfiltration | Standard SQLite databases lack cryptographic proof | Every row is SHA-256 hash-chained to the previous row and signed with an Ed25519 private key. |

---

## 4. Cryptographic Proof of Integrity

### 4.1 Hash-Chain Formula
$$H_0 = 0000000000000000000000000000000000000000000000000000000000000000$$
$$H_i = \text{SHA-256}\Big(\text{Canonical-JSON}\big(H_{i-1}, \text{timestamp}, \text{session}, \text{tool}, \text{args}_{\text{redacted}}, \text{decision}, \text{reason}\big)\Big)$$
$$\text{Signature}_i = \text{Ed25519-Sign}\big(\text{PrivateKey}, H_i\big)$$

### 4.2 Tamper Evident Verification
- **Altered row data:** `SHA-256(RowData)` will not equal stored `record_hash`.
- **Replaced row hash:** Signature verification with `ed25519_public.pem` will fail.
- **Deleted row:** Row $i+1$'s `prev_hash` will not match Row $i-1$'s hash.
- **Appended forged row:** Without the Ed25519 private key, an attacker cannot forge valid signatures.
- **Log truncation:** Detected by verifying against external anchor files (`abb verify --anchor anchor.json`).

### 4.3 Honest Assessment of Key-Handling Limits & Assumptions
1. **Co-located Private Key Boundary**:
   In standard user-mode deployments where `ed25519_private.pem` is stored on the local disk alongside the agent process (e.g. in `.blackbox_keys/`), any adversary who achieves full arbitrary code execution within the user's OS context can read the private key. With the private key in hand, the adversary could rewrite the database and re-sign the entire hash chain.
2. **What Local Signing Protects Against**:
   - Unauthorized database tampering by unprivileged processes or secondary tools.
   - Accidental row corruption, deletion, or manual edits by administrators or malicious third parties who lack direct filesystem access to `.blackbox_keys/`.
   - Post-incident repudiation: the agent cannot claim it did not generate logged actions unless keys were compromised.
3. **Achieving True Tamper-Proof Forensics via Anchoring**:
   - **External Anchoring (`abb anchor`)**: Regularly exporting the latest signed anchor hash (`blackbox_anchor.json`) to an external medium (e.g. remote syslog, an immutable S3 bucket with Object Lock, a private Git repository, or an RFC 3161 trusted timestamp authority).
   - If a local attacker subsequently truncates or rewrites the local database, `abb verify --anchor external_anchor.json` mathematically detects the rollback/truncation immediately.
   - For high-assurance environments, keys should be backed by an external HSM, Windows DPAPI / TPM, or an isolated out-of-process signing daemon.

---

## 5. Explicit Policy Safety Modes

- **Fail-Closed (`fail_mode: fail-closed`) [Default]**:
  If a regex compilation fails, memory is exhausted, or an unhandled exception occurs, the tool call is blocked with code `-32003`.
- **Fail-Open (`fail_mode: fail-open`)**:
  If explicitly configured, failures permit execution but log a `CRITICAL` severity alert to the flight recorder.
