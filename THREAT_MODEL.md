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

### 3.1 Known Evasion Limits for Canaries (Hex, Chunked, Compressed)
While the canary detector identifies raw tokens, Base64 variants, and URL-encoded strings, there are explicit known evasion boundaries that bypass text/regex pattern matching:
1. **Hex Encoding Evasion**: Converting a token into a raw continuous hex string (e.g. `414b4941...`) avoids string pattern matching unless an arbitrary hex decoding pass is executed over all hex-like sequences.
2. **Chunked Parameter Evasion**: An attacker or model splitting a canary token into separate parameters or multiple disjoint messages (e.g. `{"part1": "AKIA_CANARY_", "part2": "9999"}`) bypasses single-parameter contiguous pattern matching.
3. **Compressed Stream Evasion**: Compressing payloads with gzip, zlib, or brotli turns ASCII tokens into binary entropy that cannot be matched without a full multi-format decompression and payload unpacking pipeline.

These represent documented current boundaries (verified by automated tests in `tests/test_canary_limits.py`).

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

### 4.3 Honest Threat Assessment: Same-User Key Theft & Protection Options
1. **Plain Reality: A Same-User Attacker Can Steal the Signing Key**:
   In standard user-mode deployments where the Ed25519 private key (`.blackbox_keys/ed25519_private.pem`) is unencrypted on the filesystem within the user's workspace, **any adversary or prompt-injected agent executing code with the same user privileges can directly read and steal the private key**.
   Once an attacker reads `ed25519_private.pem`, they possess the cryptographic power to forge audit records, retroactively rewrite the database, and re-sign the entire SHA-256 hash chain to generate a clean-looking audit trail.

2. **Hardening Options Implemented for Key Protection**:
   - **Option A: Passphrase Protection (PKCS#8 with BestAvailableEncryption / PBKDF2)**:
     The private key is stored encrypted with AES-256. At startup, `KeyManager` requires a passphrase (passed via `AGENT_BLACKBOX_KEY_PASSPHRASE` environment variable or secure vault). If the agent reads the `.pem` file off disk, it only retrieves an encrypted ciphertext.
   - **Option B: Windows DPAPI Protection (`CryptProtectData`)**:
     On Windows, the private key can be encrypted at rest using Windows Data Protection API (`dpapi_protect`). Decryption is tied to the user's Windows logon session master key and machine SID, preventing extraction across machines or by unprivileged sandboxed accounts.
   - **Option C: External Anchoring (`abb anchor`)**:
     By exporting signed anchor hashes to a remote immutable log or external Git commit, any attempt by a local attacker to roll back or rewrite history is mathematically proven and caught by `abb verify --anchor <file>`.
   - **Option D: Out-of-Process Signing Daemon / HSM**:
     For enterprise high-assurance requirements, signing operations must be delegated to a root/SYSTEM service or external Hardware Security Module (HSM) that never exposes the private key material to user-mode agents.

---

## 5. Explicit Policy Safety Modes

- **Fail-Closed (`fail_mode: fail-closed`) [Default]**:
  If a regex compilation fails, memory is exhausted, or an unhandled exception occurs, the tool call is blocked with code `-32003`.
- **Fail-Open (`fail_mode: fail-open`)**:
  If explicitly configured, failures permit execution but log a `CRITICAL` severity alert to the flight recorder.
