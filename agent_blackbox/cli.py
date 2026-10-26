from __future__ import annotations

import sys
import argparse
import asyncio
import webbrowser
from pathlib import Path

from agent_blackbox.config import BlackboxConfig, PolicyRule
from agent_blackbox.security.crypto import KeyManager
from agent_blackbox.security.canaries import CanaryManager
from agent_blackbox.audit.storage import AuditStorage
from agent_blackbox.audit.verifier import AuditVerifier
from agent_blackbox.proxy.stdio_proxy import McpStdioProxy
from agent_blackbox.demos.attack_runner import AttackDemoRunner


def cmd_init(args):
    """Initializes default policy configuration and cryptographic keys."""
    config_path = Path(args.config)
    if config_path.exists() and not args.force:
        print(f"[-] Config file already exists at {config_path}. Use --force to overwrite.")
        return 1

    cfg = BlackboxConfig(
        mode="enforce",
        fail_mode="fail-closed",
        rules=[
            PolicyRule(
                name="BLOCK_WINDOWS_SYSTEM_DIRS",
                action="deny",
                tools=["*"],
                forbidden_paths=[
                    r"C:\Windows",
                    r"C:\Windows\System32",
                    r"C:\Windows\SysWOW64",
                    r"C:\Program Files",
                    r"/windows",
                    r"/etc",
                ],
                severity="HIGH",
            ),
            PolicyRule(
                name="BLOCK_PRIVATE_KEYS_AND_SECRETS",
                action="deny",
                tools=["read_file", "write_file"],
                forbidden_paths=[
                    "*.pem",
                    "*.key",
                    "*.id_rsa",
                    ".blackbox_keys/*",
                ],
                severity="CRITICAL",
            ),
        ],
    )
    cfg.save_to_yaml(config_path)
    print(f"[+] Initialized default policy at: {config_path}")

    # Generate Ed25519 keys
    km = KeyManager(key_dir=cfg.audit.key_dir)
    print(f"[+] Initialized Ed25519 signing keys at: {km.key_dir}")
    print("    Private key:", km.private_path)
    print("    Public key: ", km.public_path)
    return 0


def cmd_verify(args):
    """Cryptographically verifies the audit log."""
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[-] Database file does not exist: {db_path}")
        return 1

    km = KeyManager(key_dir=args.keys)
    verifier = AuditVerifier(db_path=db_path, key_mgr=km)
    res = verifier.verify()

    print("=" * 60)
    print("AGENTBLACKBOX CRYPTOGRAPHIC INTEGRITY VERIFICATION")
    print("=" * 60)
    print(f"Database:          {db_path}")
    print(f"Total Records:     {res.total_records}")
    print(f"Verified Records:  {res.verified_records}")
    if res.is_valid:
        print("\n[+] SUCCESS: Hash chain and Ed25519 signatures are 100% VALID.")
        print("    No records have been modified, inserted, deleted, or reordered.")
        return 0
    else:
        print(f"\n[-] INTEGRITY ERROR: Tampering detected!")
        print(f"    Record ID:     #{res.tampered_record_id}")
        print(f"    Details:       {res.error_message}")
        return 2


def cmd_canary(args):
    """Deploys honeyfiles and canary tokens."""
    target_dir = Path(args.deploy)
    mgr = CanaryManager()
    created = mgr.deploy_honeyfiles(target_dir)
    print(f"[+] Deployed {len(created)} canary honeyfiles to: {target_dir.resolve()}")
    for fname, tok in created.items():
        print(f"    - {fname} (token: {tok[:12]}...)")
    return 0


def cmd_dashboard(args):
    """Runs the localhost dashboard bound to 127.0.0.1."""
    import uvicorn
    from agent_blackbox.dashboard.server import create_dashboard_app

    config = BlackboxConfig.load_from_yaml(args.config) if Path(args.config).exists() else BlackboxConfig()
    if args.port:
        config.dashboard.port = args.port
    if args.db:
        config.audit.db_path = args.db

    token = config.dashboard.session_token
    url = f"http://127.0.0.1:{config.dashboard.port}/?token={token}"

    print("=" * 65)
    print("AGENTBLACKBOX LOCALHOST DASHBOARD")
    print("=" * 65)
    print(f"[+] Host:          127.0.0.1 (Strict local binding)")
    print(f"[+] Port:          {config.dashboard.port}")
    print(f"[+] Session Token: {token}")
    print(f"\nAccess URL: \n  -> {url}\n")
    print("Press Ctrl+C to stop.")
    print("=" * 65)

    if args.open:
        webbrowser.open(url)

    app = create_dashboard_app(config)
    uvicorn.run(app, host="127.0.0.1", port=config.dashboard.port, log_level="warning")
    return 0


def cmd_proxy(args):
    """Runs the stdio MCP proxy wrapping a child MCP server."""
    if not args.cmd:
        print("[-] Error: No target command specified. Usage: agent-blackbox proxy -- <command> [args...]")
        return 1

    config = BlackboxConfig.load_from_yaml(args.config) if Path(args.config).exists() else BlackboxConfig()
    proxy = McpStdioProxy(config=config, target_command=args.cmd)

    try:
        asyncio.run(proxy.run_stdio())
        return 0
    except KeyboardInterrupt:
        return 0


def cmd_demo(args):
    """Runs the 5 simulated attacks and generates report."""
    runner = AttackDemoRunner(db_path=args.db)
    summary = runner.run_all()
    report_file = args.report or "ATTACK_REPORT.md"
    runner.generate_markdown_report(summary, output_path=report_file)
    print(f"\n[+] Comprehensive attack report saved to: {Path(report_file).resolve()}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="agent-blackbox",
        description="Windows-native flight recorder and firewall for AI agents.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Initialize default policy config and cryptographic keys")
    p_init.add_argument("--config", "-c", default="blackbox_policy.yaml", help="Path for policy YAML file")
    p_init.add_argument("--force", "-f", action="store_true", help="Overwrite existing configuration")

    # proxy
    p_proxy = subparsers.add_parser("proxy", help="Run stdio MCP proxy wrapping child MCP server")
    p_proxy.add_argument("--config", "-c", default="blackbox_policy.yaml", help="Path to policy YAML")
    p_proxy.add_argument("cmd", nargs=argparse.REMAINDER, help="Command and arguments to run the target MCP server")

    # verify
    p_verify = subparsers.add_parser("verify", help="Cryptographically verify audit log hash chain and signatures")
    p_verify.add_argument("--db", default="blackbox_audit.db", help="Path to SQLite audit database")
    p_verify.add_argument("--keys", default=".blackbox_keys", help="Directory containing Ed25519 keys")

    # dashboard
    p_dash = subparsers.add_parser("dashboard", help="Start local web dashboard on 127.0.0.1")
    p_dash.add_argument("--config", "-c", default="blackbox_policy.yaml", help="Path to policy YAML")
    p_dash.add_argument("--port", "-p", type=int, default=8420, help="Localhost port")
    p_dash.add_argument("--db", default="blackbox_audit.db", help="Path to SQLite audit database")
    p_dash.add_argument("--open", "-o", action="store_true", help="Automatically open browser")

    # canary
    p_canary = subparsers.add_parser("canary", help="Deploy honeyfiles and canary tokens")
    p_canary.add_argument("--deploy", "-d", default="./honeyfiles", help="Destination folder for honeyfiles")

    # demo
    p_demo = subparsers.add_parser("demo", help="Run 5 simulated attack scenarios and generate verification report")
    p_demo.add_argument("--db", default="demo_audit.db", help="Database file for demo run")
    p_demo.add_argument("--report", default="ATTACK_REPORT.md", help="Markdown output report file")

    args = parser.parse_args()

    if args.command == "init":
        sys.exit(cmd_init(args))
    elif args.command == "proxy":
        sys.exit(cmd_proxy(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "dashboard":
        sys.exit(cmd_dashboard(args))
    elif args.command == "canary":
        sys.exit(cmd_canary(args))
    elif args.command == "demo":
        sys.exit(cmd_demo(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
