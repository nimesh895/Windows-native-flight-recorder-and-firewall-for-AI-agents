from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, HTTPException, Query, Header, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from agent_blackbox.config import BlackboxConfig
from agent_blackbox.audit.storage import AuditStorage
from agent_blackbox.audit.verifier import AuditVerifier


def create_dashboard_app(
    config: BlackboxConfig,
    storage: Optional[AuditStorage] = None,
    allow_testserver: bool = False,
) -> FastAPI:
    app = FastAPI(title="AgentBlackbox Flight Recorder & Firewall", version="0.1.0")

    audit_store = storage or AuditStorage(db_path=config.audit.db_path)
    verifier = AuditVerifier(db_path=config.audit.db_path)
    expected_token = config.dashboard.session_token

    # Middleware: Validate Host header and Origin for state-changing operations
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        # 1. Host header validation
        raw_host = request.headers.get("host", "")
        host_name = raw_host.split(":")[0].strip().lower()

        allowed_hosts = {"127.0.0.1", "localhost"}
        if allow_testserver:
            allowed_hosts.add("testserver")

        if not host_name or host_name not in allowed_hosts:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": f"Forbidden: Host header '{raw_host}' is not permitted. Only 127.0.0.1 / localhost allowed."},
            )

        # 2. Origin checking on state-changing requests (POST, PUT, PATCH, DELETE)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin") or request.headers.get("referer")
            if origin:
                try:
                    parsed_origin = urlparse(origin)
                    origin_host = (parsed_origin.hostname or "").lower()
                    allowed_origins = {"127.0.0.1", "localhost"}
                    if allow_testserver:
                        allowed_origins.add("testserver")

                    if origin_host not in allowed_origins:
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={"detail": f"Forbidden: Cross-origin state-changing request from '{origin}' rejected."},
                        )
                except Exception:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "Forbidden: Malformed Origin header."},
                    )

        return await call_next(request)

    def verify_token(
        token: Optional[str] = Query(None),
        x_token: Optional[str] = Header(None, alias="X-Blackbox-Token"),
    ) -> str:
        provided = token or x_token
        if not provided or provided != expected_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing dashboard session token.",
            )
        return provided

    static_dir = Path(__file__).parent / "static"

    @app.get("/", response_class=HTMLResponse)
    async def get_index(token: Optional[str] = Query(None)):
        # Allow initial loading with query token
        if token != expected_token:
            return HTMLResponse(
                content=f"""
                <html>
                <body style="font-family:sans-serif; background:#0f172a; color:#f8fafc; padding:40px; text-align:center;">
                    <h2>🔒 AgentBlackbox Dashboard Locked</h2>
                    <p>Access requires a valid session token. Open this dashboard via CLI or provide <code>?token=&lt;token&gt;</code>.</p>
                </body>
                </html>
                """,
                status_code=401,
            )

        index_file = static_dir / "index.html"
        if not index_file.exists():
            return HTMLResponse("<h1>Dashboard index.html not found</h1>", status_code=404)

        html_content = index_file.read_text(encoding="utf-8")
        # Inject the token into the frontend JS
        html_content = html_content.replace("__SESSION_TOKEN_PLACEHOLDER__", expected_token)
        return HTMLResponse(content=html_content)

    @app.get("/api/summary", dependencies=[Depends(verify_token)])
    async def get_summary():
        stats = audit_store.get_summary_stats()
        verif = verifier.verify()
        stats["integrity"] = {
            "is_valid": verif.is_valid,
            "total_records": verif.total_records,
            "verified_records": verif.verified_records,
            "error": verif.error_message,
        }
        return stats

    @app.get("/api/events", dependencies=[Depends(verify_token)])
    async def get_events(
        session_id: Optional[str] = None,
        min_severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ):
        events = audit_store.get_events(
            session_id=session_id,
            min_severity=min_severity,
            limit=limit,
            offset=offset,
        )
        return [e.model_dump() for e in events]

    @app.get("/api/verify", dependencies=[Depends(verify_token)])
    async def get_verification():
        res = verifier.verify()
        return res.model_dump()

    @app.post("/api/simulate-tamper", dependencies=[Depends(verify_token)])
    async def simulate_tampering():
        """
        Demonstration helper: Mutates an audit event's reason directly in SQLite
        without recalculating the hash or signature, proving that AuditVerifier catches it immediately!
        """
        import sqlite3
        conn = sqlite3.connect(str(config.audit.db_path))
        try:
            cursor = conn.execute("SELECT id, reason FROM audit_events ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return JSONResponse({"success": False, "message": "No events in database to tamper with."})
            row_id, orig_reason = row[0], row[1]
            tampered_reason = orig_reason + " [MALICIOUS_UNAUTHORIZED_EDIT]"
            conn.execute("UPDATE audit_events SET reason = ? WHERE id = ?", (tampered_reason, row_id))
            conn.commit()
            return {
                "success": True,
                "tampered_row_id": row_id,
                "message": f"Row #{row_id} reason was tampered. Verify will now fail!",
            }
        finally:
            conn.close()

    return app
