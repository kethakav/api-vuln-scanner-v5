"""
FastAPI backend for the API Vulnerability Scanner.

Provides endpoints to:
- Scan a single endpoint with selected vulnerability tests
- Run a complete scan using OpenAPI and/or explicit endpoints

Security: Bearer token via Authorization header. Configure API_AUTH_TOKEN env var.
"""

import os
import glob
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
from urllib.parse import urljoin, urlparse

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, HttpUrl, model_validator
import httpx
import jwt

from scanner_core import (
    APIPenTester,
    TargetConfig,
    AuthConfig,
    ScanReport,
    OpenAPISpecUtil,
)


# ----------------------------------------------------------------------------
# Security dependency (Bearer token)
# ----------------------------------------------------------------------------

security = HTTPBearer(auto_error=True)


def require_api_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    expected = os.getenv("API_AUTH_TOKEN", "changeme")
    if not credentials or credentials.scheme.lower() != "bearer" or credentials.credentials != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API token")
    return True


# ----------------------------------------------------------------------------
# Request/Response models
# ----------------------------------------------------------------------------


class EndpointScanRequest(BaseModel):
    base_url: HttpUrl = Field(..., description="Base URL of the target API, e.g., https://api.example.com")
    # Backward compatible: accept a single endpoint or a list of endpoints
    endpoint: Optional[str] = Field(default=None, description="Endpoint path or absolute URL, e.g., /users or https://api.example.com/users")
    endpoints: Optional[List[str]] = Field(default=None, description="List of endpoint paths or absolute URLs")
    method: str = Field(default="GET", description="HTTP method for the scan (GET/POST/PUT/PATCH/DELETE)")
    selected_tests: List[str] = Field(
        default_factory=lambda: [
            "BROKEN_AUTH",
            "JWT_VULN",
            "SQL_INJECTION",
            "NOSQL_INJECTION",
            "IDOR",
            "CORS",
            "INFO_DISCLOSURE",
            "XSS",
            "RATE_LIMIT",
        ],
        description="List of tests to run by key name",
    )
    openapi_path: Optional[str] = Field(default=None, description="Path to OpenAPI spec to aid request body generation")
    session_id: Optional[str] = Field(default=None, description="Client session ID to scope specs and activity")
    auth: Optional[AuthConfig] = None
    rate_limit: int = Field(default=10)
    timeout: int = Field(default=30)

    @model_validator(mode="after")
    def _validate_endpoints(self):
        if not self.endpoint and not self.endpoints:
            raise ValueError("Provide either 'endpoint' or 'endpoints' (one or more endpoints to scan)")
        return self


class FullScanRequest(TargetConfig):
    session_id: Optional[str] = Field(default=None, description="Client session ID to scope specs and activity")


class AuthCheckRequest(BaseModel):
    base_url: HttpUrl = Field(..., description="Base URL of the target API, e.g., https://api.example.com")
    endpoint: Optional[str] = Field(default="/", description="Endpoint path or absolute URL to probe")
    method: str = Field(default="GET", description="HTTP method for the probe")
    auth: Optional[AuthConfig] = Field(default=None, description="Credentials to test (bearer/basic/apikey)")
    timeout: int = Field(default=20, description="Timeout in seconds for the probe requests")


class AuthCheckResult(BaseModel):
    target_url: str
    method: str
    unauth_status: Optional[int] = None
    auth_status: Optional[int] = None
    requires_auth: Optional[bool] = None
    is_authenticated: bool = False
    detected_auth_type: Optional[str] = None
    jwt_info: Optional[Dict[str, Any]] = None
    response_snippet: Optional[str] = None
    error: Optional[str] = None


# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------

app = FastAPI(title="API Vulnerability Scanner", version="1.3.0")

# ----------------------------------------------------------------------------
# CORS configuration
# ----------------------------------------------------------------------------
# Configure allowed origins via env var CORS_ORIGINS (comma-separated).
# Default allows a typical local frontend at http://localhost:3000
_cors_origins_env = os.getenv("CORS_ORIGINS", "http://localhost:3000")
_origins = [o.strip() for o in _cors_origins_env.split(",") if o.strip()]

# If wildcard is specified, allow all origins. Note: with '*' we keep allow_credentials=False
_allow_origins = ["*"] if _origins == ["*"] else _origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ----------------------------------------------------------------------------
# Data/volume paths
# ----------------------------------------------------------------------------

DATA_DIR = os.getenv("DATA_DIR", "/data")
SPECS_DIR = os.path.join(DATA_DIR, "specs")
os.makedirs(SPECS_DIR, exist_ok=True)

# Session retention configuration (default: 1 hour)
SESSION_TIMEOUT_SECONDS = int(os.getenv("SESSION_TIMEOUT_SECONDS", "3600"))


class SessionManager:
    """Per-user session manager with directory-backed storage under SPECS_DIR.

    Tracks last activity via a heartbeat file in each session directory and
    provides sweep of inactive sessions.
    """

    HEARTBEAT_FILE = "last_activity.txt"

    @staticmethod
    def _session_dir(session_id: str) -> str:
        safe = session_id.replace("..", "_").replace("/", "_").replace("\\", "_")
        return os.path.join(SPECS_DIR, safe)

    @classmethod
    def create_session(cls) -> Dict[str, Any]:
        sid = str(uuid.uuid4())
        sdir = cls._session_dir(sid)
        os.makedirs(sdir, exist_ok=True)
        cls.touch(sid)
        return {"session_id": sid, "dir": sdir}

    @classmethod
    def delete_session(cls, session_id: str) -> bool:
        sdir = cls._session_dir(session_id)
        if os.path.isdir(sdir):
            try:
                for root, dirs, files in os.walk(sdir, topdown=False):
                    for name in files:
                        try:
                            os.remove(os.path.join(root, name))
                        except Exception:
                            pass
                    for name in dirs:
                        try:
                            os.rmdir(os.path.join(root, name))
                        except Exception:
                            pass
                os.rmdir(sdir)
            except Exception:
                return False
        return True

    @classmethod
    def ensure_session_dir(cls, session_id: str) -> str:
        sdir = cls._session_dir(session_id)
        if not os.path.isdir(sdir):
            raise HTTPException(status_code=404, detail="Session not found")
        return sdir

    @classmethod
    def touch(cls, session_id: str) -> None:
        sdir = cls._session_dir(session_id)
        if not os.path.isdir(sdir):
            return
        hb_path = os.path.join(sdir, cls.HEARTBEAT_FILE)
        try:
            with open(hb_path, "w", encoding="utf-8") as f:
                f.write(datetime.utcnow().isoformat())
        except Exception:
            pass

    @classmethod
    def last_activity(cls, session_id: str) -> Optional[datetime]:
        hb_path = os.path.join(cls._session_dir(session_id), cls.HEARTBEAT_FILE)
        try:
            with open(hb_path, "r", encoding="utf-8") as f:
                txt = f.read().strip()
                return datetime.fromisoformat(txt)
        except Exception:
            return None

    @classmethod
    def sweep_inactive(cls) -> List[str]:
        """Delete sessions inactive beyond SESSION_TIMEOUT_SECONDS. Returns deleted session_ids."""
        now = datetime.utcnow()
        deleted: List[str] = []
        try:
            for name in os.listdir(SPECS_DIR):
                sdir = os.path.join(SPECS_DIR, name)
                if not os.path.isdir(sdir):
                    continue
                sid = name
                last = cls.last_activity(sid)
                if last is None:
                    try:
                        last = datetime.utcfromtimestamp(os.path.getmtime(sdir))
                    except Exception:
                        last = now
                if (now - last).total_seconds() > SESSION_TIMEOUT_SECONDS:
                    if cls.delete_session(sid):
                        deleted.append(sid)
        except Exception:
            pass
        return deleted


_gc_task: Optional[asyncio.Task] = None


def clean_openapi_files():
    """Delete OpenAPI spec files from known locations (SPECS_DIR and project root).
    Matches common patterns like '*openapi*.json', '*openapi*.yml', 'TEST*.json'.
    """
    patterns = ["*openapi*.json", "*openapi*.yaml", "*openapi*.yml", "TEST*.json"]
    dirs = [SPECS_DIR, os.getcwd()]
    removed = []
    for d in dirs:
        try:
            for pat in patterns:
                for path in glob.glob(os.path.join(d, pat)):
                    # Ensure it's a file and avoid removing directories by mistake
                    if os.path.isfile(path):
                        try:
                            os.remove(path)
                            removed.append(path)
                        except Exception:
                            # ignore single-file failures
                            pass
        except Exception:
            # ignore failures for non-existent dirs or permission issues
            pass
    if removed:
        print(f"Cleaned OpenAPI spec files: {removed}")
    else:
        print("No OpenAPI spec files found to clean.")


@app.on_event("startup")
async def on_startup_cleanup():
    # Remove any existing specs before starting a new run
    try:
        clean_openapi_files()
    except Exception as e:
        print(f"Startup cleanup error: {e}")
    # Start background GC loop to remove inactive sessions
    async def _gc_loop():
        while True:
            try:
                deleted = SessionManager.sweep_inactive()
                if deleted:
                    print(f"GC removed inactive sessions: {deleted}")
            except Exception as e:
                print(f"Session GC error: {e}")
            await asyncio.sleep(60)

    global _gc_task
    try:
        _gc_task = asyncio.create_task(_gc_loop())
    except Exception as e:
        print(f"Failed to start GC task: {e}")


@app.on_event("shutdown")
async def on_shutdown_cleanup():
    # Clean specs on shutdown as requested
    try:
        clean_openapi_files()
    except Exception as e:
        print(f"Shutdown cleanup error: {e}")
    # Stop GC task gracefully
    global _gc_task
    if _gc_task:
        _gc_task.cancel()
        try:
            await _gc_task
        except Exception:
            pass


def _latest_spec_path(session_id: Optional[str] = None) -> Optional[str]:
    try:
        base_dir = SPECS_DIR if not session_id else SessionManager.ensure_session_dir(session_id)
        files = [
            os.path.join(base_dir, f)
            for f in os.listdir(base_dir)
            if os.path.isfile(os.path.join(base_dir, f)) and os.path.splitext(f)[1].lower() in {".json", ".yaml", ".yml"}
        ]
        if not files:
            return None
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return files[0]
    except Exception:
        return None


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/auth/check", response_model=AuthCheckResult)
async def auth_check(req: AuthCheckRequest, _: bool = Depends(require_api_token)):
    """Check if provided credentials can successfully authenticate to a target endpoint.

    Strategy:
    - Make an unauthenticated request to the target; record status
    - Make an authenticated request using the provided AuthConfig; record status
    - Report whether the endpoint likely requires auth and whether given creds work
    - If bearer token is used, decode JWT header/payload without verification and return minimal info
    """
    # Build target URL (accept absolute endpoint or join with base_url)
    endpoint = req.endpoint or "/"
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        target_url = endpoint
    else:
        target_url = urljoin(str(req.base_url), endpoint)

    unauth_status: Optional[int] = None
    auth_status: Optional[int] = None
    snippet: Optional[str] = None
    jwt_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    method = req.method.upper()

    # 1) Unauthenticated probe
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=req.timeout) as client:
            r = await client.request(method, target_url)
            unauth_status = r.status_code
    except Exception as e:
        # Continue; the auth request might still succeed if endpoint requires auth
        error = f"Unauthenticated probe error: {e}"

    # 2) Authenticated probe (reuse APIPenTester to construct auth headers correctly)
    try:
        config = TargetConfig(
            base_url=req.base_url,
            endpoints=[target_url],
            auth=req.auth,
            timeout=req.timeout,
        )
        async with APIPenTester(config) as scanner:
            r = await scanner.client.request(method, target_url)  # type: ignore
            auth_status = r.status_code
            snippet = (r.text or "")[:200]
    except Exception as e:
        error = f"Authenticated probe error: {e}"

    # Heuristics
    requires_auth = None
    if unauth_status is not None:
        requires_auth = unauth_status in {401, 403}

    is_authenticated = False
    if auth_status is not None and 200 <= auth_status < 300:
        is_authenticated = True

    # Optional JWT info if bearer
    if req.auth and (req.auth.auth_type or "").lower() == "bearer" and req.auth.token:
        try:
            header = jwt.get_unverified_header(req.auth.token)
        except Exception:
            header = {}
        try:
            payload = jwt.decode(req.auth.token, options={"verify_signature": False})
        except Exception:
            payload = {}
        info: Dict[str, Any] = {"header": header}
        # Redact heavy payload but keep key claims
        if isinstance(payload, dict):
            subset: Dict[str, Any] = {}
            for k in ("iss", "sub", "aud", "exp", "iat", "nbf", "scope"):
                if k in payload:
                    subset[k] = payload[k]
            info["claims"] = subset
        jwt_info = info

    return AuthCheckResult(
        target_url=target_url,
        method=method,
        unauth_status=unauth_status,
        auth_status=auth_status,
        requires_auth=requires_auth,
        is_authenticated=is_authenticated,
        detected_auth_type=(req.auth.auth_type if req.auth else None),
        jwt_info=jwt_info,
        response_snippet=snippet,
        error=error,
    )


@app.post("/api/v1/scan/endpoint", response_model=ScanReport)
async def scan_single_or_multiple_endpoints(req: EndpointScanRequest, _: bool = Depends(require_api_token)):
    """Scan one or many endpoints with a specified set of vulnerability tests.
    Backward compatible with previous payloads that used a single 'endpoint' string.
    """
    # Build list of raw endpoints from either field
    raw_endpoints: List[str] = []
    if req.endpoints:
        raw_endpoints.extend(req.endpoints)
    if req.endpoint:
        raw_endpoints.append(req.endpoint)

    # Normalize to absolute URLs
    # Always use base_url and override any other base specified (e.g., in OpenAPI spec)
    endpoint_urls: List[str] = []
    for ep in raw_endpoints:
        # If an absolute URL is provided, strip scheme/host and preserve path + query
        # so that we always anchor the request to req.base_url.
        if ep.startswith("http://") or ep.startswith("https://"):
            parsed = urlparse(ep)
            ep_path = parsed.path or "/"
            if parsed.query:
                ep_path = f"{ep_path}?{parsed.query}"
            endpoint_urls.append(urljoin(str(req.base_url), ep_path))
        else:
            endpoint_urls.append(urljoin(str(req.base_url), ep))

    # Prefer provided OpenAPI path, else fall back to the latest uploaded spec in the session (if provided) or global
    if req.session_id:
        SessionManager.touch(req.session_id)
    openapi_path = req.openapi_path or _latest_spec_path(req.session_id)

    config = TargetConfig(
        base_url=req.base_url,
        endpoints=endpoint_urls,
        openapi_path=openapi_path,
        auth=req.auth,
        rate_limit=req.rate_limit,
        timeout=req.timeout,
    )

    async with APIPenTester(config) as scanner:
        # Iterate endpoints sequentially (similar to full scan loop)
        for endpoint_url in endpoint_urls:
            findings = await scanner.run_selected_tests_on_endpoint(
                endpoint_url, req.selected_tests, method=req.method.upper()
            )
            scanner.report.findings.extend(findings)
            # simple rate limit pacing between endpoints
            await asyncio.sleep(1 / max(1, req.rate_limit))

        scanner.report.scan_end = scanner.report.scan_end or scanner.report.scan_start
        return scanner.report


@app.post("/api/v1/scan/full", response_model=ScanReport)
async def scan_full(req: FullScanRequest, _: bool = Depends(require_api_token)):
    # Fall back to latest uploaded spec if not provided (scoped by session if present)
    if req.session_id:
        SessionManager.touch(req.session_id)
    if not req.openapi_path:
        latest = _latest_spec_path(req.session_id)
        if latest:
            req.openapi_path = latest
    async with APIPenTester(req) as scanner:
        report = await scanner.run_scan()
        return report


# ----------------------------------------------------------------------------
# Spec management endpoints
# ----------------------------------------------------------------------------


@app.post("/api/v1/spec/upload")
async def upload_spec(session_id: str = Form(...), file: UploadFile = File(...), _: bool = Depends(require_api_token)):
    """Upload an OpenAPI spec (JSON or YAML) and save to the mounted volume.
    Returns basic metadata and a derived summary.
    """
    # Ensure session exists and record activity
    SessionManager.touch(session_id)
    dest_dir = SessionManager.ensure_session_dir(session_id)
    filename = os.path.basename(file.filename or "spec.json")
    # Basic sanitization: disallow path traversal
    filename = filename.replace("..", "_").replace("/", "_").replace("\\", "_")
    if os.path.splitext(filename)[1].lower() not in {".json", ".yaml", ".yml"}:
        raise HTTPException(status_code=400, detail="Only .json, .yaml, .yml are supported")

    dest_path = os.path.join(dest_dir, filename)
    try:
        content = await file.read()
        with open(dest_path, "wb") as f:
            f.write(content)
    finally:
        await file.close()

    # Try to parse and summarize
    try:
        spec = OpenAPISpecUtil._load_spec(dest_path)
        ops, resolved = OpenAPISpecUtil.extract_operations(spec)
        endpoints, _ = OpenAPISpecUtil.extract_endpoints(spec)
    except Exception as e:
        # If parsing fails, still return saved path
        raise HTTPException(status_code=400, detail=f"Saved file but failed to parse: {e}")

    return {
        "session_id": session_id,
        "saved_as": dest_path,
        "server_url": resolved,
        "operations": len(ops),
        "endpoints": len(endpoints),
        "filename": filename,
    }


@app.get("/api/v1/spec/endpoints")
async def get_extracted_endpoints(
    session_id: Optional[str] = Query(default=None, description="Session ID to scope the lookup; if omitted, uses global scope"),
    file: Optional[str] = Query(default=None, description="Spec filename to parse within the session; defaults to latest uploaded in the session"),
    methods: Optional[List[str]] = Query(default=None, description="Filter by HTTP methods (e.g., GET,POST)"),
    _: bool = Depends(require_api_token),
):
    """Return only the list of endpoints with request type from a stored spec.
    If no file is provided, the most recently uploaded spec is used.
    Response is a flat list of objects: [{"method": "GET", "endpoint": "/users"}]
    Note: Any scheme/host from the spec is stripped; only the path portion is returned.
    """
    if session_id:
        SessionManager.touch(session_id)
    base_dir = SPECS_DIR if not session_id else SessionManager.ensure_session_dir(session_id)
    path = None
    if file:
        sanitized = os.path.basename(file).replace("..", "_")
        candidate = os.path.join(base_dir, sanitized)
        if not os.path.exists(candidate):
            raise HTTPException(status_code=404, detail="Specified spec file not found in session")
        path = candidate
    else:
        path = _latest_spec_path(session_id)
        if not path:
            raise HTTPException(status_code=404, detail="No spec files found")

    try:
        spec = OpenAPISpecUtil._load_spec(path)
        ops, _ = OpenAPISpecUtil.extract_operations(spec, methods=methods)
        # Only return method + endpoint path (strip scheme/host; return just the path)
        minimal = []
        for op in ops:
            method = (op.get("method") or "").upper()
            endpoint_value = op.get("url") or op.get("path")
            if not endpoint_value:
                continue
            # Normalize to just the path component
            if isinstance(endpoint_value, str) and (endpoint_value.startswith("http://") or endpoint_value.startswith("https://")):
                parsed = urlparse(endpoint_value)
                endpoint_path = parsed.path or "/"
            else:
                endpoint_path = endpoint_value or "/"
                if not endpoint_path.startswith("/"):
                    endpoint_path = "/" + endpoint_path

            minimal.append({
                "method": method,
                "endpoint": endpoint_path,
            })
        return minimal
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ----------------------------------------------------------------------------
# Session management endpoints
# ----------------------------------------------------------------------------


class SessionCreateResponse(BaseModel):
    session_id: str
    dir: str


@app.post("/api/v1/sessions", response_model=SessionCreateResponse)
async def create_session(_: bool = Depends(require_api_token)):
    created = SessionManager.create_session()
    return SessionCreateResponse(session_id=created["session_id"], dir=created["dir"])


@app.delete("/api/v1/sessions/{session_id}")
async def delete_session(session_id: str, _: bool = Depends(require_api_token)):
    ok = SessionManager.delete_session(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found or could not be deleted")
    return {"deleted": True, "session_id": session_id}

# Optional: local run (uvicorn)
if __name__ == "__main__":
    import uvicorn

    # Safety: refuse default token in non-dev scenarios
    if os.getenv("API_AUTH_TOKEN", "changeme") == "changeme":
        print("WARNING: Using default API_AUTH_TOKEN. Set API_AUTH_TOKEN before exposing the server.")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)