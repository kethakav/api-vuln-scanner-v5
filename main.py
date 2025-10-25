"""
FastAPI backend for the API Vulnerability Scanner.

Provides endpoints to:
- Scan a single endpoint with selected vulnerability tests
- Run a complete scan using OpenAPI and/or explicit endpoints

Security: Bearer token via Authorization header. Configure API_AUTH_TOKEN env var.
"""

import os
import asyncio
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Query
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
    auth: Optional[AuthConfig] = None
    rate_limit: int = Field(default=10)
    timeout: int = Field(default=30)

    @model_validator(mode="after")
    def _validate_endpoints(self):
        if not self.endpoint and not self.endpoints:
            raise ValueError("Provide either 'endpoint' or 'endpoints' (one or more endpoints to scan)")
        return self


class FullScanRequest(TargetConfig):
    pass


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

app = FastAPI(title="API Vulnerability Scanner", version="1.2.0")

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


def _latest_spec_path() -> Optional[str]:
    try:
        files = [
            os.path.join(SPECS_DIR, f)
            for f in os.listdir(SPECS_DIR)
            if os.path.isfile(os.path.join(SPECS_DIR, f)) and os.path.splitext(f)[1].lower() in {".json", ".yaml", ".yml"}
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

    # Prefer provided OpenAPI path, else fall back to the latest uploaded spec in volume
    openapi_path = req.openapi_path or _latest_spec_path()

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
    # Fall back to latest uploaded spec if not provided
    if not req.openapi_path:
        latest = _latest_spec_path()
        if latest:
            req.openapi_path = latest
    async with APIPenTester(req) as scanner:
        report = await scanner.run_scan()
        return report


# ----------------------------------------------------------------------------
# Spec management endpoints
# ----------------------------------------------------------------------------


@app.post("/api/v1/spec/upload")
async def upload_spec(file: UploadFile = File(...), _: bool = Depends(require_api_token)):
    """Upload an OpenAPI spec (JSON or YAML) and save to the mounted volume.
    Returns basic metadata and a derived summary.
    """
    filename = os.path.basename(file.filename or "spec.json")
    # Basic sanitization: disallow path traversal
    filename = filename.replace("..", "_").replace("/", "_").replace("\\", "_")
    if os.path.splitext(filename)[1].lower() not in {".json", ".yaml", ".yml"}:
        raise HTTPException(status_code=400, detail="Only .json, .yaml, .yml are supported")

    dest_path = os.path.join(SPECS_DIR, filename)
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
        "saved_as": dest_path,
        "server_url": resolved,
        "operations": len(ops),
        "endpoints": len(endpoints),
        "filename": filename,
    }


@app.get("/api/v1/spec/endpoints")
async def get_extracted_endpoints(
    file: Optional[str] = Query(default=None, description="Optional spec filename to parse; defaults to latest uploaded"),
    methods: Optional[List[str]] = Query(default=None, description="Filter by HTTP methods (e.g., GET,POST)"),
    _: bool = Depends(require_api_token),
):
    """Return only the list of endpoints with request type from a stored spec.
    If no file is provided, the most recently uploaded spec is used.
    Response is a flat list of objects: [{"method": "GET", "endpoint": "/users"}]
    Note: Any scheme/host from the spec is stripped; only the path portion is returned.
    """
    path = None
    if file:
        sanitized = os.path.basename(file).replace("..", "_")
        candidate = os.path.join(SPECS_DIR, sanitized)
        if not os.path.exists(candidate):
            raise HTTPException(status_code=404, detail="Specified spec file not found")
        path = candidate
    else:
        path = _latest_spec_path()
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


# Optional: local run (uvicorn)
if __name__ == "__main__":
    import uvicorn

    # Safety: refuse default token in non-dev scenarios
    if os.getenv("API_AUTH_TOKEN", "changeme") == "changeme":
        print("WARNING: Using default API_AUTH_TOKEN. Set API_AUTH_TOKEN before exposing the server.")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)