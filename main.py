"""
FastAPI backend for the API Vulnerability Scanner.

Provides endpoints to:
- Scan a single endpoint with selected vulnerability tests
- Run a complete scan using OpenAPI and/or explicit endpoints

Security: Bearer token via Authorization header. Configure API_AUTH_TOKEN env var.
"""

import os
import asyncio
from typing import List, Optional
from urllib.parse import urljoin

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, HttpUrl

from scanner_core import (
    APIPenTester,
    TargetConfig,
    AuthConfig,
    ScanReport,
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
    endpoint: str = Field(..., description="Endpoint path or absolute URL, e.g., /users or https://api.example.com/users")
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


class FullScanRequest(TargetConfig):
    pass


# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------

app = FastAPI(title="API Vulnerability Scanner", version="1.0.0")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/scan/endpoint", response_model=ScanReport)
async def scan_single_endpoint(req: EndpointScanRequest, _: bool = Depends(require_api_token)):
    # Build absolute endpoint URL
    endpoint_url = req.endpoint
    if not endpoint_url.startswith("http://") and not endpoint_url.startswith("https://"):
        endpoint_url = urljoin(str(req.base_url), req.endpoint)

    config = TargetConfig(
        base_url=req.base_url,
        endpoints=[endpoint_url],
        openapi_path=req.openapi_path,
        auth=req.auth,
        rate_limit=req.rate_limit,
        timeout=req.timeout,
    )

    async with APIPenTester(config) as scanner:
        # If we have an OpenAPI spec, APIPenTester will try to load operations, useful for body gen
        findings = await scanner.run_selected_tests_on_endpoint(endpoint_url, req.selected_tests, method=req.method.upper())
        scanner.report.findings.extend(findings)
        scanner.report.scan_end = scanner.report.scan_end or scanner.report.scan_start
        return scanner.report


@app.post("/api/v1/scan/full", response_model=ScanReport)
async def scan_full(req: FullScanRequest, _: bool = Depends(require_api_token)):
    async with APIPenTester(req) as scanner:
        report = await scanner.run_scan()
        return report


# Optional: local run (uvicorn)
if __name__ == "__main__":
    import uvicorn

    # Safety: refuse default token in non-dev scenarios
    if os.getenv("API_AUTH_TOKEN", "changeme") == "changeme":
        print("WARNING: Using default API_AUTH_TOKEN. Set API_AUTH_TOKEN before exposing the server.")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)