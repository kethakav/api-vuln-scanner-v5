"""
API Penetration Testing Tool v1.0
A comprehensive automated security testing tool for REST APIs

LEGAL NOTICE:
This tool is for AUTHORIZED SECURITY TESTING ONLY.
Always obtain written permission before testing any API.
Unauthorized testing may violate laws and regulations.

Requirements:
pip install httpx==0.28.1 pydantic==2.12.3 pyjwt==2.10.1 rich==13.9.4 pyyaml==6.0.2
"""

import asyncio
import json
import os
import re
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from enum import Enum
from pathlib import Path

import httpx
import jwt
from pydantic import BaseModel, Field, HttpUrl, field_validator, TypeAdapter
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None


# ============================================================================
# DATA MODELS
# ============================================================================

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(str, Enum):
    AUTH_BYPASS = "Authentication Bypass"
    BROKEN_AUTH = "Broken Authentication"
    IDOR = "Insecure Direct Object Reference"
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    XSS = "Cross-Site Scripting"
    XXE = "XML External Entity"
    RATE_LIMIT = "Missing Rate Limiting"
    CORS = "CORS Misconfiguration"
    INFO_DISCLOSURE = "Information Disclosure"
    MASS_ASSIGNMENT = "Mass Assignment"
    JWT_VULN = "JWT Vulnerability"


class AuthConfig(BaseModel):
    """Authentication configuration"""
    auth_type: str = Field(default="bearer", description="Auth type: bearer, basic, apikey")
    token: Optional[str] = Field(default=None, description="Bearer token or API key")
    username: Optional[str] = Field(default=None, description="Basic auth username")
    password: Optional[str] = Field(default=None, description="Basic auth password")
    header_name: Optional[str] = Field(default="Authorization", description="Auth header name")


class TargetConfig(BaseModel):
    """Target API configuration"""
    base_url: HttpUrl
    endpoints: List[str] = Field(default_factory=list)
    openapi_path: Optional[str] = Field(
        default=None,
        description="Path to an OpenAPI 3.x spec file (.yml/.yaml/.json) to auto-discover endpoints and defaults"
    )
    auth: Optional[AuthConfig] = None
    rate_limit: int = Field(default=10, description="Max requests per second")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    
    @field_validator('base_url')
    @classmethod
    def validate_url(cls, v):
        url_str = str(v)
        if not url_str.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


# ============================================================================
# OPENAPI SPEC LOADER
# ============================================================================

class OpenAPISpecUtil:
    """Utilities to parse OpenAPI 3.x specs and extract endpoints and auth config."""

    METHOD_KEYS = {"get", "post", "put", "delete", "patch", "head", "options"}

    @staticmethod
    def _load_spec(path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"OpenAPI spec not found: {path}")

        ext = os.path.splitext(path)[1].lower()
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()

        if ext in (".yaml", ".yml"):
            if yaml is None:
                raise RuntimeError(
                    "PyYAML is required to read YAML OpenAPI specs. Install with 'pip install pyyaml'."
                )
            return yaml.safe_load(text)
        else:
            return json.loads(text)

    @staticmethod
    def _resolve_server_url(spec: Dict[str, Any]) -> Optional[str]:
        servers = spec.get("servers") or []
        if not servers:
            return None
        url = servers[0].get("url") if isinstance(servers[0], dict) else None
        if not url:
            return None
        # Substitute {var} with default values if provided
        variables = servers[0].get("variables", {}) if isinstance(servers[0], dict) else {}
        def replace_var(match: re.Match[str]) -> str:
            name = match.group(1)
            default = variables.get(name, {}).get("default")
            return str(default) if default is not None else name
        url = re.sub(r"\{([^}]+)\}", replace_var, url)
        return url

    @staticmethod
    def _join_url(base_url: str, path: str) -> str:
        base = base_url.rstrip("/")
        p = path if path.startswith("/") else f"/{path}"
        return f"{base}{p}"

    @classmethod
    def extract_endpoints(
        cls,
        spec: Dict[str, Any],
        base_url: Optional[str] = None,
        methods: Optional[List[str]] = None,
    ) -> Tuple[List[str], Optional[str]]:
        """
        Returns (endpoints, resolved_base_url)

        - endpoints: list of absolute URLs for chosen methods (default: GET only)
        - resolved_base_url: server URL derived from spec, if any
        """
        resolved_base = base_url or cls._resolve_server_url(spec)
        paths = spec.get("paths") or {}
        method_filter = set(m.lower() for m in (methods or ["get"]))

        endpoints: List[str] = []
        for path_key, ops in paths.items():
            if not isinstance(ops, dict):
                continue
            for method, op in ops.items():
                if method.lower() in method_filter and method.lower() in cls.METHOD_KEYS:
                    if resolved_base:
                        endpoints.append(cls._join_url(resolved_base, path_key))
                    # If no base URL, skip absolute formation; caller can join using config base_url
                    elif base_url:
                        endpoints.append(cls._join_url(base_url, path_key))
        # De-duplicate while preserving order
        seen = set()
        deduped = []
        for url in endpoints:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped, resolved_base

    @classmethod
    def extract_operations(
        cls,
        spec: Dict[str, Any],
        base_url: Optional[str] = None,
        methods: Optional[List[str]] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Returns (operations, resolved_base_url)

        Each operation is a dict: {
          'method': 'get'|'post'|..., 'path': '/users', 'url': 'https://..',
          'operationId': str|None, 'parameters': [...], 'requestBody': {...}|None
        }
        """
        resolved_base = base_url or cls._resolve_server_url(spec)
        paths = spec.get("paths") or {}
        method_filter = set(m.lower() for m in (methods or ["get", "post", "put", "patch", "delete"]))
        ops: List[Dict[str, Any]] = []

        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                m = method.lower()
                if m not in method_filter or m not in cls.METHOD_KEYS:
                    continue
                if not isinstance(op, dict):
                    continue
                url = None
                if resolved_base:
                    url = cls._join_url(resolved_base, path_key)
                elif base_url:
                    url = cls._join_url(base_url, path_key)
                ops.append({
                    "method": m,
                    "path": path_key,
                    "url": url or path_key,
                    "operationId": op.get("operationId"),
                    "parameters": op.get("parameters", []),
                    "requestBody": op.get("requestBody"),
                })
        return ops, resolved_base

    @staticmethod
    def derive_auth_config(spec: Dict[str, Any]) -> Optional[AuthConfig]:
        """
        Map OpenAPI securitySchemes to our AuthConfig defaults.
        Only sets types and header names; credentials remain None.
        """
        components = spec.get("components", {})
        schemes = components.get("securitySchemes", {}) or {}
        if not isinstance(schemes, dict) or not schemes:
            return None

        # Choose the first scheme referenced by the global security requirement if present
        security_reqs = spec.get("security") or []
        chosen_name: Optional[str] = None
        if isinstance(security_reqs, list) and security_reqs:
            first_req = security_reqs[0]
            if isinstance(first_req, dict) and first_req:
                chosen_name = next(iter(first_req.keys()))

        # Fallback: any one scheme
        if not chosen_name:
            chosen_name = next(iter(schemes.keys()))

        scheme = schemes.get(chosen_name, {}) if chosen_name else {}
        if not scheme:
            return None

        typ = scheme.get("type")
        if typ == "http":
            scheme_name = (scheme.get("scheme") or "").lower()
            if scheme_name == "bearer":
                return AuthConfig(auth_type="bearer", header_name="Authorization")
            if scheme_name == "basic":
                return AuthConfig(auth_type="basic", header_name="Authorization")
        elif typ == "apiKey":
            in_ = scheme.get("in")
            name = scheme.get("name") or "Authorization"
            if in_ == "header":
                return AuthConfig(auth_type="apikey", header_name=name)
        # Other types (oauth2/openIdConnect) are not auto-configured here
        return None


class Finding(BaseModel):
    """Security finding/vulnerability"""
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    endpoint: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: str
    timestamp: datetime = Field(default_factory=datetime.now)


class ScanReport(BaseModel):
    """Complete scan report"""
    target: str
    scan_start: datetime
    scan_end: Optional[datetime] = None
    findings: List[Finding] = Field(default_factory=list)
    endpoints_tested: int = 0
    requests_made: int = 0


# ============================================================================
# PAYLOAD LIBRARY
# ============================================================================

class PayloadLibrary:
    """Curated payload library for various vulnerability types"""
    
    SQL_INJECTION = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "1' UNION SELECT NULL--",
        "1' AND 1=1--",
        "1' AND 1=2--",
    ]
    
    NOSQL_INJECTION = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '[$ne]=1',
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
    ]
    
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    ]
    
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
    ]
    
    JWT_ALGORITHMS = ["none", "HS256", "RS256"]


# ============================================================================
# TEST MODULES
# ============================================================================

class AuthenticationTests:
    """Authentication and authorization testing"""
    
    @staticmethod
    async def test_broken_auth(
        client: httpx.AsyncClient,
        endpoint: str,
        method: str = "GET"
    ) -> List[Finding]:
        findings = []
        
        # Test 1: Access without authentication (use a fresh client with no default headers)
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=getattr(client, "timeout", None)) as unauth_client:
                resp = await unauth_client.request(method.upper(), endpoint)
            if resp.status_code == 200:
                findings.append(Finding(
                    vuln_type=VulnerabilityType.BROKEN_AUTH,
                    severity=SeverityLevel.CRITICAL,
                    endpoint=endpoint,
                    description="Endpoint accessible without authentication",
                    evidence={"status_code": resp.status_code},
                    remediation="Implement proper authentication checks"
                ))
        except Exception as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")
        
        return findings
    
    @staticmethod
    async def test_jwt_vulnerabilities(
        client: httpx.AsyncClient,
        token: str,
        endpoint: str
    ) -> List[Finding]:
        findings = []
        
        try:
            # Decode payload without verification to inspect claims
            decoded = jwt.decode(token, options={"verify_signature": False})
            # Inspect header to determine algorithm
            try:
                header = jwt.get_unverified_header(token)
            except Exception:
                header = {}
            alg = (header.get("alg") or "").lower()
            
            # Check 1: Weak/none algorithm in header
            if alg == "none":
                findings.append(Finding(
                    vuln_type=VulnerabilityType.JWT_VULN,
                    severity=SeverityLevel.CRITICAL,
                    endpoint=endpoint,
                    description="JWT header uses 'none' algorithm - no signature verification",
                    evidence={"algorithm": "none"},
                    remediation="Never accept or issue JWTs with alg=none; enforce strong algorithms and verification"
                ))
            
            # Check 2: Long expiration
            if "exp" in decoded:
                exp_time = datetime.fromtimestamp(decoded["exp"])
                days_until_exp = (exp_time - datetime.now()).days
                if days_until_exp > 365:
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.JWT_VULN,
                        severity=SeverityLevel.MEDIUM,
                        endpoint=endpoint,
                        description=f"JWT has very long expiration ({days_until_exp} days)",
                        evidence={"expiration": str(exp_time)},
                        remediation="Use shorter token expiration times (e.g., 15-60 minutes)"
                    ))

            # Optional active probe: try forged 'alg=none' token and see if accepted
            try:
                import base64
                def b64url(data: bytes) -> str:
                    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

                header_none = {"alg": "none", "typ": "JWT"}
                payload = decoded if isinstance(decoded, dict) else {}
                forged_header = b64url(json.dumps(header_none, separators=(',', ':')).encode())
                forged_payload = b64url(json.dumps(payload, separators=(',', ':')).encode())
                forged = f"{forged_header}.{forged_payload}."

                resp = await client.get(endpoint, headers={"Authorization": f"Bearer {forged}"})
                if resp.status_code == 200:
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.JWT_VULN,
                        severity=SeverityLevel.CRITICAL,
                        endpoint=endpoint,
                        description="API accepted an unsigned JWT (alg=none)",
                        evidence={"status_code": resp.status_code},
                        remediation="Reject tokens with alg=none and verify signature for all JWTs"
                    ))
            except Exception:
                pass
        
        except jwt.DecodeError:
            pass  # Invalid token format
        except Exception as e:
            console.print(f"[yellow]JWT analysis warning: {e}[/yellow]")
        
        return findings


class InjectionTests:
    """SQL and NoSQL injection testing"""
    
    @staticmethod
    async def test_sql_injection(
        client: httpx.AsyncClient, 
        endpoint: str, 
        param: str
    ) -> List[Finding]:
        findings = []
        
        for payload in PayloadLibrary.SQL_INJECTION:
            try:
                # Test in query parameter
                resp = await client.get(f"{endpoint}?{param}={payload}")
                
                # Look for SQL error patterns
                error_patterns = [
                    "sql", "mysql", "postgresql", "syntax error",
                    "database error", "query failed", "ORA-"
                ]
                
                resp_text = resp.text.lower()
                if any(pattern in resp_text for pattern in error_patterns):
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=SeverityLevel.CRITICAL,
                        endpoint=endpoint,
                        description=f"Possible SQL injection in parameter '{param}'",
                        evidence={
                            "payload": payload,
                            "status_code": resp.status_code,
                            "response_snippet": resp.text[:200]
                        },
                        remediation="Use parameterized queries and input validation"
                    ))
                    break  # One finding per parameter is enough
                
                await asyncio.sleep(0.1)  # Rate limiting
            
            except Exception as e:
                console.print(f"[yellow]SQL injection test warning: {e}[/yellow]")
        
        return findings
    
    @staticmethod
    async def test_nosql_injection(
        client: httpx.AsyncClient,
        endpoint: str,
        param: str
    ) -> List[Finding]:
        findings = []
        
        for payload in PayloadLibrary.NOSQL_INJECTION:
            try:
                # Test in JSON body
                resp = await client.post(
                    endpoint,
                    json={param: payload},
                    headers={"Content-Type": "application/json"}
                )
                
                # Check for successful injection signs
                if resp.status_code == 200 and len(resp.text) > 100:
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.NOSQL_INJECTION,
                        severity=SeverityLevel.HIGH,
                        endpoint=endpoint,
                        description=f"Possible NoSQL injection in parameter '{param}'",
                        evidence={
                            "payload": payload,
                            "status_code": resp.status_code
                        },
                        remediation="Use proper input validation and sanitization for NoSQL databases"
                    ))
                    break
                
                await asyncio.sleep(0.1)
            
            except Exception as e:
                console.print(f"[yellow]NoSQL injection test warning: {e}[/yellow]")
        
        return findings

    @staticmethod
    async def test_nosql_injection_in_body(
        client: httpx.AsyncClient,
        endpoint: str,
        base_body: Dict[str, Any]
    ) -> List[Finding]:
        """Attempt NoSQL injection by mutating one field in a JSON body.
        Chooses a string-like field and injects common NoSQL payloads.
        """
        findings: List[Finding] = []

        # Helper to find candidate field path
        def _first_scalar_key(d: Any, path: List[str]) -> Optional[List[str]]:
            if isinstance(d, dict):
                for k, v in d.items():
                    p = path + [k]
                    if isinstance(v, (str, int, float)):
                        return p
                    res = _first_scalar_key(v, p)
                    if res is not None:
                        return res
            elif isinstance(d, list) and d:
                return _first_scalar_key(d[0], path + ["0"])  # treat first element
            return None

        target_path = _first_scalar_key(base_body, [])
        if not target_path:
            return findings

        # function to set value by path
        def _set_path(obj: Any, path: List[str], value: Any) -> Any:
            if not path:
                return value
            head, *tail = path
            if isinstance(obj, list):
                idx = int(head)
                obj[idx] = _set_path(obj[idx], tail, value)
            else:
                obj[head] = _set_path(obj.get(head), tail, value)
            return obj

        for payload in PayloadLibrary.NOSQL_INJECTION:
            try:
                mutated = json.loads(json.dumps(base_body))  # deep copy
                _set_path(mutated, target_path, payload)
                resp = await client.post(endpoint, json=mutated, headers={"Content-Type": "application/json"})
                if resp.status_code == 200 and len(resp.text or "") > 100:
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.NOSQL_INJECTION,
                        severity=SeverityLevel.HIGH,
                        endpoint=endpoint,
                        description=f"Possible NoSQL injection via body field path {'/'.join(target_path)}",
                        evidence={"payload": payload, "status_code": resp.status_code},
                        remediation="Validate and sanitize JSON bodies; disallow operator injection in user input"
                    ))
                    break
            except Exception:
                continue
            await asyncio.sleep(0.05)

        return findings


class APISecurityTests:
    """API-specific security tests"""
    
    @staticmethod
    async def test_idor(
        client: httpx.AsyncClient,
        endpoint: str,
        id_param: str = "id"
    ) -> List[Finding]:
        findings = []
        
        # Test sequential IDs
        test_ids = [1, 2, 999, 1000]
        responses = []
        
        for test_id in test_ids:
            try:
                resp = await client.get(f"{endpoint}/{test_id}")
                responses.append((test_id, resp.status_code))
                await asyncio.sleep(0.1)
            except Exception:
                pass
        
        # If multiple IDs return 200, possible IDOR
        success_count = sum(1 for _, status in responses if status == 200)
        if success_count > 1:
            findings.append(Finding(
                vuln_type=VulnerabilityType.IDOR,
                severity=SeverityLevel.HIGH,
                endpoint=endpoint,
                description="Possible IDOR vulnerability - sequential IDs accessible",
                evidence={"responses": responses},
                remediation="Implement proper authorization checks for resource access"
            ))
        
        return findings
    
    @staticmethod
    async def test_rate_limiting(
        client: httpx.AsyncClient,
        endpoint: str,
        requests_count: int = 100,
        method: str = "GET"
    ) -> List[Finding]:
        findings = []
        
        try:
            start_time = time.time()
            concurrency = min(20, max(5, requests_count // 5))
            sem = asyncio.Semaphore(concurrency)

            statuses: List[int] = []
            headers_list: List[Dict[str, str]] = []

            async def fetch_once():
                async with sem:
                    r = await client.request(method.upper(), endpoint)
                    statuses.append(r.status_code)
                    headers_list.append({k: v for k, v in r.headers.items()})

            await asyncio.gather(*[fetch_once() for _ in range(requests_count)])
            elapsed = time.time() - start_time

            # Indicators of rate limiting present
            has_429 = any(s == 429 for s in statuses)
            has_rl_headers = any(
                any(h for h in hdrs.keys() if h.lower() in {"x-ratelimit-remaining", "x-ratelimit-limit", "retry-after"})
                for hdrs in headers_list
            )

            if not has_429 and not has_rl_headers:
                success_count = sum(1 for s in statuses if 200 <= s < 300)
                # If most succeeded very quickly, likely missing rate limiting
                if success_count >= int(0.9 * requests_count) and elapsed < 2.0:
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.RATE_LIMIT,
                        severity=SeverityLevel.MEDIUM,
                        endpoint=endpoint,
                        description=f"No rate limiting detected - {requests_count} requests in {elapsed:.2f}s",
                        evidence={
                            "requests": requests_count,
                            "time": f"{elapsed:.2f}s",
                            "success_rate": f"{success_count}/{requests_count}"
                        },
                        remediation="Implement rate limiting to prevent abuse"
                    ))
        
        except Exception as e:
            console.print(f"[yellow]Rate limit test warning: {e}[/yellow]")
        
        return findings
    
    @staticmethod
    async def test_cors(
        client: httpx.AsyncClient,
        endpoint: str
    ) -> List[Finding]:
        findings = []
        
        try:
            # Test with custom origin
            resp = await client.options(
                endpoint,
                headers={"Origin": "https://evil.com"}
            )
            
            cors_header = resp.headers.get("Access-Control-Allow-Origin", "")
            creds_header = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if cors_header == "*":
                findings.append(Finding(
                    vuln_type=VulnerabilityType.CORS,
                    severity=SeverityLevel.MEDIUM,
                    endpoint=endpoint,
                    description="CORS policy allows all origins (*)",
                    evidence={"ACAO": cors_header},
                    remediation="Restrict CORS to specific trusted origins"
                ))
            elif "evil.com" in cors_header:
                findings.append(Finding(
                    vuln_type=VulnerabilityType.CORS,
                    severity=SeverityLevel.HIGH,
                    endpoint=endpoint,
                    description="CORS policy reflects arbitrary origins",
                    evidence={"ACAO": cors_header, "test_origin": "https://evil.com"},
                    remediation="Use a whitelist of allowed origins"
                ))
            
            # Credentials + wildcard is a misconfiguration
            if cors_header == "*" and creds_header.lower() == "true":
                findings.append(Finding(
                    vuln_type=VulnerabilityType.CORS,
                    severity=SeverityLevel.HIGH,
                    endpoint=endpoint,
                    description="CORS allows credentials with wildcard origin (*)",
                    evidence={"ACAO": cors_header, "ACAC": creds_header},
                    remediation="Do not use '*' with credentials; specify exact allowed origins"
                ))
        
        except Exception as e:
            console.print(f"[yellow]CORS test warning: {e}[/yellow]")
        
        return findings
    
    @staticmethod
    async def test_sensitive_data_exposure(
        client: httpx.AsyncClient,
        endpoint: str
    ) -> List[Finding]:
        findings = []
        
        try:
            resp = await client.get(endpoint)
            resp_text = resp.text.lower()
            
            # Check for sensitive data patterns
            sensitive_patterns = {
                "password": "Password field in response",
                "secret": "Secret/API key in response",
                "credit_card": "Credit card pattern",
                "ssn": "Social Security Number pattern",
                "api_key": "API key in response",
                "private_key": "Private key in response"
            }
            
            for pattern, description in sensitive_patterns.items():
                if pattern in resp_text:
                    findings.append(Finding(
                        vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                        severity=SeverityLevel.HIGH,
                        endpoint=endpoint,
                        description=description,
                        evidence={"pattern": pattern},
                        remediation="Remove sensitive data from API responses"
                    ))
        
        except Exception as e:
            console.print(f"[yellow]Sensitive data test warning: {e}[/yellow]")
        
        return findings

    @staticmethod
    async def test_xss_reflection(
        client: httpx.AsyncClient,
        endpoint: str,
        param: str = "q"
    ) -> List[Finding]:
        """Detect possible reflected XSS by injecting payloads into a query parameter.
        Heuristic: payload appears verbatim in the response body.
        """
        findings: List[Finding] = []
        try:
            for payload in PayloadLibrary.XSS_PAYLOADS:
                try:
                    # Use QueryParams to safely encode
                    qp = httpx.QueryParams({param: payload})
                    resp = await client.get(f"{endpoint}?{qp}")
                    body = resp.text or ""
                    if payload in body:
                        findings.append(Finding(
                            vuln_type=VulnerabilityType.XSS,
                            severity=SeverityLevel.HIGH,
                            endpoint=endpoint,
                            description=f"Reflected XSS via parameter '{param}'",
                            evidence={"payload": payload, "status_code": resp.status_code},
                            remediation="Sanitize inputs and apply context-aware output encoding"
                        ))
                        break
                except Exception:
                    continue
                await asyncio.sleep(0.05)
        except Exception as e:
            console.print(f"[yellow]XSS test warning: {e}[/yellow]")
        return findings


# ============================================================================
# MAIN SCANNER
# ============================================================================

class APIPenTester:
    """Main API penetration testing engine"""
    
    def __init__(self, config: TargetConfig, transport: Any = None):
        self.config = config
        self.report = ScanReport(
            target=str(config.base_url),
            scan_start=datetime.now()
        )
        self.client: Optional[httpx.AsyncClient] = None
        self.transport = transport
        self.spec: Optional[Dict[str, Any]] = None
        self.operations: List[Dict[str, Any]] = []
        # If an OpenAPI spec path is provided, attempt to populate endpoints and defaults
        if self.config.openapi_path:
            try:
                spec = OpenAPISpecUtil._load_spec(self.config.openapi_path)
                self.spec = spec
                # Try to extract GET endpoints if none explicitly provided
                if not self.config.endpoints:
                    endpoints, resolved_base = OpenAPISpecUtil.extract_endpoints(
                        spec, base_url=str(self.config.base_url), methods=["get"]
                    )
                    if endpoints:
                        self.config.endpoints = endpoints
                else:
                    # Even if endpoints are provided, we may still want the server URL
                    _, resolved_base = OpenAPISpecUtil.extract_endpoints(
                        spec, base_url=str(self.config.base_url), methods=["get"]
                    )
                # If spec declares a server, update base_url for the client
                if resolved_base:
                    try:
                        # Best effort: update base URL string in report target as well
                        self.config.base_url = TypeAdapter(HttpUrl).validate_python(resolved_base)  # type: ignore
                        self.report.target = str(self.config.base_url)
                    except Exception:
                        # Keep original base_url if resolution fails validation
                        pass
                # Try to infer auth config if not provided
                if not self.config.auth:
                    inferred = OpenAPISpecUtil.derive_auth_config(spec)
                    if inferred:
                        self.config.auth = inferred
                        console.print("[dim]Auth inferred from OpenAPI securitySchemes; add credentials to use.[/dim]")
                # Extract broader set of operations (GET/POST/PUT/PATCH/DELETE)
                ops, _ = OpenAPISpecUtil.extract_operations(
                    spec, base_url=str(self.config.base_url)
                )
                if ops:
                    self.operations = ops
            except Exception as e:
                console.print(f"[yellow]OpenAPI parsing skipped: {e}[/yellow]")
    
    async def __aenter__(self):
        headers = {}
        
        # Configure authentication
        if self.config.auth:
            if self.config.auth.auth_type == "bearer" and self.config.auth.token:
                headers[self.config.auth.header_name] = f"Bearer {self.config.auth.token}"
            elif self.config.auth.auth_type == "apikey" and self.config.auth.token:
                headers[self.config.auth.header_name] = self.config.auth.token
        
        async def _on_response(response: httpx.Response):
            # Increment request counter for reporting
            try:
                self.report.requests_made += 1
            except Exception:
                pass

        common_kwargs = dict(
            base_url=str(self.config.base_url),
            headers=headers,
            timeout=self.config.timeout,
            follow_redirects=True,
            event_hooks={"response": [_on_response]},
        )

        if self.transport is not None:
            self.client = httpx.AsyncClient(transport=self.transport, **common_kwargs)
        else:
            self.client = httpx.AsyncClient(**common_kwargs)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()
    
    async def scan_endpoint(self, endpoint: str) -> List[Finding]:
        """Run all tests on a single endpoint"""
        all_findings = []
        
        console.print(f"[cyan]Testing endpoint:[/cyan] {endpoint}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running tests...", total=None)
            
            # Authentication tests
            progress.update(task, description="Testing authentication...")
            findings = await AuthenticationTests.test_broken_auth(self.client, endpoint, "GET")
            all_findings.extend(findings)
            
            # JWT tests (if token provided)
            if self.config.auth and self.config.auth.token:
                progress.update(task, description="Analyzing JWT...")
                findings = await AuthenticationTests.test_jwt_vulnerabilities(
                    self.client, self.config.auth.token, endpoint
                )
                all_findings.extend(findings)
            
            # Injection tests
            progress.update(task, description="Testing SQL injection...")
            findings = await InjectionTests.test_sql_injection(
                self.client, endpoint, "id"
            )
            all_findings.extend(findings)
            
            progress.update(task, description="Testing NoSQL injection...")
            findings = await InjectionTests.test_nosql_injection(
                self.client, endpoint, "id"
            )
            all_findings.extend(findings)
            
            # API security tests
            progress.update(task, description="Testing IDOR...")
            findings = await APISecurityTests.test_idor(self.client, endpoint)
            all_findings.extend(findings)
            
            progress.update(task, description="Testing CORS...")
            findings = await APISecurityTests.test_cors(self.client, endpoint)
            all_findings.extend(findings)
            
            progress.update(task, description="Checking sensitive data...")
            findings = await APISecurityTests.test_sensitive_data_exposure(
                self.client, endpoint
            )
            all_findings.extend(findings)
            
            progress.update(task, description="Testing reflected XSS...")
            findings = await APISecurityTests.test_xss_reflection(
                self.client, endpoint, "q"
            )
            all_findings.extend(findings)
            
            # Rate limiting (do this last as it's intensive)
            progress.update(task, description="Testing rate limiting...")
            findings = await APISecurityTests.test_rate_limiting(
                self.client, endpoint, requests_count=50, method="GET"
            )
            all_findings.extend(findings)
        
        self.report.endpoints_tested += 1
        return all_findings

    async def scan_operation(self, op: Dict[str, Any]) -> List[Finding]:
        """Run tests tailored to the HTTP method of the operation."""
        method = op.get("method", "get").upper()
        endpoint = op.get("url")
        if not endpoint:
            return []
        all_findings: List[Finding] = []

        console.print(f"[cyan]Testing {method} operation:[/cyan] {endpoint}")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running tests...", total=None)

            # Broken auth using the correct method
            progress.update(task, description="Testing authentication...")
            findings = await AuthenticationTests.test_broken_auth(self.client, endpoint, method)
            all_findings.extend(findings)

            # JWT tests
            if self.config.auth and self.config.auth.token:
                progress.update(task, description="Analyzing JWT...")
                findings = await AuthenticationTests.test_jwt_vulnerabilities(
                    self.client, self.config.auth.token, endpoint
                )
                all_findings.extend(findings)

            # Injection/body tests for write methods
            if method in {"POST", "PUT", "PATCH"}:
                # Baseline request using generated body if possible
                body = self._generate_request_body(op)
                if body is not None:
                    try:
                        await self.client.request(method, endpoint, json=body)
                    except Exception:
                        pass
                progress.update(task, description="Testing NoSQL injection (body)...")
                if body is not None and isinstance(body, dict):
                    findings = await InjectionTests.test_nosql_injection_in_body(self.client, endpoint, body)
                else:
                    findings = await InjectionTests.test_nosql_injection(self.client, endpoint, "id")
                all_findings.extend(findings)

            # CORS (preflight/OPTIONS)
            progress.update(task, description="Testing CORS...")
            findings = await APISecurityTests.test_cors(self.client, endpoint)
            all_findings.extend(findings)

            # Rate limiting using the method
            progress.update(task, description="Testing rate limiting...")
            findings = await APISecurityTests.test_rate_limiting(self.client, endpoint, requests_count=30, method=method)
            all_findings.extend(findings)

        self.report.endpoints_tested += 1
        return all_findings

    def _generate_request_body(self, op: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a minimal JSON body from the operation's requestBody schema or examples.
        Only handles application/json. Best-effort with simple types and refs.
        """
        try:
            rb = op.get("requestBody") or {}
            content = rb.get("content") if isinstance(rb, dict) else None
            if not content or not isinstance(content, dict):
                return None
            # Prefer application/json
            json_ct = None
            for ct in ("application/json", "application/*+json"):
                if ct in content:
                    json_ct = content[ct]
                    break
            if not json_ct:
                # pick first json-like
                for ct, v in content.items():
                    if "json" in ct:
                        json_ct = v
                        break
            if not json_ct or not isinstance(json_ct, dict):
                return None

            # examples
            if "example" in json_ct and isinstance(json_ct["example"], dict):
                return json_ct["example"]
            exs = json_ct.get("examples")
            if isinstance(exs, dict) and exs:
                first = next(iter(exs.values()))
                if isinstance(first, dict):
                    if "value" in first and isinstance(first["value"], dict):
                        return first["value"]

            schema = json_ct.get("schema")
            components = (self.spec or {}).get("components", {}) if self.spec else {}
            if schema and isinstance(schema, dict):
                return self._generate_from_schema(schema, components)
        except Exception:
            return None
        return None

    def _resolve_ref(self, ref: str, components: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not ref.startswith("#/"):
            return None
        parts = ref.lstrip("#/").split("/")
        node: Any = components
        for p in parts[1:]:  # first part should be 'components'
            if isinstance(node, dict) and p in node:
                node = node[p]
            else:
                return None
        return node if isinstance(node, dict) else None

    def _generate_from_schema(self, schema: Dict[str, Any], components: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        if depth > 3:
            return {}
        # $ref
        if "$ref" in schema:
            target = self._resolve_ref(schema["$ref"], {"components": components})
            if isinstance(target, dict):
                return self._generate_from_schema(target, components, depth + 1)
            return {}

        typ = schema.get("type")
        if not typ and "oneOf" in schema and isinstance(schema["oneOf"], list) and schema["oneOf"]:
            return self._generate_from_schema(schema["oneOf"][0], components, depth + 1)
        if not typ and "anyOf" in schema and isinstance(schema["anyOf"], list) and schema["anyOf"]:
            return self._generate_from_schema(schema["anyOf"][0], components, depth + 1)

        if typ == "object" or ("properties" in schema):
            props = schema.get("properties", {})
            required = set(schema.get("required", []) or [])
            result: Dict[str, Any] = {}
            for name, subschema in props.items():
                val: Any
                # enums
                if isinstance(subschema, dict) and "enum" in subschema and subschema["enum"]:
                    val = subschema["enum"][0]
                else:
                    val = self._generate_value(subschema or {}, components, depth + 1)
                # include if required or small payload
                if name in required or len(result) < 5:
                    result[name] = val
            return result
        # default empty object if unspecified
        return {}

    def _generate_value(self, schema: Dict[str, Any], components: Dict[str, Any], depth: int) -> Any:
        if "$ref" in schema:
            target = self._resolve_ref(schema["$ref"], {"components": components})
            if isinstance(target, dict):
                # Resolve recursively and then return generated value (object)
                return self._generate_from_schema(target, components, depth + 1)
            return None

        typ = schema.get("type")
        fmt = schema.get("format")
        if typ == "string":
            if "enum" in schema and schema["enum"]:
                return schema["enum"][0]
            if fmt == "email":
                return "user@example.com"
            if fmt == "uuid":
                return "00000000-0000-4000-8000-000000000000"
            if fmt == "date-time":
                return datetime.utcnow().isoformat() + "Z"
            return schema.get("default") or schema.get("example") or "test"
        if typ == "integer":
            return schema.get("default") or 1
        if typ == "number":
            return schema.get("default") or 1.0
        if typ == "boolean":
            return schema.get("default") if isinstance(schema.get("default"), bool) else True
        if typ == "array":
            items = schema.get("items") or {}
            return [self._generate_value(items, components, depth + 1)]
        if typ == "object" or "properties" in schema:
            return self._generate_from_schema(schema, components, depth + 1)
        # fallback
        return None
    
    async def run_scan(self) -> ScanReport:
        """Execute complete security scan"""
        console.print(Panel.fit(
            f"[bold cyan]API Security Scan[/bold cyan]\n"
            f"Target: {self.config.base_url}\n"
            f"Endpoints: {len(self.config.endpoints)} | Operations: {len(self.operations)}",
            border_style="cyan"
        ))
        
        if self.operations:
            visited = set()
            for op in self.operations:
                key = (op.get("method"), op.get("url"))
                if key in visited:
                    continue
                visited.add(key)
                findings = await self.scan_operation(op)
                self.report.findings.extend(findings)
                await asyncio.sleep(1 / self.config.rate_limit)
        else:
            for endpoint in self.config.endpoints:
                findings = await self.scan_endpoint(endpoint)
                self.report.findings.extend(findings)
                await asyncio.sleep(1 / self.config.rate_limit)  # Rate limiting
        
        self.report.scan_end = datetime.now()
        return self.report
    
    def display_report(self):
        """Display scan results in formatted table"""
        console.print("\n")
        console.print(Panel.fit(
            f"[bold green]Scan Complete[/bold green]\n"
            f"Duration: {(self.report.scan_end - self.report.scan_start).seconds}s\n"
            f"Endpoints Tested: {self.report.endpoints_tested}\n"
            f"Findings: {len(self.report.findings)}",
            border_style="green"
        ))
        
        if not self.report.findings:
            console.print("[green]✓ No vulnerabilities detected![/green]")
            return
        
        # Group by severity
        severity_counts = {}
        for finding in self.report.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        # Display summary
        table = Table(title="Vulnerability Summary", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", justify="right", style="yellow")
        
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = {
                    SeverityLevel.CRITICAL: "red",
                    SeverityLevel.HIGH: "orange1",
                    SeverityLevel.MEDIUM: "yellow",
                    SeverityLevel.LOW: "blue"
                }[severity]
                table.add_row(f"[{color}]{severity.value}[/{color}]", str(count))
        
        console.print(table)
        
        # Detailed findings
        console.print("\n[bold]Detailed Findings:[/bold]\n")
        for i, finding in enumerate(self.report.findings, 1):
            color = {
                SeverityLevel.CRITICAL: "red",
                SeverityLevel.HIGH: "orange1",
                SeverityLevel.MEDIUM: "yellow",
                SeverityLevel.LOW: "blue"
            }[finding.severity]
            
            console.print(f"[{color}]#{i} [{finding.severity.value}] {finding.vuln_type.value}[/{color}]")
            console.print(f"   Endpoint: {finding.endpoint}")
            console.print(f"   Description: {finding.description}")
            console.print(f"   Remediation: {finding.remediation}\n")
    
    def save_report(self, filename: str = "scan_report.json"):
        """Save report to JSON file"""
        report_dict = self.report.model_dump(mode='json')
        
        with open(filename, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        console.print(f"[green]Report saved to {filename}[/green]")


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

async def main():
    """Example usage of the API pen testing tool"""
    
    # IMPORTANT: Replace with your target (with authorization!)
    config = TargetConfig(
        base_url="http://localhost:9001",
        # Provide an OpenAPI spec to auto-discover endpoints and defaults.
        openapi_path=str(Path(__file__).with_name("openapi (1).json")),
        # Leave endpoints empty to let the spec populate GET endpoints automatically.
        endpoints=[],
        auth=AuthConfig(
            auth_type="bearer",
            token="TESTTOKEN123"
        ),
        rate_limit=5,  # Requests per second
        timeout=30
    )
    
    # Run the scan
    async with APIPenTester(config) as scanner:
        report = await scanner.run_scan()
        scanner.display_report()
        scanner.save_report("api_security_scan.json")


if __name__ == "__main__":
    console.print("[bold red]⚠️  LEGAL WARNING ⚠️[/bold red]")
    console.print("[yellow]This tool is for AUTHORIZED testing only![/yellow]")
    console.print("[yellow]Always obtain written permission before scanning any API.[/yellow]\n")
    
    # Uncomment to run (after adding proper authorization)
    asyncio.run(main())
    
    console.print("[cyan]Tool loaded. Configure your target and run main() to start scanning.[/cyan]")