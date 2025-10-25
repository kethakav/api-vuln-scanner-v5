# API Vulnerability Scanner (FastAPI backend)

Run API security checks via a simple REST interface powered by FastAPI. The core scanner supports auth checks, SQL/NoSQL injection heuristics, IDOR, CORS misconfigurations, sensitive data exposure, reflected XSS, and rate limiting probes. OpenAPI 3.x specs can be used to auto-discover operations and synthesize minimal request bodies for write methods.

## Legal Notice

Use this tool only against systems you have explicit, written permission to test. Unauthorized testing may violate laws and regulations.

## Requirements

Install Python packages:

```
pip install -r requirements.txt
```

## Run the server

Windows PowerShell (recommended steps):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:API_AUTH_TOKEN = "your-secret-admin-token"  # required for API access
python .\main.py
```

Open Swagger UI: http://localhost:8000/docs

All protected endpoints require:

```
Authorization: Bearer <API_AUTH_TOKEN>
```

## API endpoints

- GET `/health` – server health check
- POST `/api/v1/scan/endpoint` – scan a single endpoint with selected tests
- POST `/api/v1/scan/full` – run a complete scan using OpenAPI and/or provided endpoints

### POST /api/v1/scan/endpoint

Body example:

```json
{
    "base_url": "http://localhost:9001",
    "endpoint": "/users",
    "method": "GET",
    "selected_tests": ["BROKEN_AUTH", "JWT_VULN", "SQL_INJECTION", "NOSQL_INJECTION", "IDOR", "CORS", "INFO_DISCLOSURE", "XSS", "RATE_LIMIT"],
    "openapi_path": "openapi (1).json",
    "auth": { "auth_type": "bearer", "token": "TARGET_API_TOKEN", "header_name": "Authorization" },
    "rate_limit": 10,
    "timeout": 30
}
```

The `endpoint` may be an absolute URL or a path that will be joined to `base_url`.

### POST /api/v1/scan/full

Body example (same shape as TargetConfig):

```json
{
    "base_url": "http://localhost:9001",
    "openapi_path": "openapi (1).json",
    "endpoints": [],
    "auth": { "auth_type": "bearer", "token": "TARGET_API_TOKEN" },
    "rate_limit": 5,
    "timeout": 30
}
```

Returns a ScanReport JSON summarizing findings and counts.

## Project layout

- `main.py` – FastAPI app exposing scan endpoints
- `scanner_core.py` – core scanning engine and models (reusable)
- `openapi3.yml` / `openapi (1).json` – optional sample specs for testing
- `requirements.txt` – dependencies

## Legacy

`main_OLD.py` contains an earlier CLI example and can still be run directly if desired.
