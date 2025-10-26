# API Vulnerability Scanner (FastAPI backend)

Run API security checks via a simple REST interface powered by FastAPI. The core scanner supports auth checks, SQL/NoSQL injection heuristics, IDOR, CORS misconfigurations, sensitive data exposure, reflected XSS, and rate limiting probes. OpenAPI 3.x specs can be used to auto-discover operations and synthesize minimal request bodies for write methods.

## Legal Notice

Use this tool only against systems you have explicit, written permission to test. Unauthorized testing may violate laws and regulations.

## Requirements

Install Python packages:

```
pip install -r requirements.txt
```

## Run with Docker Compose

Quick start using Docker (recommended):

```powershell
docker compose up --build -d
```

Defaults:
- App: http://localhost:8000
- Volume: named volume `scanner_data` mounted at `/data` in the container
- Auth token: `API_AUTH_TOKEN=changeme` (change this in `docker-compose.yml` before exposing externally)
 - CORS: by default allows `http://localhost:3000`. Configure with `CORS_ORIGINS` (comma-separated)

To view logs:

```powershell
docker compose logs -f
```

To stop:

```powershell
docker compose down
```

## Run the server (local Python)

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

### CORS configuration

If you're calling the API from a browser-based frontend, set allowed origins with the `CORS_ORIGINS` environment variable (comma-separated list). Defaults to `http://localhost:3000`.

Examples:

Docker Compose (`docker-compose.yml`):

```yaml
environment:
    - CORS_ORIGINS=http://localhost:3000
```

PowerShell (local run):

```powershell
$env:CORS_ORIGINS = "http://localhost:3000"
python .\main.py
```

To allow all origins (not recommended for production):

```powershell
$env:CORS_ORIGINS = "*"; docker compose up --build -d
```

## API endpoints

- GET `/health` – server health check
- POST `/api/v1/scan/endpoint` – scan one or more endpoints with selected tests
- POST `/api/v1/scan/full` – run a complete scan using OpenAPI and/or provided endpoints
- POST `/api/v1/spec/upload` – upload an OpenAPI spec (JSON/YAML) scoped to a session
- GET `/api/v1/spec/endpoints` – return only a list of endpoints with HTTP method from a stored spec (scoped by session)
- POST `/api/v1/auth/check` – verify target API authentication with provided credentials
- POST `/api/v1/sessions` – create a new session; returns `session_id`
- DELETE `/api/v1/sessions/{session_id}` – delete a session and all its stored specs

### Sessions and storage isolation

Uploads and lookups are now scoped by a `session_id`. A session corresponds to a directory under the mounted volume (default: `/data/specs/{session_id}`) and is garbage-collected after one hour of inactivity.

Environment variable:

- `SESSION_TIMEOUT_SECONDS` – inactivity threshold for session GC (default: 3600)

Workflow:

1) Create a session:

```powershell
$token = "your-secret-admin-token"
curl -X POST "http://localhost:8000/api/v1/sessions" `
    -H "Authorization: Bearer $token"
```

Response:

```json
{ "session_id": "<uuid>", "dir": "/data/specs/<uuid>" }
```

2) Upload a spec to that session:

```powershell
curl -X POST "http://localhost:8000/api/v1/spec/upload" `
    -H "Authorization: Bearer $token" `
    -F "session_id=<uuid>" -F "file=@openapi.json"
```

3) Use `session_id` in scan requests (optional if you pass explicit `openapi_path`):

```json
{
    "base_url": "http://localhost:9001",
    "endpoint": "/users",
    "method": "GET",
    "selected_tests": ["BROKEN_AUTH", "IDOR"],
    "session_id": "<uuid>",
    "openapi_path": null,
    "auth": null,
    "rate_limit": 10,
    "timeout": 30
}
```

If `openapi_path` isn’t provided, the server will use the latest uploaded spec within that session.

4) Optionally, list minimal endpoints from the session’s latest (or specific) spec:

```powershell
curl -H "Authorization: Bearer $token" "http://localhost:8000/api/v1/spec/endpoints?session_id=<uuid>"
```

5) Delete the session (also removes stored files):

```powershell
curl -X DELETE "http://localhost:8000/api/v1/sessions/<uuid>" -H "Authorization: Bearer $token"
```

### POST /api/v1/scan/endpoint

Body example (single endpoint, backward compatible):

```json
{
    "base_url": "http://localhost:9001",
    "endpoint": "/users",
    "method": "GET",
    "selected_tests": ["BROKEN_AUTH", "JWT_VULN", "SQL_INJECTION", "NOSQL_INJECTION", "IDOR", "CORS", "INFO_DISCLOSURE", "XSS", "RATE_LIMIT"],
    "openapi_path": "openapi (1).json",
    "session_id": "<uuid>",
    "auth": { "auth_type": "bearer", "token": "TARGET_API_TOKEN", "header_name": "Authorization" },
    "rate_limit": 10,
    "timeout": 30
}
```

The `endpoint` may be an absolute URL or a path that will be joined to `base_url`.

Multiple endpoints (new):

```json
{
    "base_url": "http://localhost:9001",
    "endpoints": [
        "/users",
        "/orders",
        "http://localhost:9001/admin/health"
    ],
    "method": "GET",
    "selected_tests": ["BROKEN_AUTH", "IDOR", "CORS", "RATE_LIMIT"],
    "openapi_path": null,
    "session_id": "<uuid>",
    "auth": null,
    "rate_limit": 10,
    "timeout": 30
}
```

Notes:
- Provide either `endpoint` or `endpoints`. If both are present, they are combined.
- The same `method` is used for all endpoints provided.

### POST /api/v1/scan/full

Body example (same shape as TargetConfig):

```json
{
    "base_url": "http://localhost:9001",
    "openapi_path": "openapi (1).json",
    "endpoints": [],
    "auth": { "auth_type": "bearer", "token": "TARGET_API_TOKEN" },
    "rate_limit": 5,
    "timeout": 30,
    "session_id": "<uuid>"
}
```

Returns a ScanReport JSON summarizing findings and counts.

### POST /api/v1/auth/check

Validate that provided credentials can authenticate against a target endpoint. Useful for wiring a UI "Test connection" button.

Body:

```json
{
    "base_url": "https://api.example.com",
    "endpoint": "/me",
    "method": "GET",
    "auth": {
        "auth_type": "bearer",      // one of: bearer | basic | apikey
        "token": "<TOKEN>",         // for bearer/apikey
        "username": null,            // for basic
        "password": null,            // for basic
        "header_name": "Authorization" // header for bearer/apikey (e.g., "X-API-Key")
    },
    "timeout": 20
}
```

Response:

```json
{
    "target_url": "https://api.example.com/me",
    "method": "GET",
    "unauth_status": 401,
    "auth_status": 200,
    "requires_auth": true,
    "is_authenticated": true,
    "detected_auth_type": "bearer",
    "jwt_info": { "header": {"alg": "RS256"}, "claims": {"iss": "...", "exp": 1730000000} },
    "response_snippet": "{\n  \"id\": 123, ...",
    "error": null
}
```

Supported authentication methods:
- Bearer: `Authorization: Bearer <token>`
- Basic: HTTP Basic with username/password
- API Key (header): header name configurable via `auth.header_name` (e.g., `X-API-Key`)

### Upload an OpenAPI spec (scoped to a session)

Upload a spec file that will be saved to the mounted volume (`/data/specs`) and used as default for scans if none is provided explicitly:

PowerShell example:

```powershell
$token = "your-secret-admin-token"
$file = "C:\\path\\to\\openapi.json"
Invoke-WebRequest -Uri "http://localhost:8000/api/v1/spec/upload" -Method Post -Headers @{ Authorization = "Bearer $token" } -Form @{ session_id = "<uuid>"; file = Get-Item $file }
```

Curl alternative:

```powershell
curl -X POST "http://localhost:8000/api/v1/spec/upload" ^
    -H "Authorization: Bearer your-secret-admin-token" ^
    -F "session_id=<uuid>" ^
    -F "file=@openapi.json"
```

Response includes the saved path and a quick summary (server URL, counts).

### Get extracted endpoints (minimal)

Returns only the list of endpoints with their HTTP method from the latest uploaded spec (or a specific file via `?file=`). The response is a flat JSON array like:

```json
[
    { "method": "GET", "endpoint": "/users" },
    { "method": "POST", "endpoint": "/users" },
    { "method": "GET", "endpoint": "https://api.example.com/health" }
]
```

```powershell
curl -H "Authorization: Bearer your-secret-admin-token" "http://localhost:8000/api/v1/spec/endpoints?session_id=<uuid>"
```

Optional filters:
- `file` – the uploaded filename to parse (e.g., `openapi.json`)
- `methods` – one or more HTTP methods (e.g., `?methods=GET&methods=POST`)

## Project layout

- `main.py` – FastAPI app exposing scan endpoints
- `docker-compose.yml` / `Dockerfile` – containerized deployment; persists specs under named volume
- `scanner_core.py` – core scanning engine and models (reusable)
- `openapi3.yml` / `openapi (1).json` – optional sample specs for testing
- `requirements.txt` – dependencies

## Legacy

`main_OLD.py` contains an earlier CLI example and can still be run directly if desired.
