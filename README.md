# API Vulnerability Scanner v1.0

A lightweight automated security testing tool for REST APIs using httpx and pydantic, with an optional endpoint discovery spider.

## Important Legal Notice

Use this tool only against systems you have explicit, written permission to test. Unauthorized testing may violate laws and regulations. Respect `robots.txt` during crawling unless you have permission to override it.

## Requirements

Install the required packages in your Python environment:

```
pip install httpx==0.28.1 pydantic==2.12.3 pyjwt==2.10.1 rich==13.9.4 beautifulsoup4==4.12.3 PyYAML==6.0.2
```

## Files

- `main.py` — Scanner engine and example usage to run security tests against a set of endpoints.
- `spider.py` — Endpoint discovery spider. Crawls a base URL (and `sitemap.xml`), optionally parses OpenAPI docs (local/remote), and outputs discovered paths.
- `openapi3.yml` — Example OpenAPI v3 spec (VAmPI) that the spider can parse locally to seed endpoints.

## Discover endpoints with the spider

You can run the spider to enumerate potential endpoints (paths) for a target. It:

- Seeds from `sitemap.xml` when present
- Crawls HTML pages within the same origin (bounded by `max_depth`/`max_pages`)
- Attempts to detect OpenAPI docs from common URLs (`/openapi.json`, `/swagger.json`, `/v3/api-docs`)
- Optionally parses a local OpenAPI file (like `openapi3.yml`)
- Filters out static assets via include/exclude regex patterns

Example (programmatic):

```python
import asyncio
from spider import discover_endpoints, save_endpoints

async def run():
    endpoints = await discover_endpoints(
        base_url="http://localhost:5002",
        max_depth=2,
        max_pages=200,
        include_sitemap=True,
        local_openapi_file="openapi3.yml",
        include_patterns=[r"/api", r"/v1", r"/users", r"/books", r"/me"],
        exclude_patterns=[r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?)$", r"/static/"],
    )
    save_endpoints(endpoints, "discovered_endpoints.json")

asyncio.run(run())
```

## Built-in tests (current)

The scanner includes checks for:

- Authentication bypass / broken auth (unauthenticated access)
- JWT issues (header algorithm inspection, long-exp tokens, and optional unsigned token probe)
- SQL/NoSQL injection heuristics
- IDOR (sequential ID probing)
- CORS misconfigurations (wildcard origin, origin reflection, and credentials+wildcard)
- Sensitive data exposure (keyword-based)
- Rate limiting (concurrent request probe with 429/Retry-After/X-RateLimit detection; method-aware)
- Reflected XSS (simple reflection heuristic on a query param)

You can tune the target and which endpoints to exercise; more granular per-test toggles are planned.

## OpenAPI method coverage

If you provide an OpenAPI 3.x spec via `openapi_path`, the scanner now extracts operations across methods (GET/POST/PUT/PATCH/DELETE) and runs method-aware tests. Currently:

- GET operations: full suite as before (auth bypass, JWT analysis, SQL/NoSQL heuristics, IDOR, CORS, sensitive data exposure, reflected XSS, rate limiting)
- POST/PUT/PATCH operations: auth bypass, JWT analysis, CORS, NoSQL body injection heuristic, and rate limiting

This is an incremental step; deeper schema-driven fuzzing is planned.

### Minimal request body generation (new)

For POST/PUT/PATCH operations with `application/json` request bodies, the scanner now attempts to generate a minimal valid JSON payload using OpenAPI examples/defaults or simple type-based synthesis (strings, numbers, booleans, arrays, and objects with required fields). This enables baseline requests and basic NoSQL-injection mutation testing against body fields.

## Use the spider in the scanner

In `main.py`, set `use_spider = True` inside `main()` to auto-discover endpoints before scanning. If `openapi3.yml` exists, it will be used to seed endpoints.

Discovered endpoints (paths) are converted to absolute URLs using `base_url` and saved to `discovered_endpoints.json`.

## Run a scan

Edit `config = TargetConfig(...)` in `main.py` to point to your authorized target and endpoints. Then run:

```
python main.py
```

The scanner prints results to the console and writes `api_security_scan.json`.

### Use an OpenAPI spec to auto-populate endpoints

You can point the scanner directly at a local OpenAPI 3.x spec (YAML or JSON) and it will:

- Resolve the first server URL from `servers` (with variable defaults)
- Extract all `GET` operation paths and build absolute endpoint URLs
- Infer a basic `AuthConfig` (type and header name) from `components.securitySchemes` (no credentials)

Example snippet in `main.py`:

```python
config = TargetConfig(
    base_url="http://localhost:9001",  # used as fallback if spec servers are missing
    openapi_path="openapi3.yml",       # local path to OpenAPI spec
    endpoints=[],                        # leave empty to auto-populate GET endpoints from the spec
)
```

Note: For YAML specs, install PyYAML first:

```
pip install pyyaml==6.0.2
```

## Notes

- The spider focuses on discovering paths. It can return many non-API pages; use include/exclude patterns to narrow down to API-like paths.
- For APIs that don't link endpoints in HTML, OpenAPI parsing (local or remote) is the most reliable discovery method.
- Increase `max_pages`/`max_depth` cautiously; crawling large sites can be slow and noisy.
