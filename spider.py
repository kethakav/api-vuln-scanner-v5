"""
Endpoint discovery spider for APIs

Features:
- Crawl a target site (respecting robots.txt) to discover unique paths
- Seed from sitemap.xml when available
- Attempt to detect and parse OpenAPI/Swagger docs from common URLs
- Optionally parse a local OpenAPI file (YAML/JSON) to emit endpoints

Requirements (install if missing):
    pip install httpx==0.28.1 beautifulsoup4==4.12.3 PyYAML==6.0.2 rich==13.9.4

LEGAL: Only crawl targets you are authorized to test. Respect robots.txt unless you have explicit permission to ignore it.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse
import xml.etree.ElementTree as ET
import urllib.robotparser as robotparser

import httpx
from bs4 import BeautifulSoup
import yaml


def _normalize_url(url: str) -> str:
    """Normalize a URL by removing fragments and resolving redundant parts."""
    parts = urlparse(url)
    # Drop fragment and query for endpoint identity; endpoints are path-based
    normalized = urlunparse((parts.scheme, parts.netloc, parts.path, "", "", ""))
    # Remove trailing slash except for root
    if normalized.endswith("/") and normalized.count("/") > 2:
        normalized = normalized.rstrip('/')
    return normalized


def _to_path(url: str) -> str:
    """Return a normalized path component (starting with '/') for an absolute URL."""
    p = urlparse(url)
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip('/')
    return path or "/"


@dataclass
class SpiderOptions:
    base_url: str
    max_depth: int = 3
    max_pages: int = 300
    rate_limit_rps: float = 5.0
    timeout: float = 20.0
    respect_robots: bool = True
    include_sitemap: bool = True
    openapi_paths: List[str] = field(default_factory=lambda: [
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/swagger.json",
        "/v3/api-docs",
    ])
    include_patterns: Optional[List[str]] = None  # regexes applied to path
    exclude_patterns: Optional[List[str]] = None  # regexes applied to path
    local_openapi_file: Optional[str] = None  # optional path to local OpenAPI file to parse

    def same_origin(self, url: str) -> bool:
        bp = urlparse(self.base_url)
        up = urlparse(url)
        return (bp.scheme, bp.netloc) == (up.scheme, up.netloc)


class EndpointSpider:
    def __init__(self, options: SpiderOptions):
        self.opt = options
        self._visited: Set[str] = set()  # normalized absolute URLs
        self._endpoints: Set[str] = set()  # normalized paths
        self._robots: Optional[robotparser.RobotFileParser] = None

    async def _init_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self.opt.timeout, follow_redirects=True, headers={
            "User-Agent": "api-vuln-spider/1.0"
        })

    async def _load_robots(self, client: httpx.AsyncClient) -> None:
        if not self.opt.respect_robots:
            return
        base = _normalize_url(self.opt.base_url)
        robots_url = urljoin(base + '/', 'robots.txt')
        self._robots = robotparser.RobotFileParser()
        try:
            resp = await client.get(robots_url)
            if resp.status_code == 200 and resp.text:
                self._robots.parse(resp.text.splitlines())
            else:
                self._robots = None
        except Exception:
            self._robots = None

    def _allowed_by_robots(self, url: str) -> bool:
        if not self.opt.respect_robots or not self._robots:
            return True
        try:
            return self._robots.can_fetch("api-vuln-spider/1.0", url)
        except Exception:
            return True

    def _passes_filters(self, path: str) -> bool:
        if self.opt.include_patterns:
            if not any(re.search(p, path) for p in self.opt.include_patterns):
                return False
        if self.opt.exclude_patterns:
            if any(re.search(p, path) for p in self.opt.exclude_patterns):
                return False
        return True

    def _extract_links(self, base_url: str, html: str) -> List[str]:
        links: List[str] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return links

        # Anchor hrefs
        for tag in soup.find_all('a', href=True):
            links.append(urljoin(base_url, tag['href']))

        # Link/script common asset hints – sometimes APIs are referenced
        for tag in soup.find_all(['link', 'script'], src=True):
            links.append(urljoin(base_url, tag['src']))
        for tag in soup.find_all('link', href=True):
            links.append(urljoin(base_url, tag['href']))

        # Remove non-http(s)
        links = [u for u in links if urlparse(u).scheme in ("http", "https")]
        return links

    async def _discover_from_sitemap(self, client: httpx.AsyncClient) -> List[str]:
        results: List[str] = []
        base = _normalize_url(self.opt.base_url)
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            sm_url = urljoin(base + '/', path.lstrip('/'))
            try:
                resp = await client.get(sm_url)
                if resp.status_code != 200 or not resp.text:
                    continue
                try:
                    root = ET.fromstring(resp.text)
                except ET.ParseError:
                    continue
                for loc in root.findall('.//{*}loc'):
                    loc_text = loc.text or ""
                    if loc_text and urlparse(loc_text).scheme in ("http", "https"):
                        results.append(loc_text)
            except Exception:
                continue
        return results

    async def _discover_openapi_remote(self, client: httpx.AsyncClient) -> Set[str]:
        found: Set[str] = set()
        base = _normalize_url(self.opt.base_url)
        for path in self.opt.openapi_paths:
            url = urljoin(base + '/', path.lstrip('/'))
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                content_type = resp.headers.get("content-type", "")
                text = resp.text
                if "json" in content_type or text.strip().startswith('{'):
                    spec = json.loads(text)
                else:
                    spec = yaml.safe_load(text)
                if not spec:
                    continue
                if 'paths' in spec and isinstance(spec['paths'], dict):
                    for p in spec['paths'].keys():
                        if isinstance(p, str):
                            found.add(p if p.startswith('/') else '/' + p)
            except Exception:
                continue
        return found

    def _discover_openapi_local(self) -> Set[str]:
        if not self.opt.local_openapi_file:
            return set()
        try:
            with open(self.opt.local_openapi_file, 'r', encoding='utf-8') as f:
                text = f.read()
            # Try YAML first, then JSON
            try:
                spec = yaml.safe_load(text)
            except Exception:
                spec = json.loads(text)
            paths = set()
            if spec and isinstance(spec, dict) and 'paths' in spec:
                for p in spec['paths'].keys():
                    if isinstance(p, str):
                        paths.add(p if p.startswith('/') else '/' + p)
            return paths
        except Exception:
            return set()

    async def discover(self) -> List[str]:
        """Run discovery across OpenAPI hints, sitemap, and crawling. Returns unique paths."""
        client = await self._init_client()
        try:
            await self._load_robots(client)

            # Seed endpoints from OpenAPI (local and remote)
            openapi_paths: Set[str] = set()
            openapi_paths |= self._discover_openapi_local()
            openapi_paths |= await self._discover_openapi_remote(client)

            for p in openapi_paths:
                if self._passes_filters(p):
                    self._endpoints.add(p)

            # Build initial URL queue
            seed_urls: List[str] = []
            if self.opt.include_sitemap:
                seed_urls.extend(await self._discover_from_sitemap(client))
            seed_urls.append(_normalize_url(self.opt.base_url))
            seed_urls = [u for u in seed_urls if self.opt.same_origin(u)]

            queue: deque[Tuple[str, int]] = deque([(u, 0) for u in seed_urls])

            # Crawl BFS
            throttle = 1.0 / max(self.opt.rate_limit_rps, 0.1)
            pages_crawled = 0
            while queue and pages_crawled < self.opt.max_pages:
                url, depth = queue.popleft()
                if depth > self.opt.max_depth:
                    continue
                url_norm = _normalize_url(url)
                if url_norm in self._visited:
                    continue
                if not self._allowed_by_robots(url_norm):
                    self._visited.add(url_norm)
                    continue

                try:
                    resp = await client.get(url_norm)
                    self._visited.add(url_norm)
                    pages_crawled += 1
                    # Record endpoint path
                    path = _to_path(url_norm)
                    if self._passes_filters(path):
                        self._endpoints.add(path)

                    # Only parse HTML pages
                    ctype = resp.headers.get("content-type", "")
                    if "html" in ctype and resp.text:
                        links = self._extract_links(url_norm, resp.text)
                        for link in links:
                            if not self.opt.same_origin(link):
                                continue
                            ln = _normalize_url(link)
                            if ln not in self._visited:
                                queue.append((ln, depth + 1))
                except Exception:
                    # Ignore fetch errors and continue
                    pass
                finally:
                    await asyncio.sleep(throttle)

            # Return sorted unique paths
            result = sorted(self._endpoints)
            return result
        finally:
            await client.aclose()


async def discover_endpoints(
    base_url: str,
    *,
    max_depth: int = 3,
    max_pages: int = 300,
    rate_limit_rps: float = 5.0,
    timeout: float = 20.0,
    respect_robots: bool = True,
    include_sitemap: bool = True,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    local_openapi_file: Optional[str] = None,
) -> List[str]:
    """Convenience helper to run the spider and return discovered endpoints (paths)."""
    options = SpiderOptions(
        base_url=base_url,
        max_depth=max_depth,
        max_pages=max_pages,
        rate_limit_rps=rate_limit_rps,
        timeout=timeout,
        respect_robots=respect_robots,
        include_sitemap=include_sitemap,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        local_openapi_file=local_openapi_file,
    )
    spider = EndpointSpider(options)
    return await spider.discover()


def save_endpoints(endpoints: Iterable[str], filename: str) -> None:
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(sorted(set(endpoints)), f, indent=2)
