"""JS parser - extracts API endpoints from JavaScript files."""
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..models import Endpoint

# Patterns that often indicate API endpoints in JS
ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/[a-zA-Z0-9_\-/{}:.]+)["\']'),  # "/api/users"
    re.compile(r'fetch\(\s*["\']([^"\']+)["\']'),       # fetch("/api/...")
    re.compile(r'axios\.\w+\(\s*["\']([^"\']+)["\']'),  # axios.get("...")
    re.compile(r'url:\s*["\']([^"\']+)["\']'),          # url: "/api/..."
    re.compile(r'\$\.(?:get|post|ajax)\(\s*["\']([^"\']+)["\']'),
]

# Keywords suggesting interesting params
INTERESTING_PARAMS = re.compile(
    r'(id|user|account|token|key|password|email|admin|role|price|amount)',
    re.IGNORECASE,
)


class JSParser:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc

    async def extract(self, page_urls: list[str]) -> list[Endpoint]:
        endpoints = []
        js_urls = set()
        async with httpx.AsyncClient(trust_env=False, 
            timeout=15, follow_redirects=True,
            headers={"User-Agent": "BugScopeAI/1.0 (bug bounty recon)"},
        ) as client:
            # Find JS files from pages
            for page_url in page_urls[:20]:
                try:
                    resp = await client.get(page_url)
                except Exception:
                    continue
                if "text/html" not in resp.headers.get("content-type", ""):
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for script in soup.find_all("script", src=True):
                    full = urljoin(page_url, script["src"])
                    if urlparse(full).netloc == self.domain:
                        js_urls.add(full)
            # Parse each JS file
            for js_url in list(js_urls)[:30]:
                try:
                    resp = await client.get(js_url)
                except Exception:
                    continue
                if resp.status_code != 200:
                    continue
                text = resp.text
                for pattern in ENDPOINT_PATTERNS:
                    for m in pattern.finditer(text):
                        path = m.group(1)
                        if not path.startswith("/") or "." in path.split("/")[-1]:
                            continue  # skip file paths
                        full_url = urljoin(self.base_url, path)
                        # Grab surrounding context
                        start = max(0, m.start() - 200)
                        context = text[start:m.end() + 200]
                        # Detect HTTP method from context
                        method = "GET"
                        ctx_lower = context.lower()
                        if "method" in ctx_lower:
                            for mm in ["post", "put", "delete", "patch"]:
                                if mm in ctx_lower:
                                    method = mm.upper()
                                    break
                        # Extract params from context
                        params = list(set(INTERESTING_PARAMS.findall(context)))
                        endpoints.append(Endpoint(
                            url=full_url, method=method, params=params,
                            source="js", js_context=context[:500],
                        ))
        # Dedupe
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique
