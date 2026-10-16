"""Site crawler - discovers pages and links."""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..models import Endpoint


class Crawler:
    def __init__(self, base_url: str, max_pages: int = 50, max_depth: int = 3):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited = set()
        self.endpoints: list[Endpoint] = []

    def _is_in_scope(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

    async def crawl(self) -> list[Endpoint]:
        async with httpx.AsyncClient(trust_env=False, 
            timeout=15, follow_redirects=True,
            headers={"User-Agent": "BugScopeAI/1.0 (bug bounty recon)"},
        ) as client:
            queue = [(self.base_url, 0)]
            while queue and len(self.visited) < self.max_pages:
                url, depth = queue.pop(0)
                if url in self.visited or depth > self.max_depth:
                    continue
                self.visited.add(url)
                try:
                    resp = await client.get(url)
                except Exception:
                    continue
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "")
                self.endpoints.append(Endpoint(
                    url=url, method="GET", source="crawl",
                    content_type=ct,
                ))
                if "text/html" not in ct:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                # Links
                for a in soup.find_all("a", href=True):
                    full = urljoin(url, a["href"])
                    if self._is_in_scope(full) and full not in self.visited:
                        queue.append((full, depth + 1))
                # Forms -> potential endpoints
                for form in soup.find_all("form"):
                    action = urljoin(url, form.get("action", url))
                    method = (form.get("method") or "GET").upper()
                    params = [i.get("name") for i in form.find_all("input") if i.get("name")]
                    if self._is_in_scope(action):
                        self.endpoints.append(Endpoint(
                            url=action, method=method, params=params,
                            source="form",
                        ))
        return self.endpoints
