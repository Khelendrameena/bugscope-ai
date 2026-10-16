"""Extractor - robots.txt, sitemap.xml, and misc recon."""
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import httpx

from ..models import Endpoint


class Extractor:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc

    async def extract(self) -> list[Endpoint]:
        endpoints = []
        async with httpx.AsyncClient(trust_env=False, 
            timeout=15, follow_redirects=True,
            headers={"User-Agent": "BugScopeAI/1.0 (bug bounty recon)"},
        ) as client:
            # robots.txt
            try:
                resp = await client.get(urljoin(self.base_url, "/robots.txt"))
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("disallow:", "allow:")):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                endpoints.append(Endpoint(
                                    url=urljoin(self.base_url, path),
                                    method="GET", source="robots",
                                ))
            except Exception:
                pass
            # sitemap.xml
            for sm in ["/sitemap.xml", "/sitemap_index.xml"]:
                try:
                    resp = await client.get(urljoin(self.base_url, sm))
                    if resp.status_code != 200:
                        continue
                    root = ElementTree.fromstring(resp.text)
                    for elem in root.iter():
                        if elem.tag.endswith("loc") and elem.text:
                            url = elem.text.strip()
                            if urlparse(url).netloc == self.domain:
                                endpoints.append(Endpoint(
                                    url=url, method="GET", source="sitemap",
                                ))
                except Exception:
                    pass
        return endpoints
