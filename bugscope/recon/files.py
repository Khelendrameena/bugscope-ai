"""File/code scanner - sensitive files, secrets in JS, source maps."""
import re
from urllib.parse import urljoin

import httpx

from ..models import Endpoint

# Sensitive files to check
SENSITIVE_FILES = [
    "/.git/HEAD", "/.env", "/.env.backup", "/backup.zip", "/backup.tar.gz",
    "/wp-config.php.bak", "/config.php.bak", "/.DS_Store", "/server-status",
    "/.well-known/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/phpinfo.php", "/info.php", "/.svn/entries", "/.hg/requires",
    "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/playground", "/console",
]

# Secret patterns in JS/code
SECRET_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Token"),
    (re.compile(r'xox[baprs]-[a-zA-Z0-9-]+'), "Slack Token"),
    (re.compile(r'sk_live_[a-zA-Z0-9]+'), "Stripe Live Key"),
    (re.compile(r'AIza[0-9A-Za-z_-]{35}'), "Google API Key"),
    (re.compile(r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']'), "API Key"),
    (re.compile(r'(?i)secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']'), "Secret"),
]


class FileScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def check_sensitive_files(self) -> list[Endpoint]:
        """Check for exposed sensitive files."""
        found = []
        async with httpx.AsyncClient(
            trust_env=False, timeout=10, follow_redirects=False
        ) as client:
            for path in SENSITIVE_FILES:
                url = urljoin(self.base_url, path)
                try:
                    resp = await client.get(url)
                    # 200 with non-trivial content = likely exposed
                    if resp.status_code == 200 and len(resp.content) > 50:
                        found.append(Endpoint(
                            url=url, method="GET", source="sensitive_file",
                            js_context=f"Exposed sensitive file ({len(resp.content)} bytes)",
                        ))
                except Exception:
                    pass
        return found

    def extract_secrets(self, js_text: str, js_url: str) -> list[dict]:
        """Find hardcoded secrets in JS code."""
        secrets = []
        for pattern, name in SECRET_PATTERNS:
            for m in pattern.finditer(js_text):
                # Redact the actual secret, keep prefix
                val = m.group(0)
                redacted = val[:8] + "***REDACTED***"
                secrets.append({
                    "type": name, "file": js_url,
                    "preview": redacted,
                })
        return secrets

    async def check_source_maps(self, js_urls: list[str]) -> list[Endpoint]:
        """Check for exposed .js.map source maps (leak original source)."""
        found = []
        async with httpx.AsyncClient(trust_env=False, timeout=10) as client:
            for js_url in js_urls[:20]:
                map_url = js_url + ".map"
                try:
                    resp = await client.get(map_url)
                    if resp.status_code == 200 and "sources" in resp.text[:500]:
                        found.append(Endpoint(
                            url=map_url, method="GET",
                            source="source_map",
                            js_context="Exposed source map - original source code visible",
                        ))
                except Exception:
                    pass
        return found
