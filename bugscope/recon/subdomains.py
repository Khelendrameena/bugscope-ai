"""Subdomain enumeration via CT logs + DNS brute force."""
import asyncio
import json
from urllib.parse import urlparse

import httpx

# Common subdomains to brute force
COMMON_SUBDOMAINS = [
    "www", "api", "app", "dev", "staging", "test", "admin", "portal",
    "dashboard", "auth", "login", "vpn", "mail", "ftp", "blog", "shop",
    "support", "help", "docs", "status", "cdn", "static", "assets",
    "graphql", "rest", "v1", "v2", "beta", "demo", "internal", "corp",
    "db", "cache", "queue", "worker", "jobs", "ci", "cd", "jenkins",
    "gitlab", "github", "jira", "confluence", "slack", "zoom",
    "mobile", "m", "secure", "sso", "oauth", "openid", "billing",
    "payments", "webhook", "hooks", "events", "logs", "metrics",
    "monitor", "grafana", "kibana", "elastic", "prometheus",
]


class SubdomainEnumerator:
    def __init__(self, domain: str):
        self.domain = domain

    async def via_ct_logs(self) -> set[str]:
        """Get subdomains from Certificate Transparency (crt.sh)."""
        subs = set()
        try:
            async with httpx.AsyncClient(
                trust_env=False, timeout=20
            ) as client:
                url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
                resp = await client.get(url)
                if resp.status_code == 200:
                    for entry in resp.json():
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            if n.endswith(self.domain) and "*" not in n:
                                subs.add(n)
        except Exception:
            pass
        return subs

    async def via_dns_bruteforce(
        self, wordlist: list[str] = None, max_concurrent: int = 20
    ) -> set[str]:
        """Brute force common subdomains via DNS."""
        import socket
        wordlist = wordlist or COMMON_SUBDOMAINS
        subs = set()
        sem = asyncio.Semaphore(max_concurrent)

        async def check(sub: str):
            async with sem:
                host = f"{sub}.{self.domain}"
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, socket.gethostbyname, host
                    )
                    subs.add(host)
                except Exception:
                    pass

        await asyncio.gather(*[check(s) for s in wordlist])
        return subs

    async def enumerate(self) -> list[str]:
        ct, brute = await asyncio.gather(
            self.via_ct_logs(),
            self.via_dns_bruteforce(),
        )
        all_subs = ct | brute
        # Always include the root domain and www
        all_subs.add(self.domain)
        return sorted(all_subs)
