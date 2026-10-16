"""Heuristic scorer - local fallback when no Jev API key.

Uses bug-bounty heuristics to estimate bug probability.
Not as good as Jev, but works offline with zero setup.
"""
import re

from ..models import Endpoint, ScoredEndpoint
from .base import BaseScorer


class HeuristicScorer(BaseScorer):
    async def score(self, endpoints: list[Endpoint]) -> list[ScoredEndpoint]:
        results = [self._score_one(ep) for ep in endpoints]
        return sorted(results, key=lambda r: r.top_probability, reverse=True)

    def _score_one(self, ep: Endpoint) -> ScoredEndpoint:
        url = ep.url.lower()
        scores = {
            "idor": 0.1, "xss": 0.1, "sqli": 0.1,
            "auth_bypass": 0.1, "ssrf": 0.05, "info_disclosure": 0.1,
        }
        # IDOR signals: numeric IDs in path or params
        if re.search(r"/\d+(/|$)", url) or "id" in ep.params:
            scores["idor"] += 0.4
        if any(p in ep.params for p in ["user_id", "account_id", "order_id"]):
            scores["idor"] += 0.2
        # XSS signals: reflected params, search
        if any(k in url for k in ["search", "query", "q=", "keyword"]):
            scores["xss"] += 0.35
        if ep.method == "GET" and ep.params:
            scores["xss"] += 0.15
        # SQLi signals: id params, filter/sort
        if any(k in url for k in ["filter", "sort", "order", "where"]):
            scores["sqli"] += 0.3
        if "id" in ep.params:
            scores["sqli"] += 0.15
        # Auth bypass: admin paths, no auth
        if "admin" in url:
            scores["auth_bypass"] += 0.4
        if not ep.requires_auth and ep.method in ("POST", "PUT", "DELETE"):
            scores["auth_bypass"] += 0.25
        # SSRF: url/redirect params
        if any(k in ep.params for k in ["url", "redirect", "callback", "webhook"]):
            scores["ssrf"] += 0.5
        # Info disclosure: debug, config, .git paths (word boundaries to avoid "testing" matching "test")
        if re.search(r"[./_-](debug|config|\.git|backup|test)([./_-]|$)", url):
            scores["info_disclosure"] += 0.5
        if ep.source == "robots":
            scores["info_disclosure"] += 0.2
        # JS-discovered API endpoints are often less tested
        if ep.source == "js" and "/api/" in url:
            for k in scores:
                scores[k] += 0.1
        # Deprioritize static content pages (blog, news, marketing) - not bug targets
        if re.search(r"/(blog|news|clp|press|about|contact|careers|docs|help|faq)(/|$)", url):
            for k in scores:
                scores[k] *= 0.3
        # Boost API-like endpoints
        if "/api/" in url:
            for k in scores:
                scores[k] = min(scores[k] * 1.3, 0.95)
        # Clamp
        scores = {k: min(v, 0.95) for k, v in scores.items()}
        top = max(scores.items(), key=lambda x: x[1])
        return ScoredEndpoint(
            endpoint=ep, scores=scores,
            top_vuln=top[0], top_probability=top[1],
        )
