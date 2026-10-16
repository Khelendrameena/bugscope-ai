"""Jev scorer - uses TypeSafe AI's decision model for bug probability.

Jev takes endpoint 'state' + typed questions, returns calibrated
probabilities in ~100ms. No text generation, just decisions.
Get an API key at typesafe.ai (also available via Vercel AI Gateway).
"""
import asyncio
import os

import httpx

from ..models import Endpoint, ScoredEndpoint
from .base import VULN_CLASSES, BaseScorer

JEV_API_URL = os.environ.get(
    "JEV_API_URL", "https://api.typesafe.ai/v1/decide"
)

# Typed questions Jev answers for each endpoint
QUESTIONS = [
    {
        "id": "idor",
        "question": "How likely is this endpoint to have an IDOR/broken object-level authorization bug?",
        "type": "probability",
    },
    {
        "id": "xss",
        "question": "How likely is this endpoint to have a cross-site scripting (XSS) bug?",
        "type": "probability",
    },
    {
        "id": "sqli",
        "question": "How likely is this endpoint to have a SQL injection bug?",
        "type": "probability",
    },
    {
        "id": "auth_bypass",
        "question": "How likely is this endpoint to have an authentication bypass or missing auth check?",
        "type": "probability",
    },
    {
        "id": "ssrf",
        "question": "How likely is this endpoint to have a server-side request forgery (SSRF) bug?",
        "type": "probability",
    },
    {
        "id": "info_disclosure",
        "question": "How likely is this endpoint to leak sensitive information?",
        "type": "probability",
    },
]


class JevScorer(BaseScorer):
    def __init__(self, api_key: str = None, max_concurrent: int = 10):
        self.api_key = api_key or os.environ.get("JEV_API_KEY", "")
        if not self.api_key:
            raise ValueError("JEV_API_KEY not set")
        self.max_concurrent = max_concurrent

    async def _score_one(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        endpoint: Endpoint,
    ) -> ScoredEndpoint:
        async with sem:
            payload = {
                "state": endpoint.to_state(),
                "questions": QUESTIONS,
            }
            try:
                resp = await client.post(
                    JEV_API_URL, json=payload,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=10,
                )
                data = resp.json()
                scores = {
                    q["id"]: float(data.get("answers", {}).get(q["id"], 0))
                    for q in QUESTIONS
                }
            except Exception:
                scores = {v: 0.0 for v in VULN_CLASSES}
            top = max(scores.items(), key=lambda x: x[1])
            return ScoredEndpoint(
                endpoint=endpoint, scores=scores,
                top_vuln=top[0], top_probability=top[1],
            )

    async def score(self, endpoints: list[Endpoint]) -> list[ScoredEndpoint]:
        sem = asyncio.Semaphore(self.max_concurrent)
        async with httpx.AsyncClient(trust_env=False, ) as client:
            results = await asyncio.gather(*[
                self._score_one(client, sem, ep) for ep in endpoints
            ])
        return sorted(results, key=lambda r: r.top_probability, reverse=True)
