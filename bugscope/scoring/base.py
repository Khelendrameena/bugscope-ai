"""Scorer interface."""
from abc import ABC, abstractmethod

from ..models import Endpoint, ScoredEndpoint

# Vulnerability classes Jev scores
VULN_CLASSES = ["idor", "xss", "sqli", "auth_bypass", "ssrf", "info_disclosure"]


class BaseScorer(ABC):
    @abstractmethod
    async def score(self, endpoints: list[Endpoint]) -> list[ScoredEndpoint]:
        ...
