"""Core data models for BugScope AI."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Endpoint:
    """A discovered API/web endpoint."""
    url: str
    method: str = "GET"
    params: list = field(default_factory=list)
    source: str = ""  # where it was found: "crawl", "js", "form", "robots", "sitemap"
    requires_auth: bool = False
    content_type: str = ""
    js_context: str = ""  # surrounding code snippet if found in JS

    def to_state(self) -> dict:
        """Convert to Jev 'state' dict."""
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "requires_auth": self.requires_auth,
            "source": self.source,
            "js_context": self.js_context[:500],
        }


@dataclass
class ScoredEndpoint:
    """An endpoint with Jev probability scores."""
    endpoint: Endpoint
    scores: dict = field(default_factory=dict)  # vuln_class -> probability
    top_vuln: str = ""
    top_probability: float = 0.0

    @property
    def url(self) -> str:
        return self.endpoint.url
