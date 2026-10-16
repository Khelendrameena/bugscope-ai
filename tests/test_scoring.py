"""Tests for BugScope AI."""
import asyncio

from bugscope.models import Endpoint
from bugscope.scoring.heuristic import HeuristicScorer


def test_idor_detection():
    ep = Endpoint(
        url="https://target.com/api/users/123", method="GET",
        params=["id"], source="js",
    )
    r = asyncio.run(HeuristicScorer().score([ep]))
    assert r[0].top_vuln == "idor"
    assert r[0].top_probability >= 0.5


def test_ssrf_detection():
    ep = Endpoint(
        url="https://target.com/api/fetch", method="POST",
        params=["url", "callback"], source="form",
    )
    r = asyncio.run(HeuristicScorer().score([ep]))
    assert r[0].top_vuln == "ssrf"


def test_xss_detection():
    ep = Endpoint(
        url="https://target.com/search?q=test", method="GET",
        params=["q"], source="crawl",
    )
    r = asyncio.run(HeuristicScorer().score([ep]))
    assert r[0].scores["xss"] > 0.3


def test_ranking():
    eps = [
        Endpoint(url="https://t.com/", source="crawl"),
        Endpoint(url="https://t.com/api/admin/users/1", method="DELETE",
                 params=["id"], source="js"),
    ]
    r = asyncio.run(HeuristicScorer().score(eps))
    assert r[0].url == "https://t.com/api/admin/users/1"


def test_endpoint_to_state():
    ep = Endpoint(url="https://t.com/api/x", method="POST", params=["a"])
    s = ep.to_state()
    assert s["url"] == "https://t.com/api/x"
    assert s["method"] == "POST"
