"""CLI for BugScope AI."""
import argparse
import asyncio
import json
import os
import sys

from .models import ScoredEndpoint
from .recon.crawler import Crawler
from .recon.extractor import Extractor
from .recon.js_parser import JSParser
from .scoring.heuristic import HeuristicScorer


async def run_scan(target: str, scorer_name: str, max_pages: int) -> list[ScoredEndpoint]:
    print(f"[+] Recon on {target} ...", file=sys.stderr)
    crawler = Crawler(target, max_pages=max_pages)
    crawled = await crawler.crawl()
    print(f"[+] Crawled {len(crawled)} pages/forms", file=sys.stderr)

    extractor = Extractor(target)
    extra = await extractor.extract()
    print(f"[+] robots.txt/sitemap: {len(extra)} endpoints", file=sys.stderr)

    js_parser = JSParser(target)
    js_eps = await js_parser.extract([e.url for e in crawled])
    print(f"[+] JS files: {len(js_eps)} API endpoints", file=sys.stderr)

    all_eps = crawled + extra + js_eps
    # Dedupe
    seen, unique = set(), []
    for ep in all_eps:
        key = (ep.url, ep.method)
        if key not in seen:
            seen.add(key)
            unique.append(ep)
    print(f"[+] Total unique endpoints: {len(unique)}", file=sys.stderr)

    # Score
    if scorer_name == "jev":
        from .scoring.jev import JevScorer
        scorer = JevScorer()
        print("[+] Scoring with Jev ...", file=sys.stderr)
    else:
        scorer = HeuristicScorer()
        print("[+] Scoring with heuristic engine ...", file=sys.stderr)
    return await scorer.score(unique)


def cmd_scan(args):
    results = asyncio.run(run_scan(args.target, args.scorer, args.max_pages))
    output = [
        {
            "url": r.url,
            "method": r.endpoint.method,
            "source": r.endpoint.source,
            "top_vuln": r.top_vuln,
            "top_probability": round(r.top_probability, 3),
            "scores": {k: round(v, 3) for k, v in r.scores.items()},
        }
        for r in results
    ]
    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"[+] Report saved to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(output, indent=2))
    # Top 10 summary
    print("\n=== TOP 10 BUG TARGETS ===", file=sys.stderr)
    for r in results[:10]:
        print(
            f"  {r.top_probability:.0%} {r.top_vuln:15s} {r.endpoint.method} {r.url}",
            file=sys.stderr,
        )


def main():
    p = argparse.ArgumentParser(prog="bugscope")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Scan a target")
    s.add_argument("target", help="Target URL (must be in scope / authorized)")
    s.add_argument("--scorer", choices=["hev", "jev"], default="hev",
                   help="hev=heuristic (default), jev=Jev API")
    s.add_argument("--max-pages", type=int, default=50)
    s.add_argument("--output", "-o", help="Save JSON report")
    args = p.parse_args()
    # Normalize scorer name
    if args.cmd == "scan":
        args.scorer = "jev" if args.scorer == "jev" else "heuristic"
        cmd_scan(args)


if __name__ == "__main__":
    main()
