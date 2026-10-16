"""CLI for BugScope AI."""
import argparse
import asyncio
import json
import os
import sys
import time

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

from .models import ScoredEndpoint
from .recon.crawler import Crawler
from .recon.extractor import Extractor
from .recon.js_parser import JSParser
from .recon.subdomains import SubdomainEnumerator
from .recon.files import FileScanner
from .scoring.heuristic import HeuristicScorer


async def run_scan(target: str, scorer_name: str, max_pages: int) -> list[ScoredEndpoint]:
    start = time.time()
    print(f"[+] Recon on {target} ...", file=sys.stderr)
    crawler = Crawler(target, max_pages=max_pages)
    crawled = await crawler.crawl()
    print(f"    [{time.time()-start:.0f}s] Crawled {len(crawled)} pages", file=sys.stderr)
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



async def run_full_scope(
    target: str, scorer_name: str, max_pages: int
) -> tuple[list, list]:
    """Full scope scan: all subdomains, routes, files, code."""
    from urllib.parse import urlparse
    domain = urlparse(target).netloc.replace("www.", "")
    print(f"[+] Enumerating subdomains for {domain} ...", file=sys.stderr)
    enumerator = SubdomainEnumerator(domain)
    subdomains = await enumerator.enumerate()
    print(f"[+] Found {len(subdomains)} subdomains", file=sys.stderr)
    for sd in subdomains[:20]:
        print(f"    - {sd}", file=sys.stderr)

    # DNS pre-filter: only scan subdomains that actually resolve (kills dead ones fast)
    print(f"[+] DNS filtering {len(subdomains)} subdomains ...", file=sys.stderr)
    import socket
    async def _resolves(host: str) -> bool:
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyname, host
            )
            return True
        except Exception:
            return False
    resolved = []
    # Check in batches to avoid overwhelming DNS
    for i in range(0, len(subdomains), 50):
        batch = subdomains[i:i+50]
        results = await asyncio.gather(*[_resolves(sd) for sd in batch])
        resolved.extend([sd for sd, ok in zip(batch, results) if ok])
        if HAS_TQDM:
            print(f"    [{i+len(batch)}/{len(subdomains)}] {len(resolved)} alive",
                  file=sys.stderr, end="\r")
    # Cap at 50 to keep scan time reasonable
    live = resolved[:50]
    print(f"\n[+] {len(live)} live subdomains (from {len(subdomains)} total)",
          file=sys.stderr)

    # Pick scorer once
    if scorer_name == "jev":
        from .scoring.jev import JevScorer
        scorer = JevScorer()
    else:
        scorer = HeuristicScorer()

    all_results = []
    all_secrets = []
    start = time.time()

    async def _scan_one(sd: str, sem: asyncio.Semaphore):
        async with sem:
            sd_url = f"https://{sd}"
            try:
                crawler = Crawler(sd_url, max_pages=max_pages // 3)
                crawled = await crawler.crawl()
                extractor = Extractor(sd_url)
                extra = await extractor.extract()
                js_parser = JSParser(sd_url)
                js_eps = await js_parser.extract([e.url for e in crawled])
                fs = FileScanner(sd_url)
                sensitive = await fs.check_sensitive_files()
                sub_eps = crawled + extra + js_eps + sensitive
                scored = await scorer.score(sub_eps)
                return scored, len(sub_eps), None
            except Exception as e:
                return [], 0, str(e)

    # Parallel: 8 subdomains at once
    sem = asyncio.Semaphore(8)
    pbar = tqdm(total=len(live), desc="Scanning", unit="domain") if HAS_TQDM else None
    async def _wrapped(sd):
        r = await _scan_one(sd, sem)
        if pbar:
            elapsed = time.time() - start
            pbar.set_postfix_str(f"{len(all_results)} eps, {elapsed:.0f}s")
            pbar.update(1)
        else:
            print(f"    [{sd}] {r[1]} endpoints", file=sys.stderr)
        return r
    scan_results = await asyncio.gather(*[_wrapped(sd) for sd in live])
    if pbar:
        pbar.close()
    for scored, _, _ in scan_results:
        all_results.extend(scored)

    # Global dedupe and sort
    seen, unique = set(), []
    for r in sorted(all_results, key=lambda x: x.top_probability, reverse=True):
        key = (r.url, r.endpoint.method)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique, all_secrets


def cmd_full_scope(args):
    results, secrets = asyncio.run(
        run_full_scope(args.target, args.scorer, args.max_pages)
    )
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
            json.dump({"endpoints": output, "secrets": secrets}, f, indent=2)
        print(f"\n[+] Report saved to {args.output}", file=sys.stderr)
    else:
        print(json.dumps({"endpoints": output, "secrets": secrets}, indent=2))
    print("\n=== TOP 20 BUG TARGETS (ALL SCOPES) ===", file=sys.stderr)
    for r in results[:20]:
        print(
            f"  {r.top_probability:.0%} {r.top_vuln:15s} {r.endpoint.method} {r.url}",
            file=sys.stderr,
        )

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
    f = sub.add_parser("full-scope", help="Scan all subdomains, routes, files")
    f.add_argument("target", help="Target domain (must be in scope / authorized)")
    f.add_argument("--scorer", choices=["hev", "jev"], default="hev")
    f.add_argument("--max-pages", type=int, default=30)
    f.add_argument("--output", "-o", help="Save JSON report")
    args = p.parse_args()
    # Normalize scorer name
    args.scorer = "jev" if args.scorer == "jev" else "heuristic"
    if args.cmd == "scan":
        cmd_scan(args)
    elif args.cmd == "full-scope":
        cmd_full_scope(args)


if __name__ == "__main__":
    main()
