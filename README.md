# BugScope AI

AI-powered bug bounty reconnaissance. Automatically discovers every endpoint in a target's scope, then scores each one for bug probability using Jev (TypeSafe AI's decision model) — so you hunt where bugs are most likely, not blindly.

## How it works

1. **Recon**: Crawl the target, extract JS files, parse API endpoints, forms, robots.txt, sitemap.xml
2. **Score**: Each endpoint is sent to Jev with typed questions like "How likely is IDOR here?" — Jev returns calibrated probabilities in ~100ms
3. **Rank**: Endpoints sorted by bug probability. Hunt the top ones first.

## Quick start

```bash
pip install -r requirements.txt
python -m bugscope scan https://target.com --output report.json
```

With Jev API key (get one at typesafe.ai):
```bash
export JEV_API_KEY=your_key
python -m bugscope scan https://target.com --scorer jev
```

Without a key, uses the built-in heuristic scorer (no API needed).

## Dashboard

```bash
python -m bugscope dashboard report.json
# Open http://localhost:8080
```
