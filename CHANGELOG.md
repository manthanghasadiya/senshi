# Changelog

All notable changes to Senshi are documented here.

## [0.2.0] — 2026-03-06

### ⚡ Performance Overhaul
- **Batch response analysis** — 1 LLM call per endpoint per scanner instead of 1 per payload (~6x fewer LLM calls)
- **Smart endpoint-to-scanner routing** — XSS only scans HTML endpoints, SSRF only URL params, IDOR only numeric IDs, etc.
- **Scan time reduction** — target 5-10 min vs 60+ min for a 7-endpoint app

### 🛡 Reliability
- **Progressive saving** — findings saved to disk as discovered via `ScanState`
- **Ctrl+C handler** — partial results preserved on interrupt
- **Robust JSON extraction** — handles markdown code blocks, trailing commas, comments, embedded JSON
- **Auto-output** — results always saved to timestamped JSON file
- **Finding deduplication** — same vuln at same endpoint = 1 finding

### 🆕 New Features
- **Browser-based recon** (`senshi recon --browser`) — Playwright headless browser captures XHR/fetch traffic
- **Scan summary dashboard** — Rich table with severity, confidence, duration, LLM call count
- **`--endpoints` flag** — use pre-discovered endpoints from `senshi recon`
- **`--browser` flag** — enable headless browser recon
- **`content_type` on endpoints** — enables smarter scanner routing

### 🏗 Architecture Changes
- Rewritten `BaseDastScanner` — new batch pipeline: generate → send all → analyze all → validate
- Scanners receive full endpoint list, filter internally via `filter_relevant_endpoints()`
- Engine instantiates scanners once with all endpoints (was once per endpoint)
- `ResponseAnalyzer.analyze_batch()` replaces per-payload `analyze()`
- `ScanState` in `reporters/models.py` for progressive save
- `BrowserRecon` in `dast/browser_recon.py` for headless browser recon

### 📦 Dependencies
- `playwright` added as optional dependency (`pip install senshi[browser]`)

---

## [0.1.0] — 2026-03-06

### Added
- **DAST scanning** — 7 scanner modules: XSS, SSRF, Injection (SQLi/CMDi/SSTI), IDOR, Auth Bypass, Deserialization, AI Product
- **SAST scanning** — 5 pattern scanners: Injection, Auth, Crypto, Config, AI Patterns
- **AI-powered analysis** — LLM payload generation, response analysis, false positive filtering, exploit chain building
- **Multi-provider LLM support** — DeepSeek, OpenAI, Groq, Ollama, Anthropic (all via OpenAI-compatible API)
- **Smart crawling** — endpoint discovery via HTML crawling, JavaScript analysis, robots.txt, form extraction
- **Technology detection** — fingerprint server, framework, and security headers
- **Multiple output formats** — JSON, Markdown, SARIF
- **Bounty report generation** — AI-generated reports for HackerOne, Bugcrowd, MSRC
- **CLI interface** — `senshi dast`, `senshi sast`, `senshi recon`, `senshi payloads`, `senshi report`, `senshi config`
- **Rate limiting** — configurable request throttling with burst support
- **Custom headers and auth** — Cookie, Bearer token, custom header support
- **Proxy support** — route traffic through Burp Suite or other proxies
