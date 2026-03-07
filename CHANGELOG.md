# Changelog

All notable changes to Senshi are documented here.

## [0.3.1] — 2026-03-07

### 🐛 Agent Loop Fixes
- **AgentModeScanner**: Bypassed strict DAST endpoint filtering during the autonomous agent loop to ensure LLM-selected endpoints are actually tested.
- **Robust Parameter Extraction**: URL query strings and known fallback parameters are inherently tested even if the reconnaissance crawler missed them.
- **Deterministic Fuzzer Fallback**: The deterministic pre-fuzzer is automatically executed as a fallback if the LLM's payload variations fail to find anything on an endpoint.
- **Improved Context Memory**: Aggressive filtering instructions explicitly prevent the agent from infinitely retesting failed payload combinations or previously confirmed findings.
- **Enhanced Vulnerability Detection**: Added detection patterns for SQLite errors and Command Injection root paths. Fixed XSS payload reflection detection logic.

---

## [0.3.0] — 2026-03-06

### 🤖 Autonomous Pentesting Agent
- **`senshi pentest` command** — fully autonomous Think → Act → Observe agent loop
- **LLM-driven action selection** — AI decides what to test next based on accumulated context
- **10 registered action handlers** — scan, fuzz, auth test, IDOR, SSRF, explore, escalate, browser, websocket, GraphQL
- **PentestContext** — persistent accumulator for all knowledge across iterations
- **Progressive save** — findings saved to disk in real-time, survives Ctrl+C
- **Rich dashboard** — scan summary with findings table, PoC indicators, chain count

### 🔐 Authentication & IDOR
- **Multi-account AuthManager** — supports cookie, bearer, and browser-based auth
- **Cross-account IDOR testing** — Account A vs Account B resource access
- **Auto-discovery of resource IDs** — extracts IDs from API responses

### 🌐 WebSocket Testing
- **WebSocketTester** — auth bypass (stripped/modified token), injection payloads, rate limit
- **WebSocketFuzzer** — LLM-generated WebSocket message payloads

### 🖥️ Browser Exploitation (Playwright)
- **BrowserExploiter** — confirm XSS (JS execution detection), CSRF, auth bypass, open redirect
- **BrowserAuthHandler** — form login, OAuth flows, cookie/token extraction
- **Evidence screenshots** — captures proof of exploitation

### 📋 PoC Generation
- **PoCGenerator** — three formats per finding: curl, Python script, browser steps
- **Auth token masking** — sensitive tokens masked with `<AUTH_TOKEN>`
- **PoC fields on Finding** — `poc_curl`, `poc_python`, `poc_steps`, `confirmed`, `screenshot_path`

### 🕵️ Detection Engine
- **CallbackServer** — OOB HTTP callback receiver for SSRF/XXE/RCE detection
- **InteractshClient** — interact.sh integration for blind vulnerability detection
- **ResponseDiffer** — baseline vs payload response comparison (SQLi/SSTI/timing indicators)
- **JWTAnalyzer** — decode, weak secret brute-force, none-algo bypass, claim analysis
- **DeterministicFuzzer** — fast pre-fuzzer with known payloads (no LLM, no cost)
- **GraphQLTester** — endpoint discovery, introspection, depth limit testing, batch attack
- **OpenAPIDiscovery** — find exposed specs, extract endpoints, check for security issues

### 🎯 Target Profiles
- **Microsoft Copilot** — expanded with WebSocket endpoints, scope rules, auth config, bounty info
- **OpenAI ChatGPT** — backend API endpoints, scope rules
- **Salesforce Agentforce** — agent API endpoints

### 🛡️ Security Features
- **ScopeManager** — enforce in-scope/out-of-scope rules before every request
- **EvidenceCollector** — HAR export, screenshot collection, zip evidence bundle
- **Budget control** — `--budget N` caps max LLM calls

### 🖥️ CLI Flags
- `--auth2` — secondary account auth for IDOR testing
- `--target-profile` — load pre-built target config (copilot|openai|salesforce)
- `--max-iterations` — agent loop iterations (default: 50)
- `--browser` — enable Playwright browser exploitation
- `--ws` — enable WebSocket testing
- `--strict` — no exploit = no report mode
- `--stealth` — random delays, UA rotation
- `--scope` — scope rules (comma-separated, ! to exclude)
- `--budget` — max LLM calls
- `--har` — export HTTP traffic to HAR file

### Dependencies
- `websockets>=12.0` (optional: `pip install senshi[websocket]`)
- `playwright>=1.40.0` (optional: `pip install senshi[browser]`)
- `pip install senshi[all]` — install all optional dependencies

---

## [0.2.0] — 2026-03-06

### ⚡ Performance Overhaul
- **Batch response analysis** — 1 LLM call per endpoint per scanner instead of 1 per payload (~6x fewer LLM calls)
- **Smart endpoint-to-scanner routing** — only runs relevant scanners per endpoint
- **Progressive save** — findings saved to disk in real-time, survives Ctrl+C
- **Scan dashboard** — Rich-formatted summary with timing, findings, and chain info

### 🌐 Browser Recon
- **Playwright headless browser** — captures XHR/fetch/WebSocket traffic
- **Dynamic endpoint discovery** — finds API calls that static crawling misses
- **`--browser` flag** — enable browser recon on DAST scans

### 🛠️ Reliability
- **Robust JSON extraction** — handles markdown code blocks, trailing commas, partial JSON
- **Ctrl+C graceful shutdown** — saves partial results before exit
- **`--endpoints` flag** — skip discovery, load endpoints from file

---

## [0.1.0] — 2026-03-06

### Initial Release
- **DAST** — crawl, probe, inject, and analyze live endpoints
- **SAST** — deep source code analysis with multi-language support
- **7 scanner modules** — XSS, SQLi, SSRF, IDOR, Auth, Command Injection, AI Product
- **LLM providers** — DeepSeek, OpenAI, Groq, Ollama
- **Chain builder** — detect multi-step exploit chains across findings
- **Multiple reporters** — JSON, Markdown, SARIF output
