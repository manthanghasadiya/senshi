# Changelog

## [0.6.3] — 2026-03-09
### Fixed
- **Crawler URL Resolution**: Switched to robust `urljoin` resolution to prevent path stacking (e.g., `/about.php/vulnerabilities/`).
- **Crawler Filtering**: Added noise filtering for static assets (JS, CSS, images) and `logout` links to preserve sessions.

## [0.6.2] — 2026-03-09
### Fixed
- **Cookie Capture**: Improved session cookie extraction by capturing cookies from the initial GET request to the login page.
- **DVWA Compatibility**: Added automatic `security=low` cookie for better out-of-the-box support for DVWA.
- **Auth Manager**: Simplified `login_sync` and `login` methods to use `httpx` cookie jar for automatic session maintenance.

## [0.6.1] — 2026-03-09
### Fixed
- **Missing Dependencies**: Fixed `ModuleNotFoundError: No module named 'bs4'` by ensuring `beautifulsoup4` and `nest_asyncio` are correctly handled.
- **Auto-Login**: Guaranteed authentication flow with explicit CLI Phase 0 execution.

## [0.5.9] — 2026-03-09
### Fixed
- **Auto-Login Execution**: Fixed a sync/async mismatch that was silently preventing the auto-login from running in `ScanEngine`.
- **Recon Auth**: Integrated auto-authentication into the `recon` command. Previously, `recon` would skip login and fail to discover protected endpoints.
- **Dependency**: Added `nest_asyncio` to support synchronous execution of async authentication flows in CLI/Engine.
- **Debug Visibility**: Added `DEBUG` log output (enabled with `--verbose`) to show parsed login credentials and auth status.

## [0.5.8] — 2026-03-09
### Fixed
- **Auth Before Recon**: Moved auto-authentication to Phase 0, strictly before reconnaissance and tech detection. This ensures the crawler discovers authenticated endpoints.
- **Session Propagation**: Added `update_cookies` and `update_headers` to `Session` to correctly sync authentication state across active HTTP clients.
- **Bug**: Fixed `AttributeError` when accessing `session.cookies`.

## [0.5.7] — 2026-03-09
### Added
- **Smart Auto-Authentication**: Automatically detects login forms, extracts CSRF tokens, and performs login.
- **Form Parser**: New `LoginFormParser` uses hints and types to identify username/password/hidden fields.
- **Auth Manager**: Orchestrates login flows and handles session cookie extraction/persistence.
- **CLI Options**: Added `--login-url`, `--username` (`-u`), and `--password` (`-p`) to `pentest`, `dast`, and `recon` commands.
- **Session Recovery**: `PentestAgent` now attempts auto-relogin if the session dies mid-scan.

## [0.5.6] — 2026-03-09
### Added
- **Session Auto-Validation**: Scanner now checks if the session is alive before starting and during the scan loop.
- **Logout Detection**: Automatically detects 302 redirects to login pages and stops/skips accordingly.
- **Persistent HTTP Clients**: Uses persistent `httpx` clients to better manage the cookie jar and handle session updates from the server.

### Fixed
- **Session Death Cycle**: Prevented the scanner from infinitely testing redirected login pages after session expiration.

## [0.5.5] — 2026-03-09
### Fixed
- **Cookie Persistence**: Fixed major bug where cookies were dropped during `pentest` and `recon` operations.
- **Improved Logging**: Added debug logging for outgoing headers and cookies in verbose mode.

## [0.5.4] — 2026-03-09
### Added
- `--cookie` / `-c` flag for session-based testing (e.g., DVWA, internal portals).
- Consistent `--header` / `-H` support across `pentest`, `dast`, and `recon`.

### Fixed
- **Crawler Pathing**: Preserves base path context (e.g., scanning `/DVWA/` correctly hits subdirectories).
- **Session Support**: Ensured cookies and custom headers correctly propagate to all scan requests.

All notable changes to Senshi are documented here.

## [0.5.3] - 2026-03-09

### Added
- **Final Results Table**: Added a comprehensive results table display for SAST scans, mirroring the DAST output style.

### Improved
- **Aggressive Deduplication**: Overhauled SAST deduplication to be more aggressive, focusing on core vulnerability types and file-based grouping to eliminate cross-scanner redundancy.

## [0.5.2] - 2026-03-09

## [0.5.1] — 2026-03-09

### 🧬 Engine Improvements
- **SAST Deduplication** — implemented cross-scanner finding deduplication to eliminate redundant reports (e.g., reducing findings from 36 to 9 on common codebases).
- **CMDi Confidence Scoring** — upgraded command injection findings to `CONFIRMED` when definitive command output (e.g., `whoami`) is detected in `stdout`.

### 🛡️ Module Enhancements
- **API Key Detection** — added critical regex patterns for OpenAI-style `sk-` keys and generic `api_key` patterns to the `InfoDisclosureModule`.
- **Open Redirect Verification** — fully integrated and verified the `OpenRedirectModule` in the DAST pipeline.

## [0.5.0] — 2026-03-09

### 🧩 Production-Grade Modular Architecture
- **Pluggable VulnModules** — refactored the entire scanning core to use a registry of specialized vulnerability modules.
- **Payload Database** — introduced a structured directory for managing thousands of payloads across all vulnerability classes.
- **Lazy Loading** — scanners are now loaded on-demand, reducing memory footprint and startup time.

### 🛡️ Expanded Vulnerability Coverage (10+ Scanners)
- **Open Redirect Scanner** — [NEW] automated injection of external validation URLs and protocol bypasses.
- **SSTI & Deserialization** — specialized modules for template injection and insecure object handling.
- **Autonomous Access Control** — systematic discovery and testing of IDOR and Broken Authentication issues.
- **Information Disclosure Detector** — regex-based secret and PII identification in responses.
- **Core Injection Suite** — major logic overhaul for XSS, SQLi, SSRF, and CMDi modules.

### 🧬 Hybrid Scanning Pipeline
- **Deterministic Delivery** — systematic testing of all endpoints with fixed, proven payload sets.
- **AI-Driven Analysis** — batch evaluation of raw test results using specialized LLM reasoning for high-precision vuln verification.
- **Improved Reliability** — 100% reproducible test execution with human-like intelligent response analysis.

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
