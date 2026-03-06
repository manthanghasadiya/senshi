# Changelog

All notable changes to Senshi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-06

### Added

- **AI Core** — Universal LLM interface (`Brain`) supporting DeepSeek, OpenAI, Groq, Ollama, and Anthropic via raw `httpx` calls. No SDK dependencies.
- **DAST Scanning** — 7 scanner modules: XSS, SSRF, IDOR, Injection (SQLi/command/SSTI), Auth bypass, Deserialization, and AI Product (prompt injection/data leakage).
- **SAST Scanning** — 5 pattern scanners: Injection, Auth, Crypto, Config, and AI patterns. Multi-language parser for Python, JavaScript, TypeScript, Java, and Go.
- **Endpoint Discovery** — Crawler with HTML crawling, JavaScript analysis (LLM-powered), form extraction, API pattern detection, and `robots.txt` parsing.
- **Technology Detection** — Fingerprinting via header signatures, body patterns, cookie analysis, and path probing.
- **Parameter Discovery** — Hidden parameter fuzzing with common wordlists and LLM-suggested parameters.
- **False Positive Elimination** — Skeptical 2nd-pass AI reviewer that validates findings and adjusts severity/confidence.
- **Exploit Chain Builder** — Links individual findings into multi-step attack paths with bounty-ready narratives.
- **Exploitability Validation** — LLM-based validator to confirm real-world exploit potential.
- **4 Report Formats** — JSON (machine-readable), Markdown (human-readable), SARIF (CI/CD integration), and LLM-generated bounty reports.
- **CLI** — 6 commands: `dast`, `sast`, `recon`, `payloads`, `report`, `config`.
- **Auto-Configuration** — Auto-detects LLM provider from environment variables. Persistent config via `~/.senshi/config.json`.
- **Burp Integration** — Proxy support for routing traffic through Burp Suite.
- **Test App** — Intentionally vulnerable Flask application for testing with SQLi, XSS, SSRF, IDOR, command injection, and missing auth.

[0.1.0]: https://github.com/manthanghasadiya/senshi/releases/tag/v0.1.0
