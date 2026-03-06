<p align="center">
  <h1 align="center">Senshi (戦士)</h1>
  <p align="center">
    <strong>AI-powered SAST + DAST security scanner for bug bounty hunters</strong>
  </p>
  <p align="center">
    <a href="https://pypi.org/project/senshi/"><img src="https://img.shields.io/pypi/v/senshi?color=blue&label=PyPI" alt="PyPI"></a>
    <a href="https://github.com/manthanghasadiya/senshi/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
    <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python">
    <img src="https://img.shields.io/badge/LLM-DeepSeek%20%7C%20OpenAI%20%7C%20Groq%20%7C%20Ollama-purple" alt="LLM Providers">
  </p>
</p>

---

Senshi uses LLMs to generate context-aware payloads, analyze responses intelligently, eliminate false positives, and chain findings into exploitable attack paths — all from a single CLI.

**Created by [Manthan Ghasadiya](https://github.com/manthanghasadiya)** — creator of [mcpsec](https://github.com/manthanghasadiya/mcpsec) (4 CVEs including CVSS 10.0) and [igris](https://github.com/manthanghasadiya/igris).

## Why Senshi?

Traditional scanners fire generic payloads and drown you in false positives. Senshi is different:

- **🧠 AI-First** — LLMs generate payloads tailored to the target's tech stack and context
- **🚫 FP Elimination** — A skeptical 2nd-pass AI reviewer slashes false positives
- **🔗 Chain Builder** — Links individual findings into high-impact exploit chains
- **📋 Bounty Reports** — LLM writes your HackerOne/MSRC submission for you
- **🔌 Provider Agnostic** — DeepSeek, OpenAI, Groq, Ollama, Anthropic — your choice

## Features

| Feature | Description |
|---------|-------------|
| **DAST** | Crawl, probe, inject, and analyze live endpoints |
| **SAST** | Deep source code analysis with multi-language support |
| **7 DAST Scanners** | XSS, SSRF, IDOR, SQLi/CMDi/SSTI, Auth bypass, Deserialization, AI Product |
| **5 SAST Scanners** | Injection, Auth, Crypto, Config, AI pattern detection |
| **Auto-Recon** | Endpoint discovery, JS analysis, tech fingerprinting |
| **4 Output Formats** | JSON, Markdown, SARIF (CI/CD), Bounty Report |
| **Burp Integration** | Route traffic through your proxy |

## Installation

```bash
pip install senshi
```

Or from source:

```bash
git clone https://github.com/manthanghasadiya/senshi.git
cd senshi
pip install -e ".[dev]"
```

## Quick Start

### 1. Set your API key

```bash
export DEEPSEEK_API_KEY="sk-..."
# or: export OPENAI_API_KEY="sk-..."
# or: export GROQ_API_KEY="gsk_..."
```

### 2. Scan

```bash
# DAST — scan live targets
senshi dast https://target.com --provider deepseek

# With auth + Burp proxy
senshi dast https://target.com/api \
  --auth "Cookie: session=abc" \
  --proxy http://127.0.0.1:8080

# Specific scanners only
senshi dast https://target.com --modules xss,ssrf,injection

# SAST — analyze source code
senshi sast ./my-project
senshi sast https://github.com/user/repo.git

# Recon only
senshi recon https://target.com --depth 3

# Generate payloads
senshi payloads --vuln xss --target "POST /api/chat" --param message

# Generate bounty report from findings
senshi dast https://target.com --output findings.json
senshi report findings.json --platform hackerone --output report.md
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `senshi dast <url>` | Scan live web endpoints |
| `senshi sast <path>` | Analyze source code (dir, git URL, or zip) |
| `senshi recon <url>` | Discover endpoints (no scanning) |
| `senshi payloads` | Generate payloads for manual testing |
| `senshi report <file>` | Generate bounty report from findings JSON |
| `senshi config` | Configure API keys and settings |

## DAST Scanners

| Scanner | Vulnerability Types |
|---------|-------------------|
| `xss` | Reflected, stored, DOM, markdown injection |
| `ssrf` | Cloud metadata, internal services, DNS rebind |
| `idor` | ID enumeration, path-based access control |
| `injection` | SQLi (error + blind), command injection, SSTI |
| `auth` | Auth bypass, method switching, header bypass |
| `deserialization` | Prototype pollution, pickle, YAML, XXE |
| `ai_product` | Prompt injection, data leakage, cross-user |

## SAST Scanners

| Scanner | Focus |
|---------|-------|
| Injection | SQLi, command injection, SSRF, path traversal in code |
| Auth | Hardcoded creds, missing auth checks, broken access control |
| Crypto | Weak hashing (MD5/SHA1), hardcoded keys, insecure random |
| Config | Debug mode, CORS misconfiguration, missing security headers |
| AI | Prompt injection sinks, unsafe eval of LLM output |

## Output Formats

- **JSON** — Machine-readable, re-importable with `senshi report`
- **Markdown** — Human-readable with severity indicators and evidence blocks
- **SARIF** — CI/CD integration (GitHub Code Scanning, Azure DevOps)
- **Bounty Report** — LLM-written submission tailored to your platform

## Supported LLM Providers

| Provider | Environment Variable | Default Model |
|----------|---------------------|---------------|
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Groq | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| Ollama | — (local) | `llama3.1` |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3.5-sonnet` |

## Architecture

```
senshi/
├── ai/                     # AI Core
│   ├── brain.py            # Universal LLM interface (no SDK dependencies)
│   ├── prompts/            # Security-focused system prompts
│   ├── payload_gen.py      # Context-aware payload generator
│   ├── response_analyzer.py
│   ├── code_analyzer.py
│   ├── false_positive_filter.py
│   ├── chain_builder.py
│   └── report_writer.py
├── core/
│   ├── config.py           # Auto-detect providers from env vars
│   ├── session.py          # HTTP session (auth, proxy, rate limiting)
│   └── engine.py           # Main scan orchestrator
├── dast/
│   ├── crawler.py          # Endpoint discovery + LLM JS analysis
│   ├── tech_detector.py    # Tech stack fingerprinting
│   ├── param_discovery.py  # Hidden parameter fuzzing
│   ├── scanners/           # 7 DAST scanner modules
│   └── validators/         # Exploitability validation
├── sast/
│   ├── repo_loader.py      # Load from dir, git, zip
│   ├── file_parser.py      # Multi-language parser
│   ├── dependency_analyzer.py
│   ├── context_builder.py
│   └── scanners/           # 5 SAST scanner modules
├── reporters/
│   ├── models.py           # Finding + ScanResult (Pydantic)
│   ├── json_report.py
│   ├── markdown_report.py
│   ├── sarif_report.py
│   └── bounty_report.py
├── targets/                # Target-specific configs
└── cli.py                  # Typer CLI
```

## Development

```bash
git clone https://github.com/manthanghasadiya/senshi.git
cd senshi
pip install -e ".[dev]"
pytest tests/ -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Legal

> [!CAUTION]
> Senshi is intended for **authorized security testing only**. Only scan targets you have explicit written permission to test. Unauthorized scanning is illegal. See [SECURITY.md](SECURITY.md).

## License

MIT License — see [LICENSE](LICENSE) for details.
