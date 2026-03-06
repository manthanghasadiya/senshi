# Contributing to Senshi

Thanks for your interest in contributing to Senshi! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/manthanghasadiya/senshi.git
cd senshi
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
senshi/
├── ai/          # LLM interface, prompts, analyzers
├── core/        # Config, session, scan engine
├── dast/        # DAST crawlers, scanners, validators
├── sast/        # SAST loaders, parsers, scanners
├── reporters/   # JSON, Markdown, SARIF, bounty reports
├── targets/     # Target-specific configurations
├── utils/       # Logging, rate limiting, HTTP helpers
└── cli.py       # Typer CLI entry point
```

## Adding a New DAST Scanner

1. Create `senshi/dast/scanners/your_scanner.py`
2. Extend `BaseDastScanner` from `senshi/dast/scanners/base.py`
3. Implement `get_scanner_name()` and `get_vuln_class()`
4. Add it to `DAST_SCANNERS` in `senshi/core/engine.py`
5. Add tests in `tests/`

## Adding a New SAST Scanner

1. Create `senshi/sast/scanners/your_scanner.py`
2. Extend `BaseSastScanner` from `senshi/sast/scanners/base.py`
3. Implement `get_scanner_name()`, `get_analysis_prompt()`, and optionally `filter_relevant_files()`
4. Add it to `SAST_SCANNERS` in `senshi/core/engine.py`

## Code Style

- Use type hints everywhere
- Docstrings for public functions
- `from __future__ import annotations` at the top of every module

## Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-scanner`)
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a PR with a clear description

## Reporting Issues

Use GitHub Issues for bugs and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
