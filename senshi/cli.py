"""
Senshi CLI — main entry point.

senshi pentest <url> [options]       # Autonomous pentesting agent (v0.3.0)
senshi dast <url> [options]          # Scan live web endpoints
senshi sast <path|url> [options]     # Analyze source code
senshi recon <url> [options]         # Recon only (discover endpoints)
senshi payloads [options]            # Generate payloads for manual testing
senshi report <findings.json>        # Generate bounty report from findings
senshi config                        # Configure API keys and settings
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from senshi import __version__
from senshi.utils.logger import console, print_banner, print_success, print_error

app = typer.Typer(
    name="senshi",
    help="Senshi (戦士) — AI-Powered Security Scanner for Bug Bounty Hunters",
    add_completion=False,
    rich_markup_mode="rich",
)


def version_callback(value: bool) -> None:
    if value:
        console.print(f"senshi {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Senshi (戦士) — AI-Powered Security Scanner."""
    pass


@app.command()
def dast(
    url: str = typer.Argument(..., help="Target URL to scan"),
    provider: str = typer.Option("", help="LLM provider (deepseek|openai|groq|ollama)"),
    model: str = typer.Option("", help="Specific model name"),
    auth: str = typer.Option("", help='Auth header (e.g., "Cookie: session=abc")'),
    header: list[str] = typer.Option([], help="Custom headers (repeatable)"),
    proxy: str = typer.Option("", help="Proxy URL (e.g., http://127.0.0.1:8080)"),
    modules: str = typer.Option("", help="Comma-separated scanner modules"),
    rate_limit: float = typer.Option(1.0, help="Min seconds between requests"),
    output: str = typer.Option("", help="Output file path (.json)"),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed output"),
    max_payloads: int = typer.Option(15, help="Max payloads per scanner"),
    timeout: float = typer.Option(10.0, help="HTTP request timeout in seconds"),
    endpoints: str = typer.Option("", help="Path to endpoints file (from 'senshi recon')"),
) -> None:
    """Run a DAST scan against a live target."""
    from senshi.core.config import SenshiConfig
    from senshi.core.engine import ScanEngine
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)

    # Build config
    config = SenshiConfig.load()
    if provider:
        config.provider = provider
    if model:
        config.model = model
    if auth:
        config.auth = auth
    if proxy:
        config.proxy = proxy
    config.rate_limit = rate_limit
    config.timeout = timeout
    config.verbose = verbose
    config.max_payloads = max_payloads

    # Parse headers
    for h in header:
        if ":" in h:
            key, _, value = h.partition(":")
            config.headers[key.strip()] = value.strip()

    # Re-init after overrides
    config.__post_init__()

    # Parse modules
    module_list = [m.strip() for m in modules.split(",")] if modules else None

    try:
        engine = ScanEngine(config)
        result = engine.run_dast(
            url,
            modules=module_list,
            max_payloads=max_payloads,
            output=output or None,
        )

    except Exception as e:
        print_error(f"Scan failed: {e}")
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1)


@app.command()
def pentest(
    url: str = typer.Argument(..., help="Target URL to pentest"),
    provider: str = typer.Option("", help="LLM provider (deepseek|openai|groq|ollama)"),
    model: str = typer.Option("", help="Specific model name"),
    auth: str = typer.Option("", help='Primary auth header (e.g., "Cookie: session=abc")'),
    auth2: str = typer.Option("", help='Secondary account auth (for IDOR testing)'),
    header: list[str] = typer.Option([], help="Custom headers (repeatable)"),
    proxy: str = typer.Option("", help="Proxy URL (e.g., http://127.0.0.1:8080)"),
    target_profile: str = typer.Option("", help="Target profile (copilot|openai|salesforce)"),
    max_iterations: int = typer.Option(50, help="Max agent loop iterations"),
    rate_limit: float = typer.Option(1.0, help="Min seconds between requests"),
    output: str = typer.Option("", help="Output file path (.json)"),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed output"),
    timeout: float = typer.Option(10.0, help="HTTP request timeout in seconds"),
    browser: bool = typer.Option(False, "--browser", help="Enable Playwright browser exploitation"),
    ws: bool = typer.Option(False, "--ws", help="Enable WebSocket testing"),
    strict: bool = typer.Option(False, "--strict", help="No exploit = no report (strict mode)"),
    stealth: bool = typer.Option(False, "--stealth", help="Stealth mode (random delays, UA rotation)"),
    scope: str = typer.Option("", help='Scope rules (comma-separated, prefix ! to exclude)'),
    budget: int = typer.Option(0, help="Max LLM calls (0 = unlimited)"),
    har: str = typer.Option("", help="Export HTTP traffic to HAR file"),
) -> None:
    """Run autonomous pentest agent — Think → Act → Observe loop."""
    import asyncio
    from senshi.core.config import SenshiConfig
    from senshi.core.session import Session
    from senshi.ai.brain import Brain
    from senshi.agent.pentest_agent import PentestAgent
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)

    # Build config
    config = SenshiConfig.load()
    if provider:
        config.provider = provider
    if model:
        config.model = model
    if auth:
        config.auth = auth
    if proxy:
        config.proxy = proxy
    config.rate_limit = rate_limit
    config.timeout = timeout
    config.verbose = verbose

    # Parse headers
    for h in header:
        if ":" in h:
            key, _, value = h.partition(":")
            config.headers[key.strip()] = value.strip()

    config.__post_init__()

    try:
        brain = Brain(config)
        session = Session(
            base_url=url,
            auth=config.auth,
            proxy=config.proxy,
            headers=config.headers,
            rate_limit=config.rate_limit,
            timeout=config.timeout,
        )

        agent = PentestAgent(
            target=url,
            brain=brain,
            session=session,
            max_iterations=max_iterations,
            strict_mode=strict,
            budget=budget,
            browser_enabled=browser,
            ws_enabled=ws,
            stealth=stealth,
            auth2=auth2,
            target_profile=target_profile,
            output=output,
        )

        result = asyncio.run(agent.run())

        if har:
            from senshi.core.evidence import EvidenceCollector
            collector = EvidenceCollector()
            collector.export_har(har)
            print_success(f"HAR exported to: {har}")

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print_error(f"Pentest failed: {e}")
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1)


@app.command()
def sast(
    source: str = typer.Argument(..., help="Source path or git URL"),
    provider: str = typer.Option("", help="LLM provider (deepseek|openai|groq|ollama)"),
    model: str = typer.Option("", help="Specific model name"),
    language: str = typer.Option("", help="Force language (python|javascript|etc)"),
    exclude: str = typer.Option("", help='Glob patterns to exclude (comma-separated)'),
    output: str = typer.Option("", help="Output file path (.json, .md, .sarif)"),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed output"),
    max_files: int = typer.Option(100, help="Max files to analyze"),
) -> None:
    """Run a SAST scan on source code."""
    from senshi.core.config import SenshiConfig
    from senshi.core.engine import ScanEngine
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)

    config = SenshiConfig.load()
    if provider:
        config.provider = provider
    if model:
        config.model = model
    config.verbose = verbose
    config.__post_init__()

    exclude_list = [e.strip() for e in exclude.split(",")] if exclude else None

    try:
        engine = ScanEngine(config)
        result = engine.run_sast(
            source,
            language=language or None,
            exclude=exclude_list,
            max_files=max_files,
        )

        _write_output(result, output)

    except Exception as e:
        print_error(f"Scan failed: {e}")
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1)


@app.command()
def recon(
    url: str = typer.Argument(..., help="Target URL for recon"),
    provider: str = typer.Option("", help="LLM provider"),
    auth: str = typer.Option("", help="Auth header"),
    depth: int = typer.Option(3, help="Crawl depth"),
    output: str = typer.Option("", help="Save endpoints to JSON"),
    verbose: bool = typer.Option(False, "--verbose"),
    browser: bool = typer.Option(False, "--browser", help="Use headless browser for recon"),
) -> None:
    """Discover endpoints (recon only, no scanning)."""
    import json

    from senshi.ai.brain import Brain
    from senshi.core.config import SenshiConfig
    from senshi.core.session import Session
    from senshi.dast.crawler import Crawler
    from senshi.dast.tech_detector import TechDetector
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)

    config = SenshiConfig.load()
    if provider:
        config.provider = provider
    if auth:
        config.auth = auth
    config.__post_init__()

    session = Session(base_url=url, auth=auth)

    # Tech detection
    tech = TechDetector(session)
    tech_info = tech.detect()
    print_success(f"Tech stack: {tech.get_summary(tech_info)}")

    endpoints = []

    # Browser-based recon
    if browser:
        try:
            from senshi.dast.browser_recon import BrowserRecon
            console.print("[bold cyan]Browser recon:[/bold cyan] Launching headless browser...")
            browser_recon = BrowserRecon(timeout=30)
            browser_endpoints = browser_recon.discover(url, auth=auth)
            endpoints.extend(browser_endpoints)
            print_success(f"Browser discovered {len(browser_endpoints)} endpoints")
        except ImportError:
            print_error(
                "Playwright not installed. Run: pip install 'senshi[browser]' && playwright install chromium"
            )
        except Exception as e:
            print_error(f"Browser recon failed: {e}")

    # Standard crawl
    brain = None
    try:
        brain = Brain(config=config)
    except Exception:
        console.print("[dim]No LLM configured, using basic crawl[/dim]")

    crawler = Crawler(session, brain=brain, max_depth=depth)
    crawl_endpoints = crawler.crawl()

    # Merge endpoints (deduplicate)
    seen = {(ep.url, ep.method) for ep in endpoints}
    for ep in crawl_endpoints:
        if (ep.url, ep.method) not in seen:
            endpoints.append(ep)
            seen.add((ep.url, ep.method))

    # Display
    table = Table(title="Discovered Endpoints")
    table.add_column("Method", style="cyan")
    table.add_column("URL", style="white")
    table.add_column("Params", style="yellow")
    table.add_column("Source", style="dim")

    for ep in endpoints:
        table.add_row(ep.method, ep.url, ", ".join(ep.params), ep.source)

    console.print(table)
    print_success(f"Total: {len(endpoints)} endpoints")

    if output:
        data = [ep.to_dict() for ep in endpoints]
        Path(output).write_text(json.dumps(data, indent=2))
        print_success(f"Saved to {output}")


@app.command()
def payloads(
    target: str = typer.Option("", help='Target spec (e.g., "POST /api/chat")'),
    param: str = typer.Option("q", help="Parameter name"),
    vuln: str = typer.Option("xss", help="Vulnerability class"),
    provider: str = typer.Option("", help="LLM provider"),
    count: int = typer.Option(15, help="Number of payloads"),
) -> None:
    """Generate payloads for manual testing."""
    import json

    from senshi.ai.brain import Brain
    from senshi.ai.payload_gen import PayloadGenerator
    from senshi.core.config import SenshiConfig

    print_banner()

    config = SenshiConfig.load()
    if provider:
        config.provider = provider
    config.__post_init__()

    brain = Brain(config=config)
    gen = PayloadGenerator(brain)

    parts = target.split(" ", 1)
    method = parts[0] if len(parts) > 1 else "GET"
    endpoint = parts[1] if len(parts) > 1 else parts[0]

    payload_list = gen.generate(
        vulnerability_class=vuln,
        endpoint=endpoint,
        method=method,
        parameters=[param],
        count=count,
    )

    for i, p in enumerate(payload_list, 1):
        console.print(f"  [cyan]{i:2d}.[/cyan] {p.get('value', '')}")
        console.print(f"      [dim]{p.get('technique', '')}[/dim]")

    console.print(f"\n  [green]Generated {len(payload_list)} payloads[/green]")


@app.command()
def report(
    findings_file: str = typer.Argument(..., help="Path to findings JSON"),
    platform: str = typer.Option("", help="Bug bounty platform (msrc|hackerone|bugcrowd)"),
    output: str = typer.Option("report.md", help="Output report file"),
    provider: str = typer.Option("", help="LLM provider for report generation"),
) -> None:
    """Generate a bounty report from scan findings."""
    from senshi.ai.brain import Brain
    from senshi.core.config import SenshiConfig
    from senshi.reporters.bounty_report import generate_bounty_report
    from senshi.reporters.json_report import load_findings_from_json

    print_banner()

    config = SenshiConfig.load()
    if provider:
        config.provider = provider
    config.__post_init__()

    result = load_findings_from_json(findings_file)
    brain = Brain(config=config)

    report_text = generate_bounty_report(
        result, brain, platform=platform, output_path=output
    )

    print_success(f"Report saved to {output}")
    console.print(f"  [dim]{len(report_text)} chars, {len(result.findings)} findings[/dim]")


@app.command(name="config")
def config_cmd(
    provider: str = typer.Option("", help="Set LLM provider"),
    api_key: str = typer.Option("", help="Set API key"),
    proxy: str = typer.Option("", help="Set proxy URL"),
    show: bool = typer.Option(False, "--show", help="Show current config"),
) -> None:
    """Configure Senshi settings."""
    from senshi.core.config import SenshiConfig

    config = SenshiConfig.load()

    if show or (not provider and not api_key and not proxy):
        table = Table(title="Senshi Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")

        for key, value in config.show().items():
            table.add_row(key, str(value))

        console.print(table)
        return

    if provider:
        config.provider = provider
    if api_key:
        config.api_key = api_key
    if proxy:
        config.proxy = proxy

    config.__post_init__()
    config.save()
    print_success("Configuration saved!")
    console.print(f"  [dim]Config file: {config.CONFIG_DIR / 'config.json'}[/dim]" if hasattr(config, 'CONFIG_DIR') else "")


def _write_output(result: "ScanResult", output: str) -> None:
    """Write scan results to the appropriate format."""
    if not output:
        return

    from senshi.reporters.json_report import generate_json_report
    from senshi.reporters.markdown_report import generate_markdown_report
    from senshi.reporters.sarif_report import generate_sarif_report

    if output.endswith(".json"):
        generate_json_report(result, output)
    elif output.endswith(".md"):
        generate_markdown_report(result, output)
    elif output.endswith(".sarif"):
        generate_sarif_report(result, output)
    else:
        generate_json_report(result, output)

    print_success(f"Report saved to {output}")


if __name__ == "__main__":
    app()
