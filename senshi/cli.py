"""
Senshi CLI — main entry point.

senshi pentest <url> [options]       # Autonomous pentesting agent (v0.5.0)
senshi scan <url> [options]          # Phase 2: exploit scan (v1.0.0)
senshi scan --from-recon <file>      # Exploit from existing recon
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
from senshi.utils.logger import console, print_banner, print_success, print_error, print_status

app = typer.Typer(
    name="senshi",
    help="Senshi - AI-Powered Security Scanner for Bug Bounty Hunters",
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
    """Senshi - AI-Powered Security Scanner."""
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
    cookie: str = typer.Option(None, "--cookie", "-c", help="Session cookie (e.g., 'PHPSESSID=abc123; security=low')"),
    depth: int = typer.Option(2, help="Crawl depth"),
    browser: bool = typer.Option(False, "--browser", help="Use headless browser for discovery"),
    endpoints: str = typer.Option("", help="Path to endpoints file (from 'senshi recon')"),
    login_url: str = typer.Option("", help="Login page URL for auto-auth"),
    username: str = typer.Option("", "-u", help="Username for auto-auth"),
    password: str = typer.Option("", "-p", help="Password for auto-auth"),
) -> None:
    """Run a DAST scan against a live target."""
    from senshi.core.config import SenshiConfig
    from senshi.core.engine import ScanEngine
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)

    # ============================================
    # PHASE 0: AUTHENTICATION (MUST BE FIRST!)
    # ============================================
    if verbose:
        console.print(f"[dim]DEBUG: login_url={login_url}, u={username}, p={'*'*len(password) if password else None}[/dim]")
    
    config = SenshiConfig.load()

    if login_url and username and password:
        console.print("\n[bold cyan]Phase 0: Authentication[/bold cyan]")
        console.print(f"  Logging into {login_url}...")
        
        from senshi.auth.manager import AuthManager
        import httpx
        
        auth_manager = AuthManager(login_url, username, password)
        
        with httpx.Client(follow_redirects=True, timeout=30) as client:
            session_cookie = auth_manager.login_sync(client)
        
        if session_cookie:
            console.print(f"  [green]✓ Login successful![/green]")
            if verbose:
                console.print(f"  [dim]Session: {session_cookie[:50]}...[/dim]")
            
            # Update config cookies
            from senshi.utils.http import parse_cookies
            config.cookies.update(parse_cookies(session_cookie))
        else:
            console.print(f"  [red]✗ Login FAILED - check credentials[/red]")
            raise typer.Exit(1)
    elif login_url or username or password:
        console.print("[yellow]! Warning: Missing some login credentials (need url, user, AND pass)[/yellow]")

    # Build config overrides
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
            
    # Parse cookies override
    if cookie:
        from senshi.utils.http import parse_cookies
        config.cookies.update(parse_cookies(cookie))

    # Re-init after overrides
    config.__post_init__()

    # Parse modules
    module_list = [m.strip() for m in modules.split(",")] if modules else None

    try:
        engine = ScanEngine(config)
        result = engine.run_dast(
            url,
            modules=modules or "all",
            depth=depth,
            browser=browser,
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
    cookie: str = typer.Option(None, "--cookie", "-c", help="Session cookie (e.g., 'PHPSESSID=abc123; security=low')"),
    fast: bool = typer.Option(False, "--fast", help="Fast mode - fewer LLM calls, more aggressive batching"),
    login_url: str = typer.Option("", help="Login page URL for auto-auth"),
    username: str = typer.Option("", "-u", help="Username for auto-auth"),
    password: str = typer.Option("", "-p", help="Password for auto-auth"),
) -> None:
    """Run autonomous pentest agent - Think -> Act -> Observe loop."""
    import asyncio
    from senshi.core.config import SenshiConfig
    from senshi.core.session import Session
    from senshi.ai.brain import Brain
    from senshi.agent.pentest_agent import PentestAgent
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)

    # ============================================
    # PHASE 0: AUTHENTICATION (MUST BE FIRST!)
    # ============================================
    if verbose:
        console.print(f"[dim]DEBUG: login_url={login_url}, u={username}, p={'*'*len(password) if password else None}[/dim]")
    
    config = SenshiConfig.load()

    if login_url and username and password:
        console.print("\n[bold cyan]Phase 0: Authentication[/bold cyan]")
        console.print(f"  Logging into {login_url}...")
        
        from senshi.auth.manager import AuthManager
        import httpx
        
        auth_manager = AuthManager(login_url, username, password)
        
        with httpx.Client(follow_redirects=True, timeout=30) as client:
            session_cookie = auth_manager.login_sync(client)
        
        if session_cookie:
            console.print(f"  [green]✓ Login successful![/green]")
            if verbose:
                console.print(f"  [dim]Session: {session_cookie[:50]}...[/dim]")
            
            # Update config cookies
            from senshi.utils.http import parse_cookies
            config.cookies.update(parse_cookies(session_cookie))
        else:
            console.print(f"  [red]✗ Login FAILED - check credentials[/red]")
            raise typer.Exit(1)
    elif login_url or username or password:
        console.print("[yellow]! Warning: Missing some login credentials (need url, user, AND pass)[/yellow]")

    # Build config overrides
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

    # Parse cookies override
    if cookie:
        from senshi.utils.http import parse_cookies
        config.cookies.update(parse_cookies(cookie))

    config.__post_init__()

    try:
        brain = Brain(config=config)
        session = Session(
            base_url=url,
            auth=config.auth,
            proxy=config.proxy,
            headers=config.headers,
            cookies=config.cookies,
            rate_limit=config.rate_limit,
            timeout=config.timeout,
        )

        agent = PentestAgent(
            target=url,
            brain=brain,
            session=session,
            max_iterations=max_iterations if not fast else 20,
            fast_mode=fast,
            strict_mode=strict,
            budget=budget,
            browser_enabled=browser,
            ws_enabled=ws,
            stealth=stealth,
            auth2=auth2,
            target_profile=target_profile,
            output=output,
        )

        if browser:
            console.print("[cyan]Browser mode enabled - Playwright headless Chrome[/cyan]")
            
            from senshi.browser.engine import BrowserEngine, DOMXSSScanner
            from senshi.browser.spa_crawler import SPACrawler
            from urllib.parse import urlparse, parse_qs
            from senshi.reporters.models import Finding, Severity, Confidence, ScanMode
            from senshi.utils.logger import print_finding
            
            with BrowserEngine(headless=True) as engine:
                if 'session_cookie' in locals() and session_cookie:
                    from senshi.utils.http import parse_cookies
                    cookies_dict = parse_cookies(session_cookie)
                    cookies_list = [{"name": k, "value": v} for k, v in cookies_dict.items()]
                    engine.set_cookies(cookies_list, urlparse(url).netloc)
                elif config.cookies:
                    cookies_list = [{"name": k, "value": v} for k, v in config.cookies.items()]
                    engine.set_cookies(cookies_list, urlparse(url).netloc)
                
                spa_crawler = SPACrawler(engine)
                try:
                    spa_results = spa_crawler.crawl(url)
                    
                    api_endpoints = spa_results.get('api_endpoints', [])
                    forms = spa_results.get('forms', [])
                    pages = spa_results.get('pages', [])
                    
                    console.print(f"  Discovered {len(api_endpoints)} API endpoints")
                    console.print(f"  Found {len(forms)} forms")
                    
                    xss_scanner = DOMXSSScanner(engine)
                    
                    for endpoint in pages:
                        params = list(parse_qs(urlparse(endpoint).query).keys())
                        for param in params:
                            results = xss_scanner.scan_parameter(endpoint, param)
                            for res in results:
                                if res.vulnerable:
                                    finding = Finding(
                                        title=f"DOM XSS in {param}",
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.CONFIRMED,
                                        category="xss",
                                        mode=ScanMode.DAST,
                                        endpoint=endpoint,
                                        payload=res.payload,
                                        description=res.execution_proof,
                                        evidence=res.evidence.screenshot_path,
                                        confirmed=True,
                                    )
                                    agent.context.add_finding(finding)
                                    print_finding(finding.severity.value, finding.title, finding.endpoint)
                    for form in forms:
                        finding = xss_scanner.scan_context(engine.new_page(), endpoint, "form_input", form)
                        if finding:
                            agent.context.add_finding(finding)
                            print_finding(finding.severity.value, finding.title, finding.endpoint)
                except Exception as e:
                    console.print(f"\n[bold red]✗ Browser engine failed to connect:[/bold red] {e}")
                    if "ERR_CONNECTION_REFUSED" in str(e) or "ERR_NAME_NOT_RESOLVED" in str(e):
                        console.print(f"  [yellow]Hint: Could not reach {url}. Double check if the IP Address or Domain is correct and running.[/yellow]")
                    console.print("  [dim]Skipping browser-based discovery and falling back to standard recon mode...[/dim]")
                    spa_results = {}
                    api_endpoints = []
                    forms = []
                
                console.print("\n[bold cyan]Phase 1:[/bold cyan] Autonomous Agent Started...")
                found_eps = [{"url": ep["url"], "method": ep["method"]} for ep in api_endpoints]
                found_eps.extend([{"url": f["action"], "method": f["method"]} for f in forms])
                agent.context.add_endpoints(found_eps)

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
    cookie: str = typer.Option(None, "--cookie", "-c", help="Session cookie (e.g., 'PHPSESSID=abc123; security=low')"),
    depth: int = typer.Option(3, help="Crawl depth"),
    output: str = typer.Option("", help="Save endpoints to JSON"),
    verbose: bool = typer.Option(False, "--verbose"),
    browser: bool = typer.Option(False, "--browser", help="Use headless browser for recon"),
    login_url: str = typer.Option("", help="Login page URL for auto-auth"),
    username: str = typer.Option("", "-u", help="Username for auto-auth"),
    password: str = typer.Option("", "-p", help="Password for auto-auth"),
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

    # ============================================
    # PHASE 0: AUTHENTICATION (MUST BE FIRST!)
    # ============================================
    if verbose:
        console.print(f"[dim]DEBUG: login_url={login_url}, u={username}, p={'*'*len(password) if password else None}[/dim]")
    
    session_cookie = None
    
    config = SenshiConfig.load()

    if login_url and username and password:
        console.print("\n[bold cyan]Phase 0: Authentication[/bold cyan]")
        console.print(f"  Logging into {login_url}...")
        
        from senshi.auth.manager import AuthManager
        import httpx
        
        auth_manager = AuthManager(login_url, username, password)
        
        with httpx.Client(follow_redirects=True, timeout=30) as client:
            session_cookie = auth_manager.login_sync(client)
        
        if session_cookie:
            console.print(f"  [green]✓ Login successful![/green]")
            if verbose:
                console.print(f"  [dim]Session: {session_cookie[:50]}...[/dim]")
            
            # Update config cookies
            from senshi.utils.http import parse_cookies
            config.cookies.update(parse_cookies(session_cookie))
        else:
            console.print(f"  [red]✗ Login FAILED - check credentials[/red]")
            raise typer.Exit(1)
    elif login_url or username or password:
        console.print("[yellow]! Warning: Missing some login credentials (need url, user, AND pass)[/yellow]")
    
    if provider:
        config.provider = provider
    if auth:
        config.auth = auth
    
    # Parse cookies override
    if cookie:
        from senshi.utils.http import parse_cookies
        config.cookies.update(parse_cookies(cookie))
        
    config.__post_init__()

    session = Session(
        base_url=url,
        auth=config.auth,
        proxy=config.proxy,
        headers=config.headers,
        cookies=config.cookies,
        rate_limit=config.rate_limit,
        timeout=config.timeout,
    )

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


# -- Phase 1: Browser-Instrumented Recon ---------------------

@app.command()
def recon(
    target: str = typer.Argument(..., help="Target URL to scan"),
    output: str = typer.Option("attack_surface.json", "--output", "-o", help="Output file path (.json)"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Run browser headlessly"),
    max_pages: int = typer.Option(50, "--max-pages", help="Maximum pages to crawl"),
    timeout: int = typer.Option(60, "--timeout", help="Navigation timeout in seconds"),
    export_har: bool = typer.Option(False, "--har", help="Also export HAR file"),
    proxy: str = typer.Option("", "--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)"),
    cookie: str = typer.Option("", "--cookie", "-c", help="Session cookies ('key=val; key2=val2')"),
    extra_cookies: str = typer.Option("", "--extra-cookies", help="Additional cookies to inject after login ('key=val; key2=val2')"),
    login_url: str = typer.Option("", help="Login page URL for automated auth"),
    username: str = typer.Option("", "-u", help="Username for auto-auth"),
    password: str = typer.Option("", "-p", help="Password for auto-auth"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """
    Discover all endpoints and parameters from a web application.

    Launches a real browser, navigates to the target, interacts with the
    UI (clicks, forms, scrolling), and captures all API traffic to build
    a complete attack surface.

    Works on traditional HTML apps, SPAs (React/Angular/Vue), REST APIs,
    and GraphQL -- anything the browser can reach.

    Examples:
        senshi recon https://target.com
        senshi recon https://target.com -o results.json --har
        senshi recon https://target.com --no-headless         # watch the browser
        senshi recon http://10.0.0.151/DVWA/ --login-url http://10.0.0.151/DVWA/login.php -u admin -p password
    """
    import asyncio
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)
    asyncio.run(_recon_async(
        target=target,
        output=output,
        headless=headless,
        max_pages=max_pages,
        timeout=timeout,
        export_har=export_har,
        proxy=proxy,
        cookie=cookie,
        extra_cookies=extra_cookies,
        login_url=login_url,
        username=username,
        password=password,
        verbose=verbose,
    ))


async def _recon_async(
    *,
    target: str,
    output: str,
    headless: bool,
    max_pages: int,
    timeout: int,
    export_har: bool,
    proxy: str,
    cookie: str,
    extra_cookies: str,
    login_url: str,
    username: str,
    password: str,
    verbose: bool,
) -> None:
    """Async implementation of the recon command."""
    from urllib.parse import urlparse
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from senshi.browser.runtime import BrowserRuntime
    from senshi.browser.interceptor import TrafficInterceptor
    from senshi.browser.interactor import AppInteractor
    from senshi.browser.analyzer import EndpointAnalyzer

    target_domain = urlparse(target).netloc

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # ── 1. Launch browser ────────────────────────────────────────
        task = progress.add_task("Launching headless Chromium...", total=None)
        runtime = BrowserRuntime(headless=headless, timeout=timeout * 1000, proxy=proxy)
        try:
            await runtime.launch()
        except Exception as exc:
            print_error(f"Browser launch failed: {exc}")
            print_error("Run: pip install playwright && playwright install chromium")
            return
        progress.update(task, description="[green]Browser launched[/green] ✓")

        # ── 2. Authentication (if credentials provided) ──────────────
        if login_url and username and password:
            task = progress.add_task("Authenticating...", total=None)
            try:
                import httpx
                from senshi.auth.manager import AuthManager

                auth_mgr = AuthManager(login_url, username, password)
                with httpx.Client(follow_redirects=True, timeout=30) as client:
                    session_cookie = auth_mgr.login_sync(client)

                if session_cookie:
                    await runtime.set_cookies_from_string(session_cookie, target_domain)
                    progress.update(task, description="[green]Authenticated[/green] ✓")
                else:
                    progress.update(task, description="[yellow]Auth failed -- continuing unauthenticated[/yellow]")
            except Exception as exc:
                progress.update(task, description=f"[yellow]Auth error: {exc}[/yellow]")

        elif cookie:
            await runtime.set_cookies_from_string(cookie, target_domain)

        if extra_cookies:
            await runtime.set_cookies_from_string(extra_cookies, target_domain)

        # ── 3. Attach interceptor ────────────────────────────────────
        task = progress.add_task("Attaching traffic interceptor...", total=None)
        page = await runtime.get_page()
        interceptor = TrafficInterceptor(target_domain)
        await interceptor.attach(page)
        progress.update(task, description="[green]Interceptor attached[/green] ✓")

        # ── 4. Navigate to target ────────────────────────────────────
        task = progress.add_task(f"Navigating to {target}...", total=None)
        try:
            await runtime.navigate(target, wait_strategy="smart")
            progress.update(task, description="[green]Navigation complete[/green] ✓")
        except Exception as exc:
            print_error(f"Could not reach {target}: {exc}")
            await runtime.close()
            return

        # ── 5. Interactive crawl ─────────────────────────────────────
        task = progress.add_task("Discovering endpoints via interaction...", total=None)
        interactor = AppInteractor(page, interceptor, target_domain, target_url=target)

        # BFS crawl handles: link following, form submission, SPA clicks per-page
        crawl_stats = await interactor.crawl_spa(max_pages=max_pages)

        # Final scroll + JS triggers on last visited page
        await interactor.scroll_for_lazy_content()
        await interactor.trigger_javascript_actions()

        stats = interceptor.get_stats()
        progress.update(
            task,
            description=f"[green]Discovered {stats['unique_endpoints']} endpoints[/green] ✓",
        )

        # ── 6. Analyze traffic ───────────────────────────────────────
        task = progress.add_task("Analyzing captured traffic...", total=None)
        analyzer = EndpointAnalyzer(
            requests=interceptor.get_all_endpoints(),
            responses=interceptor.responses,
        )
        auth_scheme = interceptor.detect_auth_scheme()
        if auth_scheme["type"] == "none":
            if cookie or extra_cookies:
                auth_scheme = {"type": "cookie", "cookie_name": "injected", "token": "[hidden]"}
            elif 'session_cookie' in locals() and session_cookie:
                auth_scheme = {"type": "cookie", "cookie_name": "injected", "token": "[hidden]"}

        attack_surface = analyzer.build_attack_surface(
            target_url=target,
            auth_scheme=auth_scheme,
        )
        progress.update(task, description="[green]Analysis complete[/green] ✓")

        # ── 7. Save results ──────────────────────────────────────────
        attack_surface.save(output)

        if export_har:
            har_path = output.replace(".json", ".har")
            interceptor.export_har(har_path)
            console.print(f"  [dim]HAR exported to: {har_path}[/dim]")

        # ── 8. Close browser ─────────────────────────────────────────
        await runtime.close()

    # ── Print summary ────────────────────────────────────────────────
    console.print()
    _print_recon_summary(attack_surface)
    console.print(f"\n  [green]Attack surface saved to: {output}[/green]")
    console.print(f"  [dim]Load later with: AttackSurface.load(\"{output}\")[/dim]\n")


# -- Phase 2: Exploit Scan ------------------------------------------------

@app.command()
def scan(
    target: str = typer.Argument("", help="Target URL (runs recon first, then exploit)"),
    from_recon: str = typer.Option("", "--from-recon", help="Path to attack_surface.json (skip recon)"),
    output: str = typer.Option("scan_results.json", "-o", "--output", help="Output file path"),
    agents: str = typer.Option("", "--agents", help="Comma-separated agents to run (sqli,xss,cmdi,...)"),
    skip_agents: str = typer.Option("", "--skip-agents", help="Comma-separated agents to skip"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Seed payloads only (no LLM)"),
    aggressive: bool = typer.Option(False, "--aggressive", help="Enable Layer 3 LLM escalation"),
    browser_verify: bool = typer.Option(False, "--browser-verify", help="Verify XSS in real browser"),
    rate_limit: float = typer.Option(0.0, "--rate-limit", help="Seconds between requests (0 = fast)"),
    timeout: float = typer.Option(10.0, "--timeout", help="HTTP request timeout"),
    proxy: str = typer.Option("", "--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp)"),
    cookie: str = typer.Option("", "--cookie", "-c", help="Session cookies ('key=val; key2=val2')"),
    extra_cookies: str = typer.Option("", "--extra-cookies", help="Additional cookies ('key=val; key2=val2')"),
    login_url: str = typer.Option("", help="Login page URL for auto-auth"),
    username: str = typer.Option("", "-u", help="Username for auto-auth"),
    password: str = typer.Option("", "-p", help="Password for auto-auth"),
    provider: str = typer.Option("", help="LLM provider (deepseek|openai|groq|ollama)"),
    model: str = typer.Option("", help="Specific LLM model name"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """
    Run exploit scan against discovered attack surface.

    Supports two modes:
      1. Full pipeline: senshi scan http://target.com (runs recon then exploit)
      2. From recon:    senshi scan --from-recon attack_surface.json

    8 exploit agents: SQLi, XSS, CMDi, PathTraversal, SSRF, SSTI, IDOR, OpenRedirect.
    Layered payload architecture: seed payloads + LLM-adaptive generation.
    NO EXPLOIT = NO REPORT.

    Examples:
        senshi scan http://dvwa.local --login-url http://dvwa.local/login.php -u admin -p password --extra-cookies "security=low"
        senshi scan --from-recon attack_surface.json --cookie "PHPSESSID=abc; security=low"
        senshi scan http://target.com --agents sqli,xss,cmdi --no-ai
        senshi scan http://target.com --proxy http://127.0.0.1:8080
    """
    from senshi.utils.logger import setup_global_logging

    print_banner()
    setup_global_logging(verbose)

    if not target and not from_recon:
        print_error("Provide a target URL or --from-recon path")
        raise typer.Exit(1)

    # -- Load or build attack surface --
    if from_recon:
        console.print(f"\n  Loading attack surface from: [cyan]{from_recon}[/cyan]")
        from senshi.models.attack_surface import AttackSurface
        try:
            surface = AttackSurface.load(from_recon)
        except Exception as exc:
            print_error(f"Failed to load attack surface: {exc}")
            raise typer.Exit(1)
        console.print(f"  [green][OK][/green] {surface.summary()}")
        console.print()
    else:
        # Run recon first, then exploit
        import asyncio
        console.print("\n  [bold cyan]Phase 1: Reconnaissance[/bold cyan]\n")

        # Write recon to a temp file
        recon_output = "attack_surface.json"
        asyncio.run(_recon_async(
            target=target,
            output=recon_output,
            headless=True,
            max_pages=50,
            timeout=60,
            export_har=False,
            proxy=proxy,
            cookie=cookie,
            extra_cookies=extra_cookies,
            login_url=login_url,
            username=username,
            password=password,
            verbose=verbose,
        ))

        from senshi.models.attack_surface import AttackSurface
        try:
            surface = AttackSurface.load(recon_output)
        except Exception as exc:
            print_error(f"Recon failed: {exc}")
            raise typer.Exit(1)

    # -- Build session --
    from senshi.core.session import Session
    from senshi.utils.http import parse_cookies

    base_url = surface.target_url or target or ""
    session_cookies: dict[str, str] = {}

    # Auth
    if login_url and username and password:
        console.print("  Authenticating...")
        try:
            import httpx
            from senshi.auth.manager import AuthManager
            auth_mgr = AuthManager(login_url, username, password)
            with httpx.Client(follow_redirects=True, timeout=30) as client:
                session_cookie_str = auth_mgr.login_sync(client)
            if session_cookie_str:
                session_cookies.update(parse_cookies(session_cookie_str))
                console.print("  [green][OK][/green] Authenticated")
            else:
                console.print("  [yellow]! Auth failed -- continuing unauthenticated[/yellow]")
        except Exception as exc:
            console.print(f"  [yellow]! Auth error: {exc}[/yellow]")

    if cookie:
        session_cookies.update(parse_cookies(cookie))
    if extra_cookies:
        session_cookies.update(parse_cookies(extra_cookies))

    session = Session(
        base_url=base_url,
        proxy=proxy,
        rate_limit=rate_limit,
        cookies=session_cookies if session_cookies else None,
        timeout=timeout,
    )

    # -- Brain (LLM) --
    brain = None
    if not no_ai:
        try:
            from senshi.ai.brain import Brain
            from senshi.core.config import SenshiConfig
            config = SenshiConfig.load()
            if provider:
                config.provider = provider
            if model:
                config.model = model
            brain = Brain(config=config)
            console.print(f"  [dim]AI: {brain.provider}/{brain.model}[/dim]")
        except Exception:
            console.print("  [yellow]! No AI provider configured. Using seed payloads only.[/yellow]")
            console.print("  [dim]Run 'senshi setup' to configure an LLM for adaptive payload generation.[/dim]")

    # -- Config --
    from senshi.exploit.config import ExploitConfig
    exploit_config = ExploitConfig(
        output_path=output,
        rate_limit=rate_limit,
        timeout=timeout,
        aggressive=aggressive,
        browser_verify=browser_verify,
        use_ai=not no_ai,
        proxy=proxy,
        skip_agents=[a.strip() for a in skip_agents.split(",") if a.strip()],
        only_agents=[a.strip() for a in agents.split(",") if a.strip()],
    )

    # -- Run exploit engine --
    from senshi.exploit.engine import ExploitEngine
    from rich.table import Table as RichTable

    engine = ExploitEngine(session=session, config=exploit_config, brain=brain)

    console.print(f"\n  [bold cyan]Phase 2: Exploitation[/bold cyan]")
    console.print(f"  Agents: {', '.join(a.name for a in engine.agents)}")
    console.print(f"  Endpoints: {surface.total_endpoints} ({surface.injectable_params} injectable params)")
    console.print()

    def _print_event(event: str, **kwargs):
        """Real-time output callback."""
        if event == "agent_start":
            agent = kwargs.get("agent", "")
            ep = kwargs.get("endpoint")
            params = kwargs.get("params", "")
            if ep:
                console.print(f"  [dim]{agent}[/dim] -> {ep.method} {ep.path} [dim](param: {params})[/dim]")
        elif event == "finding":
            f = kwargs.get("finding")
            if f:
                sev_color = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim",
                }.get(f.severity.value, "white")
                confirmed = " [green][CONFIRMED][/green]" if f.confirmed else ""
                console.print(f"\n  [{sev_color}][{f.severity.value.upper()}][/{sev_color}] {f.title}{confirmed}")
                console.print(f"    Endpoint: {f.endpoint}")
                console.print(f"    Payload:  {f.payload[:80]}")
                console.print(f"    Evidence: {f.evidence[:100]}")
                if f.poc_curl:
                    console.print(f"    PoC:      {f.poc_curl[:120]}")
                console.print()

    try:
        findings = engine.run(surface, print_fn=_print_event)
    except KeyboardInterrupt:
        engine.state.interrupt()
        console.print("\n  [yellow]Scan interrupted -- partial results saved[/yellow]")
        findings = engine.state.findings
    finally:
        session.close()

    # -- Summary --
    summary = engine.get_summary(findings)
    console.print(f"\n  [bold cyan]Scan Complete[/bold cyan]")

    stats_table = RichTable(title="Scan Results", show_header=True)
    stats_table.add_column("Metric", style="cyan", min_width=20)
    stats_table.add_column("Value", style="green bold")

    stats_table.add_row("Total Findings", str(summary["total_findings"]))
    stats_table.add_row("Confirmed", str(summary["confirmed"]))

    sev = summary["severity"]
    sev_str = f"{sev['critical']} CRITICAL, {sev['high']} HIGH, {sev['medium']} MEDIUM, {sev['low']} LOW"
    stats_table.add_row("By Severity", sev_str)
    stats_table.add_row("Endpoints Tested", str(summary["endpoints_tested"]))
    stats_table.add_row("Requests Sent", str(summary["requests_sent"]))
    stats_table.add_row("LLM Calls", str(summary.get("llm_calls", 0)))

    mins = int(summary["duration_seconds"]) // 60
    secs = int(summary["duration_seconds"]) % 60
    stats_table.add_row("Duration", f"{mins}m {secs}s")
    stats_table.add_row("Report", output)

    console.print(stats_table)

    if findings:
        console.print()
        findings_table = RichTable(title="Findings", show_header=True)
        findings_table.add_column("Sev", width=10)
        findings_table.add_column("Title", min_width=30)
        findings_table.add_column("Endpoint", min_width=25)
        findings_table.add_column("Confirmed", width=10)

        def _format_endpoint(f):
            if not f.endpoint: return ""
            from urllib.parse import urlparse
            parsed = urlparse(f.endpoint)
            segments = [s for s in parsed.path.split("/") if s]
            short_path = "/".join(segments[-2:]) if len(segments) > 2 else "/".join(segments)
            display = f"{f.method} /{short_path}"
            if parsed.query: display += f"?{parsed.query[:30]}"
            return display[:50]

        for f in sorted(findings, key=lambda x: x.severity.rank if hasattr(x.severity, 'rank') else 0, reverse=True):
            sev_color = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(f.severity.value, "white")
            findings_table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f.title,
                _format_endpoint(f),
                "[green]YES[/green]" if f.confirmed else "[dim]no[/dim]",
            )
        console.print(findings_table)

    console.print(f"\n  [green]Results saved to: {output}[/green]\n")

    if findings:
        from senshi.reporters.poc_report import generate_poc_script
        
        poc_findings = [f for f in findings if f.poc_curl or f.poc_python]
        if poc_findings:
            bash_path, python_path = generate_poc_script(
                poc_findings,
                target=from_recon or target,
                cookie=cookie,
                output_dir=".",
            )
            if bash_path:
                console.print(f"  [cyan]PoC Scripts Generated:[/cyan]")
                console.print(f"    Bash:   [green]{bash_path}[/green]  (run: bash {bash_path})")
                console.print(f"    Python: [green]{python_path}[/green]  (run: python {python_path})")
                console.print()

    md_output = output.replace(".json", "_report.md") if output.endswith(".json") else "scan_report.md"

    from senshi.reporters.markdown_report import generate_markdown_report
    from senshi.reporters.models import ScanResult, ScanMode
    from datetime import datetime

    scan_result = ScanResult(
        target=from_recon or target,
        mode=ScanMode.DAST,
        started_at=engine.state.start_time,
        completed_at=datetime.now().isoformat(),
        findings=findings,
        endpoints_discovered=len(engine.state.scanned_endpoints),
        provider=provider or "default",
    )
    generate_markdown_report(scan_result, md_output)
    console.print(f"  [cyan]Report:[/cyan] [green]{md_output}[/green]\n")


def _print_recon_summary(surface: "AttackSurface") -> None:
    """Rich table summarizing the discovered attack surface."""
    from rich.table import Table as RichTable

    # Stats table
    stats_table = RichTable(title="Recon Summary", show_header=True)
    stats_table.add_column("Metric", style="cyan", min_width=25)
    stats_table.add_column("Value", style="green bold")

    stats_table.add_row("Total Endpoints", str(surface.total_endpoints))
    stats_table.add_row("Total Parameters", str(surface.total_params))
    stats_table.add_row("Injectable Parameters", str(surface.injectable_params))
    stats_table.add_row("Auth Scheme", surface.auth_scheme.get("type", "none"))
    if surface.technologies:
        stats_table.add_row("Technologies", ", ".join(surface.technologies[:5]))

    console.print(stats_table)

    # Top endpoints by risk
    top = surface.get_endpoints_by_risk()[:15]
    if top:
        ep_table = RichTable(title="Top Endpoints (by risk)", show_header=True)
        ep_table.add_column("Method", style="magenta", width=8)
        ep_table.add_column("Path", style="blue")
        ep_table.add_column("Params", style="white")
        ep_table.add_column("Type", style="dim", width=6)

        for ep in top:
            param_names = [p.name for p in ep.get_injectable_params()[:4]]
            more = len(ep.get_injectable_params()) - 4
            params_str = ", ".join(param_names)
            if more > 0:
                params_str += f" (+{more})"
            ep_table.add_row(
                ep.method,
                ep.path,
                params_str or "-",
                ep.content_type.value,
            )

        console.print(ep_table)


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
