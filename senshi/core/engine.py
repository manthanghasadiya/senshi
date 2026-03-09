"""
Senshi scan engine — main orchestrator for DAST and SAST scans.

v0.2.0: Smart routing, progressive save, Ctrl+C handler, scan summary dashboard.
"""

from __future__ import annotations

import signal
import sys
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from rich.panel import Panel
from rich.table import Table

from senshi.ai.brain import Brain
from senshi.ai.chain_builder import ChainBuilder
from senshi.core.config import SenshiConfig
from senshi.core.session import Session
from senshi.dast.crawler import Crawler, DiscoveredEndpoint
from senshi.dast.scanners.ai_product import AiProductScanner
from senshi.dast.scanners.auth import AuthScanner
from senshi.dast.scanners.deserialization import DeserializationScanner
from senshi.dast.scanners.idor import IdorScanner
from senshi.dast.scanners.injection import InjectionScanner
from senshi.dast.scanners.ssrf import SsrfScanner
from senshi.dast.scanners.xss import XssScanner
from senshi.dast.tech_detector import TechDetector
from senshi.reporters.models import Finding, ScanMode, ScanResult, ScanState
from senshi.sast.context_builder import ContextBuilder
from senshi.sast.dependency_analyzer import DependencyAnalyzer
from senshi.sast.file_parser import FileParser
from senshi.sast.repo_loader import RepoLoader
from senshi.sast.scanners.ai_patterns import AiPatternScanner
from senshi.sast.scanners.auth_patterns import AuthPatternScanner
from senshi.sast.scanners.config_patterns import ConfigPatternScanner
from senshi.sast.scanners.crypto_patterns import CryptoPatternScanner
from senshi.sast.scanners.injection_patterns import InjectionPatternScanner
from senshi.utils.logger import console, get_logger, print_success, print_error

logger = get_logger("senshi.core.engine")

# Map scanner module names to classes
DAST_SCANNERS = {
    "xss": XssScanner,
    "ssrf": SsrfScanner,
    "idor": IdorScanner,
    "injection": InjectionScanner,
    "auth": AuthScanner,
    "deserialization": DeserializationScanner,
    "ai": AiProductScanner,
    "ai_product": AiProductScanner,
}

SAST_SCANNERS = [
    InjectionPatternScanner,
    AuthPatternScanner,
    CryptoPatternScanner,
    ConfigPatternScanner,
    AiPatternScanner,
]


def _generate_output_path(url: str) -> str:
    """Auto-generate output filename from target URL."""
    host = urlparse(url).hostname or "scan"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"senshi_dast_{host}_{timestamp}.json"


class ScanEngine:
    """Main scan orchestrator — DAST + SAST."""

    def __init__(self, config: SenshiConfig | None = None) -> None:
        self.config = config or SenshiConfig.load()
        self.brain = Brain(config=self.config)
        
        # Load vulnerability modules
        from senshi.modules import VULNERABILITY_MODULES
        self._module_classes = VULNERABILITY_MODULES
        self._scan_state: ScanState | None = None

    def _load_modules(self, session: Session) -> list:
        """Load all vulnerability detection modules."""
        modules = []
        for name, module_class in self._module_classes.items():
            try:
                module = module_class(
                    session=session,
                    brain=self.brain,
                    callback_server=getattr(self.config, "callback_server", None),
                )
                modules.append(module)
            except Exception as e:
                logger.warning(f"Failed to load module {name}: {e}")
        return modules

    def run_dast(
        self,
        url: str,
        modules: str = "all",
        depth: int = 2,
        browser: bool = False,
        output: str | None = None,
    ) -> ScanResult:
        """
        Run a DAST scan against a live target.

        v0.2.0: Smart routing, batch analysis, progressive save.
        """
        start_time = time.time()

        result = ScanResult(
            target=url,
            mode=ScanMode.DAST,
            provider=self.config.provider,
            model=self.config.model,
        )

        # Progressive save setup
        output_path = output or _generate_output_path(url)
        self._scan_state = ScanState(output_path)
        console.print(f"[dim]Results saving to: {output_path}[/dim]")

        # Register Ctrl+C handler
        original_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_interrupt)

        try:
            # Initialize session
            session = Session(
                base_url=url,
                auth=self.config.auth,
                proxy=self.config.proxy,
            )
            # Phase 1: Discovery
            console.print(f"\n[bold cyan]Phase 1:[/bold cyan] Discovering endpoints for {url}...")
            from senshi.dast.crawler import Crawler
            crawler = Crawler(session, brain=self.brain, max_depth=depth)
            endpoints = crawler.crawl()
            result.endpoints_discovered = len(endpoints)
            print_success(f"Discovered {len(endpoints)} unique endpoints")

            if not endpoints:
                print_error("No endpoints discovered, cannot scan")
                result.completed_at = datetime.now().isoformat()
                return result

            # Show discovered endpoints
            for ep in endpoints:
                params_str = f" ({', '.join(ep.params)})" if ep.params else ""
                console.print(f"  [dim]{ep.method:4s} {ep.url}{params_str}[/dim]")

            # Phase 2: Tech Profiling
            console.print("\n[bold cyan]Phase 2:[/bold cyan] Fingerprinting technology stack...")
            from senshi.dast.tech_detector import TechDetector
            tech_detector = TechDetector(session)
            tech_info = tech_detector.detect()
            tech_stack = tech_detector.get_summary(tech_info)
            print_success(f"Tech stack: {tech_stack}")

            # Phase 3: Modular Scanning
            console.print("\n[bold cyan]Phase 3:[/bold cyan] Running modular vulnerability scans...")
            all_findings = []
            
            # Load and filter modules
            active_modules = self._load_modules(session)
            if modules != "all":
                target_modules = [m.strip() for m in modules.split(",")]
                active_modules = [m for m in active_modules if m.name in target_modules]

            for ep in endpoints:
                # Convert ep to dict format expected by modules if needed
                ep_dict = {
                    "url": ep.url if hasattr(ep, "url") else ep.get("url"),
                    "method": ep.method if hasattr(ep, "method") else ep.get("method", "GET"),
                    "params": ep.params if hasattr(ep, "params") else ep.get("params", []),
                    "content_type": ep.content_type if hasattr(ep, "content_type") else ep.get("content_type", "text/html"),
                }
                
                for module in active_modules:
                    applicability = module.is_applicable(ep_dict, tech_info)
                    if applicability >= 0.3: # Threshold for applicability
                        console.print(f"[dim]Testing {module.name} on {ep_dict['method']} {ep_dict['url']}...[/dim]")
                        findings = module.test(ep_dict, tech_info)
                        all_findings.extend(findings)

            # Phase 4: Deduplicate and sort
            from senshi.ai.batch_analyzer import BatchAnalyzer
            analyzer = BatchAnalyzer(self.brain)
            unique_findings = analyzer._deduplicate_findings(all_findings)
            print_success(f"Analysis complete: found {len(unique_findings)} vulnerabilities")
            
            # Phase 5: Build chains
            if len(unique_findings) >= 2: # Use unique_findings for chain building
                console.print("\n[bold cyan]Phase 5:[/bold cyan] Building exploit chains...")
                chain_builder = ChainBuilder(self.brain)
                chains = chain_builder.build_chains(all_findings, target_description=url)
                result.chains = chains
                if chains:
                    print_success(f"Found {len(chains)} exploit chains")

            result.findings = all_findings
            result.completed_at = datetime.now().isoformat()

            # Finalize progressive save
            if self._scan_state:
                self._scan_state.findings = all_findings
                self._scan_state.llm_calls = self.brain.total_calls
                self._scan_state.complete()

        finally:
            signal.signal(signal.SIGINT, original_handler)

        elapsed = time.time() - start_time

        # Summary
        self._print_dashboard(result, elapsed, output_path)

        return result

    def run_sast(
        self,
        source: str,
        language: str | None = None,
        exclude: list[str] | None = None,
        max_files: int = 100,
    ) -> ScanResult:
        """Run a SAST scan on source code."""
        result = ScanResult(
            target=source,
            mode=ScanMode.SAST,
            provider=self.config.provider,
            model=self.config.model,
        )

        # Phase 1: Load files
        console.print("\n[bold cyan]Phase 1:[/bold cyan] Loading source files...")
        loader = RepoLoader(
            exclude_patterns=exclude,
            language=language,
            max_files=max_files,
        )
        loaded_files = loader.load(source)
        print_success(f"Loaded {len(loaded_files)} files")

        if not loaded_files:
            print_error("No source files found")
            result.completed_at = datetime.now().isoformat()
            return result

        # Phase 2: Parse files
        console.print("\n[bold cyan]Phase 2:[/bold cyan] Parsing files...")
        parser = FileParser()
        parsed_files = parser.parse_batch(loaded_files)
        result.files_analyzed = len(parsed_files)

        # Phase 3: Build context
        console.print("\n[bold cyan]Phase 3:[/bold cyan] Building context...")
        dep_analyzer = DependencyAnalyzer()
        dep_graph = dep_analyzer.analyze(parsed_files)
        context_builder = ContextBuilder(parsed_files, dep_graph)
        code_context = context_builder.build_context()

        relevant_files = dep_analyzer.get_security_relevant_files(parsed_files)
        print_success(
            f"Context: {code_context.language} / {code_context.framework} "
            f"({len(relevant_files)} security-relevant files)"
        )

        # Phase 4: Run SAST scanners
        console.print("\n[bold cyan]Phase 4:[/bold cyan] Running SAST scanners...")
        all_findings: list[Finding] = []

        for scanner_class in SAST_SCANNERS:
            scanner = scanner_class(
                brain=self.brain,
                files=parsed_files,
                context=code_context,
            )
            try:
                findings = scanner.scan()
                all_findings.extend(findings)
            except Exception as e:
                logger.warning(f"{scanner.get_scanner_name()} failed: {e}")

        # Phase 5: Build chains
        if len(all_findings) >= 2:
            console.print("\n[bold cyan]Phase 5:[/bold cyan] Building exploit chains...")
            chain_builder = ChainBuilder(self.brain)
            chains = chain_builder.build_chains(
                all_findings, target_description=source
            )
            result.chains = chains
            if chains:
                print_success(f"Found {len(chains)} exploit chains")

        result.findings = all_findings
        result.completed_at = datetime.now().isoformat()

        self._print_summary(result)
        return result

    def _handle_interrupt(self, signum: Any, frame: Any) -> None:
        """Handle Ctrl+C — save partial results and exit."""
        console.print("\n[yellow]⚡ Scan interrupted! Saving partial results...[/yellow]")
        if self._scan_state:
            self._scan_state.interrupt()
            console.print(
                f"[green]✓ Partial results saved to {self._scan_state.output_path}[/green]"
            )
            console.print(
                f"  {len(self._scan_state.findings)} findings saved, "
                f"{self.brain.total_calls} LLM calls made"
            )
        sys.exit(0)

    def _print_dashboard(self, result: ScanResult, elapsed: float, output_path: str) -> None:
        """Print scan summary dashboard with Rich table."""
        console.print("\n")

        # Header panel
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"

        stats = self.brain.get_stats()

        header = Panel(
            f"[bold]Target:[/bold] {result.target}\n"
            f"[bold]Duration:[/bold] {duration_str}\n"
            f"[bold]Endpoints:[/bold] {result.endpoints_discovered} discovered\n"
            f"[bold]LLM Calls:[/bold] {stats['total_calls']} ({stats['provider']})\n"
            f"[bold]Status:[/bold] {'[green]Complete[/green]' if result.completed_at else '[yellow]Partial[/yellow]'}",
            title="[bold]Senshi Scan Report[/bold]",
            border_style="cyan",
        )
        console.print(header)

        # Findings table
        if result.findings:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Severity", width=10)
            table.add_column("Confidence", width=12)
            table.add_column("Finding")

            severity_colors = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }

            for finding in sorted(
                result.findings, key=lambda f: f.severity.rank, reverse=True
            ):
                sev = finding.severity.value
                color = severity_colors.get(sev, "white")
                table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    finding.confidence.value,
                    finding.title,
                )

            console.print(table)
        else:
            console.print("[dim]No findings[/dim]")

        # Footer
        console.print(f"\n[bold green]Findings saved to:[/bold green] {output_path}")
        console.print(
            f"[dim]Run 'senshi report {output_path}' to generate bounty report[/dim]\n"
        )

    def _print_summary(self, result: ScanResult) -> None:
        """Print scan result summary (for SAST)."""
        console.print("\n")
        severity_parts = []
        if result.critical_count:
            severity_parts.append(f"[red bold]{result.critical_count} CRITICAL[/red bold]")
        if result.high_count:
            severity_parts.append(f"[red]{result.high_count} HIGH[/red]")
        if result.medium_count:
            severity_parts.append(f"[yellow]{result.medium_count} MEDIUM[/yellow]")
        if result.low_count:
            severity_parts.append(f"[blue]{result.low_count} LOW[/blue]")

        summary = ", ".join(severity_parts) if severity_parts else "No findings"

        panel = Panel(
            f"[bold]{len(result.findings)} findings[/bold]: {summary}"
            + (f"\n[bold]{len(result.chains)} exploit chains[/bold]" if result.chains else ""),
            title="[bold]Scan Results[/bold]",
            border_style="green" if not result.critical_count else "red",
        )
        console.print(panel)

        for finding in sorted(
            result.findings, key=lambda f: f.severity.rank, reverse=True
        ):
            console.print(
                f"  {'🔴' if finding.severity.value == 'critical' else '🟠' if finding.severity.value == 'high' else '🟡' if finding.severity.value == 'medium' else '🔵'}"
                f"  [bold]{finding.severity.value.upper():8s}[/bold]  "
                f"{finding.title}"
            )
