"""
Senshi scan engine — main orchestrator for DAST and SAST scans.

Wires together crawlers, scanners, analyzers, and reporters into
a complete scanning pipeline with progress output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from senshi.ai.brain import Brain
from senshi.ai.chain_builder import ChainBuilder
from senshi.ai.false_positive_filter import FalsePositiveFilter
from senshi.core.config import SenshiConfig
from senshi.core.session import Session
from senshi.dast.crawler import Crawler
from senshi.dast.scanners.ai_product import AiProductScanner
from senshi.dast.scanners.auth import AuthScanner
from senshi.dast.scanners.deserialization import DeserializationScanner
from senshi.dast.scanners.idor import IdorScanner
from senshi.dast.scanners.injection import InjectionScanner
from senshi.dast.scanners.ssrf import SsrfScanner
from senshi.dast.scanners.xss import XssScanner
from senshi.dast.tech_detector import TechDetector
from senshi.reporters.models import Finding, ScanMode, ScanResult
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


class ScanEngine:
    """Main scan orchestrator — DAST + SAST."""

    def __init__(self, config: SenshiConfig) -> None:
        self.config = config
        self.brain = Brain(
            provider=config.provider,
            model=config.model or None,
            api_key=config.api_key or None,
            config=config,
        )

    def run_dast(
        self,
        url: str,
        modules: list[str] | None = None,
        max_payloads: int = 15,
    ) -> ScanResult:
        """
        Run a DAST scan against a live target.

        Args:
            url: Target URL.
            modules: Scanner modules to run (default: all).
            max_payloads: Max payloads per scanner.

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult(
            target=url,
            mode=ScanMode.DAST,
            provider=self.config.provider,
            model=self.config.model,
        )

        # Initialize session
        session = Session(
            base_url=url,
            auth=self.config.auth,
            proxy=self.config.proxy,
            rate_limit=self.config.rate_limit,
            timeout=self.config.timeout,
        )

        # Phase 1: Tech detection
        console.print("\n[bold cyan]Phase 1:[/bold cyan] Detecting technology stack...")
        tech_detector = TechDetector(session)
        tech_info = tech_detector.detect()
        tech_summary = tech_detector.get_summary(tech_info)
        print_success(f"Tech stack: {tech_summary}")

        # Phase 2: Crawl endpoints
        console.print("\n[bold cyan]Phase 2:[/bold cyan] Discovering endpoints...")
        crawler = Crawler(session, brain=self.brain)
        endpoints = crawler.crawl()
        result.endpoints_discovered = len(endpoints)
        print_success(f"Found {len(endpoints)} endpoints")

        if not endpoints:
            print_error("No endpoints discovered, cannot scan")
            result.completed_at = datetime.now().isoformat()
            return result

        # Phase 3: Run scanners
        console.print("\n[bold cyan]Phase 3:[/bold cyan] Running scanners...")
        active_modules = modules or list(DAST_SCANNERS.keys())
        all_findings: list[Finding] = []

        for module_name in active_modules:
            scanner_class = DAST_SCANNERS.get(module_name)
            if not scanner_class:
                logger.warning(f"Unknown module: {module_name}")
                continue

            for endpoint in endpoints[:20]:  # Limit endpoints
                target_context = {
                    "endpoint": endpoint.url,
                    "method": endpoint.method,
                    "parameters": endpoint.params,
                    "tech_stack": tech_summary,
                    "app_description": "",
                    "previous_findings": "",
                }

                scanner = scanner_class(
                    session=session,
                    brain=self.brain,
                    target_context=target_context,
                    max_payloads=max_payloads,
                )

                try:
                    findings = scanner.scan()
                    all_findings.extend(findings)
                except Exception as e:
                    logger.warning(f"{module_name} failed on {endpoint.url}: {e}")

        # Phase 4: Build chains
        if len(all_findings) >= 2:
            console.print("\n[bold cyan]Phase 4:[/bold cyan] Building exploit chains...")
            chain_builder = ChainBuilder(self.brain)
            chains = chain_builder.build_chains(all_findings, target_description=url)
            result.chains = chains
            if chains:
                print_success(f"Found {len(chains)} exploit chains")

        result.findings = all_findings
        result.completed_at = datetime.now().isoformat()

        # Summary
        self._print_summary(result)

        return result

    def run_sast(
        self,
        source: str,
        language: str | None = None,
        exclude: list[str] | None = None,
        max_files: int = 100,
    ) -> ScanResult:
        """
        Run a SAST scan on source code.

        Args:
            source: Path to source code (dir, git URL, or zip).
            language: Force specific language.
            exclude: Glob patterns to exclude.
            max_files: Maximum files to analyze.

        Returns:
            ScanResult with all findings.
        """
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

        # Prioritize security-relevant files
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

    def _print_summary(self, result: ScanResult) -> None:
        """Print scan result summary."""
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

        # Print each finding
        for finding in sorted(
            result.findings, key=lambda f: f.severity.rank, reverse=True
        ):
            console.print(
                f"  {'🔴' if finding.severity.value == 'critical' else '🟠' if finding.severity.value == 'high' else '🟡' if finding.severity.value == 'medium' else '🔵'}"
                f"  [bold]{finding.severity.value.upper():8s}[/bold]  "
                f"{finding.title}"
            )
