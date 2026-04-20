"""
Senshi structured logger — Rich-powered console output.

Provides consistent logging across all modules with color-coded
severity levels and scan progress indicators.
"""

from __future__ import annotations

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Senshi color theme
SENSHI_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "red bold",
        "critical": "red bold reverse",
        "success": "green bold",
        "scanner": "magenta",
        "finding": "yellow bold",
        "endpoint": "blue underline",
        "payload": "dim",
    }
)

console = Console(theme=SENSHI_THEME, stderr=True)


def get_logger(name: str, verbose: bool = False) -> logging.Logger:
    """
    Get a structured logger for a module.

    Args:
        name: Module name (e.g., "senshi.dast.xss")
        verbose: If True, set to DEBUG; otherwise INFO.

    Returns:
        Configured logger with Rich handler.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = RichHandler(
            console=console,
            show_path=verbose,
            show_time=verbose,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=verbose,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    return logger


def setup_global_logging(verbose: bool = False) -> None:
    """Configure logging for the entire senshi package."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[
            RichHandler(
                console=console,
                show_path=verbose,
                show_time=verbose,
                markup=True,
                rich_tracebacks=True,
            )
        ],
        force=True,
    )


def print_banner() -> None:
    """Print the Senshi ASCII banner."""
    banner = r"""
[bold red]
   ____                 _     _
  / ___|  ___ _ __  ___| |__ (_)
  \___ \ / _ \ '_ \/ __| '_ \| |
   ___) |  __/ | | \__ \ | | | |
  |____/ \___|_| |_|___/_| |_|_|
[/bold red]
  [dim]AI-Powered Security Scanner  v{version}[/dim]
  [dim]SAST + DAST for Bug Bounty Hunters[/dim]
"""
    from senshi import __version__

    console.print(banner.format(version=__version__))


def print_finding(severity: str, title: str, location: str) -> None:
    """Print a finding in colored format."""
    colors = {
        "critical": "red bold reverse",
        "high": "red bold",
        "medium": "yellow bold",
        "low": "blue",
        "info": "dim",
    }
    color = colors.get(severity.lower(), "white")
    console.print(f"  [{color}]{severity.upper():8s}[/{color}]  {title} — [endpoint]{location}[/endpoint]")


def print_success(message: str) -> None:
    console.print(f"  [success][OK][/success] {message}")


def print_error(message: str) -> None:
    console.print(f"  [error][FAIL][/error] {message}")


def print_status(message: str) -> None:
    console.print(f"  [info]*[/info] {message}")
