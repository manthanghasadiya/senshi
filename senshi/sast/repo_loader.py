"""
Repo loader — load code from local directory, git URL, or zip file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from senshi.utils.logger import get_logger

logger = get_logger("senshi.sast.repo_loader")

# Default ignore patterns
DEFAULT_EXCLUDES: set[str] = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".env", "dist", "build", ".next", ".nuxt", "vendor",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "coverage", ".coverage", "htmlcov", "egg-info",
}

# Supported language extensions
LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "go": [".go"],
    "ruby": [".rb"],
    "php": [".php"],
    "csharp": [".cs"],
    "rust": [".rs"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
}

ALL_EXTENSIONS: set[str] = {ext for exts in LANGUAGE_EXTENSIONS.values() for ext in exts}


class LoadedFile:
    """A loaded source file."""

    def __init__(self, path: str, content: str, language: str = "") -> None:
        self.path = path
        self.content = content
        self.language = language or self._detect_language(path)
        self.line_count = content.count("\n") + 1

    def _detect_language(self, path: str) -> str:
        ext = Path(path).suffix.lower()
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if ext in exts:
                return lang
        return "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "content": self.content,
            "language": self.language,
            "line_count": self.line_count,
        }


class RepoLoader:
    """Load source code from various sources."""

    def __init__(
        self,
        exclude_patterns: list[str] | None = None,
        language: str | None = None,
        max_files: int = 100,
        max_file_size: int = 100_000,
    ) -> None:
        self.excludes = set(exclude_patterns or []) | DEFAULT_EXCLUDES
        self.language = language
        self.max_files = max_files
        self.max_file_size = max_file_size

    def load(self, source: str) -> list[LoadedFile]:
        """
        Load source files from a path or URL.

        Args:
            source: Local path, git URL, or zip path.

        Returns:
            List of LoadedFile objects.
        """
        source = source.strip()

        if source.startswith(("http://", "https://", "git@")):
            return self._load_git(source)
        elif source.endswith(".zip"):
            return self._load_zip(source)
        else:
            return self._load_directory(source)

    def _load_directory(self, path: str) -> list[LoadedFile]:
        """Load files from a local directory."""
        root = Path(path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Directory not found: {path}")
        if root.is_file():
            return self._load_single_file(root)

        files: list[LoadedFile] = []

        # Get extensions to filter by
        extensions = self._get_extensions()

        for dirpath, dirnames, filenames in os.walk(root):
            # Filter excluded directories
            dirnames[:] = [d for d in dirnames if d not in self.excludes]

            for filename in filenames:
                if len(files) >= self.max_files:
                    logger.warning(f"Max files ({self.max_files}) reached")
                    return files

                filepath = Path(dirpath) / filename

                # Check extension
                if extensions and filepath.suffix.lower() not in extensions:
                    continue

                # Check exclude patterns
                if any(pat in str(filepath) for pat in self.excludes):
                    continue

                # Check file size
                try:
                    if filepath.stat().st_size > self.max_file_size:
                        continue
                except OSError:
                    continue

                # Load file
                try:
                    content = filepath.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(filepath.relative_to(root))
                    files.append(LoadedFile(path=rel_path, content=content))
                except (OSError, UnicodeDecodeError) as e:
                    logger.debug(f"Skipping {filepath}: {e}")
                    continue

        logger.info(f"Loaded {len(files)} files from {path}")
        return files

    def _load_single_file(self, path: Path) -> list[LoadedFile]:
        """Load a single file."""
        content = path.read_text(encoding="utf-8", errors="ignore")
        return [LoadedFile(path=str(path), content=content)]

    def _load_git(self, url: str) -> list[LoadedFile]:
        """Clone a git repo and load files."""
        tmpdir = tempfile.mkdtemp(prefix="senshi_")

        try:
            logger.info(f"Cloning {url}...")
            subprocess.run(
                ["git", "clone", "--depth", "1", url, tmpdir],
                check=True,
                capture_output=True,
                text=True,
            )
            return self._load_directory(tmpdir)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Git clone failed: {e.stderr}") from e

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _load_zip(self, path: str) -> list[LoadedFile]:
        """Extract and load files from a zip."""
        import zipfile

        tmpdir = tempfile.mkdtemp(prefix="senshi_")

        try:
            with zipfile.ZipFile(path, "r") as zf:
                zf.extractall(tmpdir)
            return self._load_directory(tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _get_extensions(self) -> set[str]:
        """Get file extensions to include."""
        if self.language:
            return set(LANGUAGE_EXTENSIONS.get(self.language, []))
        return ALL_EXTENSIONS
