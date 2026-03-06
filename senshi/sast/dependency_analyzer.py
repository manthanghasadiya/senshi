"""
Dependency analyzer — analyze imports, dependencies, and data flow.
"""

from __future__ import annotations

from typing import Any

from senshi.sast.file_parser import ParsedFile
from senshi.utils.logger import get_logger

logger = get_logger("senshi.sast.dependency_analyzer")


class DependencyGraph:
    """Simple dependency graph for analyzed files."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, str]] = []

    def add_file(self, path: str, metadata: dict[str, Any] | None = None) -> None:
        self.nodes[path] = metadata or {}

    def add_dependency(self, source: str, target: str, dep_type: str = "import") -> None:
        self.edges.append({"source": source, "target": target, "type": dep_type})

    def get_dependents(self, path: str) -> list[str]:
        """Get files that depend on the given file."""
        return [e["source"] for e in self.edges if e["target"] == path]

    def get_dependencies(self, path: str) -> list[str]:
        """Get files that the given file depends on."""
        return [e["target"] for e in self.edges if e["source"] == path]

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": self.nodes, "edges": self.edges}


class DependencyAnalyzer:
    """Analyze inter-file dependencies."""

    def __init__(self) -> None:
        self.graph = DependencyGraph()

    def analyze(self, parsed_files: list[ParsedFile]) -> DependencyGraph:
        """Build dependency graph from parsed files."""
        # Build path index
        file_index: dict[str, ParsedFile] = {}
        for pf in parsed_files:
            file_index[pf.path] = pf
            self.graph.add_file(pf.path, pf.to_dict())

        # Analyze imports
        for pf in parsed_files:
            for imp in pf.imports:
                resolved = self._resolve_import(imp, pf.path, pf.language, file_index)
                if resolved:
                    self.graph.add_dependency(pf.path, resolved)

        logger.info(
            f"Analyzed {len(parsed_files)} files, "
            f"{len(self.graph.edges)} dependencies"
        )
        return self.graph

    def get_security_relevant_files(
        self, parsed_files: list[ParsedFile]
    ) -> list[ParsedFile]:
        """
        Identify files most likely to contain security issues.

        Prioritizes files with:
        - Route handlers
        - Database/SQL operations
        - Authentication logic
        - External API calls
        - File operations
        - Serialization/deserialization
        """
        scored: list[tuple[float, ParsedFile]] = []

        security_keywords = {
            "high": [
                "sql", "query", "exec", "eval", "system", "subprocess",
                "shell", "cmd", "password", "secret", "token", "api_key",
                "pickle", "yaml.load", "deserialize", "unserialize",
                "redirect", "forward", "include", "require", "render",
            ],
            "medium": [
                "auth", "login", "session", "cookie", "jwt", "oauth",
                "request", "response", "upload", "download", "file",
                "open", "read", "write", "path", "url", "http",
                "database", "db", "mongo", "redis", "cache",
            ],
        }

        for pf in parsed_files:
            score = 0.0
            content_lower = pf.content.lower()

            # Routes are high priority
            score += len(pf.routes) * 3.0

            # Keyword scoring
            for keyword in security_keywords["high"]:
                if keyword in content_lower:
                    score += 2.0

            for keyword in security_keywords["medium"]:
                if keyword in content_lower:
                    score += 1.0

            # Files with many functions are more interesting
            score += min(len(pf.functions), 10) * 0.5

            scored.append((score, pf))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        return [pf for _, pf in scored if _ > 0]

    def _resolve_import(
        self,
        import_str: str,
        source_path: str,
        language: str,
        file_index: dict[str, ParsedFile],
    ) -> str | None:
        """Resolve an import to a file path in the project."""
        # Simple resolution — try to match import to file paths
        import_parts = import_str.replace("from ", "").replace("import ", "")
        import_parts = import_parts.split(" ")[0].strip()

        # Try dot-notation to path
        possible_paths = [
            import_parts.replace(".", "/") + ".py",
            import_parts.replace(".", "/") + ".js",
            import_parts.replace(".", "/") + ".ts",
            import_parts.replace(".", "/") + "/index.py",
            import_parts.replace(".", "/") + "/index.js",
        ]

        for path in possible_paths:
            if path in file_index:
                return path

        return None
