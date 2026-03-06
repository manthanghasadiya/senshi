"""
Context builder — build code context for LLM analysis.

Chunks and frames code for the LLM's context window.
"""

from __future__ import annotations

from typing import Any

from senshi.sast.file_parser import ParsedFile
from senshi.sast.dependency_analyzer import DependencyGraph
from senshi.utils.logger import get_logger

logger = get_logger("senshi.sast.context_builder")

# Max tokens approximation (4 chars ~= 1 token, max context ~8K tokens for code)
MAX_CHUNK_CHARS = 30_000


class CodeContext:
    """Code context for LLM analysis."""

    def __init__(
        self,
        language: str = "python",
        framework: str = "unknown",
        app_description: str = "",
        dependencies: list[str] | None = None,
    ) -> None:
        self.language = language
        self.framework = framework
        self.app_description = app_description
        self.dependencies = dependencies or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "framework": self.framework,
            "app_description": self.app_description,
            "dependencies": self.dependencies,
        }


class ContextBuilder:
    """Build code context for LLM security analysis."""

    def __init__(
        self,
        parsed_files: list[ParsedFile],
        dep_graph: DependencyGraph | None = None,
    ) -> None:
        self.files = parsed_files
        self.dep_graph = dep_graph

    def build_context(self) -> CodeContext:
        """Build overall code context."""
        # Detect language and framework
        language = self._detect_primary_language()
        framework = self._detect_framework()
        deps = self._collect_dependencies()

        return CodeContext(
            language=language,
            framework=framework,
            app_description=self._build_description(),
            dependencies=deps,
        )

    def chunk_files(
        self, max_chunk_size: int = MAX_CHUNK_CHARS
    ) -> list[list[dict[str, str]]]:
        """
        Split files into chunks suitable for LLM analysis.

        Each chunk is a list of {"path": str, "content": str} dicts
        that together fit within the context window.
        """
        chunks: list[list[dict[str, str]]] = []
        current_chunk: list[dict[str, str]] = []
        current_size = 0

        for pf in self.files:
            file_size = len(pf.content)

            if file_size > max_chunk_size:
                # Split large file into sub-chunks
                if current_chunk:
                    chunks.append(current_chunk)
                    current_chunk = []
                    current_size = 0

                sub_chunks = self._split_file(pf, max_chunk_size)
                for sc in sub_chunks:
                    chunks.append([sc])
                continue

            if current_size + file_size > max_chunk_size:
                chunks.append(current_chunk)
                current_chunk = []
                current_size = 0

            current_chunk.append({"path": pf.path, "content": pf.content})
            current_size += file_size

        if current_chunk:
            chunks.append(current_chunk)

        logger.info(f"Split {len(self.files)} files into {len(chunks)} chunks")
        return chunks

    def get_file_with_context(self, target_file: ParsedFile) -> str:
        """
        Get a file's content with relevant context from dependencies.

        Includes imports from related files to give LLM full picture.
        """
        context_parts: list[str] = []

        context_parts.append(f"# File: {target_file.path}")
        context_parts.append(f"# Language: {target_file.language}")

        if target_file.routes:
            context_parts.append(f"# Routes: {[r['path'] for r in target_file.routes]}")

        # Add dependency context
        if self.dep_graph:
            deps = self.dep_graph.get_dependencies(target_file.path)
            if deps:
                context_parts.append(f"# Dependencies: {deps}")

                # Include relevant dependency snippets
                for dep_path in deps[:3]:
                    dep_file = next(
                        (f for f in self.files if f.path == dep_path), None
                    )
                    if dep_file:
                        snippet = dep_file.content[:2000]
                        context_parts.append(
                            f"\n# --- Dependency: {dep_path} ---\n{snippet}"
                        )

        context_parts.append(f"\n# --- Main file: {target_file.path} ---")
        context_parts.append(target_file.content)

        return "\n".join(context_parts)

    def _split_file(
        self, parsed_file: ParsedFile, max_size: int
    ) -> list[dict[str, str]]:
        """Split a large file into sub-chunks at function boundaries."""
        lines = parsed_file.content.split("\n")
        chunks: list[dict[str, str]] = []
        current_lines: list[str] = []
        current_size = 0

        for line in lines:
            line_size = len(line) + 1
            if current_size + line_size > max_size and current_lines:
                chunks.append({
                    "path": f"{parsed_file.path} (chunk {len(chunks) + 1})",
                    "content": "\n".join(current_lines),
                })
                current_lines = []
                current_size = 0

            current_lines.append(line)
            current_size += line_size

        if current_lines:
            chunks.append({
                "path": f"{parsed_file.path} (chunk {len(chunks) + 1})",
                "content": "\n".join(current_lines),
            })

        return chunks

    def _detect_primary_language(self) -> str:
        """Detect the primary language of the project."""
        lang_counts: dict[str, int] = {}
        for f in self.files:
            lang_counts[f.language] = lang_counts.get(f.language, 0) + 1
        if lang_counts:
            return max(lang_counts, key=lang_counts.get)  # type: ignore
        return "unknown"

    def _detect_framework(self) -> str:
        """Detect the framework from imports and file patterns."""
        all_imports = set()
        for f in self.files:
            all_imports.update(f.imports)

        import_str = " ".join(all_imports).lower()

        frameworks = {
            "flask": "Flask",
            "django": "Django",
            "fastapi": "FastAPI",
            "express": "Express.js",
            "next": "Next.js",
            "react": "React",
            "spring": "Spring",
            "laravel": "Laravel",
            "rails": "Ruby on Rails",
            "gin": "Gin",
        }

        for keyword, name in frameworks.items():
            if keyword in import_str:
                return name

        return "unknown"

    def _collect_dependencies(self) -> list[str]:
        """Collect external dependencies."""
        deps: set[str] = set()
        for f in self.files:
            for imp in f.imports:
                parts = imp.replace("from ", "").replace("import ", "").split(" ")[0]
                root = parts.split(".")[0].split("/")[0]
                if root and not root.startswith("."):
                    deps.add(root)
        return sorted(deps)[:20]

    def _build_description(self) -> str:
        """Build a description of the application."""
        routes: list[str] = []
        for f in self.files:
            for r in f.routes:
                routes.append(r["path"])

        desc_parts = [
            f"Language: {self._detect_primary_language()}",
            f"Framework: {self._detect_framework()}",
            f"Files: {len(self.files)}",
        ]
        if routes:
            desc_parts.append(f"Routes: {routes[:10]}")

        return " | ".join(desc_parts)
