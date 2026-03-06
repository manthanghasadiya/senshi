"""
File parser — parse source files into structured representation.

Extracts functions, classes, imports, routes, and other security-relevant structures.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.sast.repo_loader import LoadedFile
from senshi.utils.logger import get_logger

logger = get_logger("senshi.sast.file_parser")


class ParsedFunction:
    """A parsed function or method."""

    def __init__(
        self,
        name: str,
        start_line: int,
        end_line: int,
        params: list[str],
        decorators: list[str] | None = None,
        body: str = "",
    ) -> None:
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.params = params
        self.decorators = decorators or []
        self.body = body


class ParsedClass:
    """A parsed class."""

    def __init__(
        self,
        name: str,
        start_line: int,
        end_line: int,
        methods: list[ParsedFunction] | None = None,
        bases: list[str] | None = None,
    ) -> None:
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.methods = methods or []
        self.bases = bases or []


class ParsedFile:
    """A parsed source file with structured metadata."""

    def __init__(self, loaded_file: LoadedFile) -> None:
        self.path = loaded_file.path
        self.content = loaded_file.content
        self.language = loaded_file.language
        self.line_count = loaded_file.line_count

        self.imports: list[str] = []
        self.functions: list[ParsedFunction] = []
        self.classes: list[ParsedClass] = []
        self.routes: list[dict[str, str]] = []
        self.strings: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "line_count": self.line_count,
            "imports": self.imports,
            "function_count": len(self.functions),
            "class_count": len(self.classes),
            "route_count": len(self.routes),
        }


class FileParser:
    """Parse source files into structured representations."""

    def parse(self, loaded_file: LoadedFile) -> ParsedFile:
        """Parse a loaded file based on its language."""
        parsed = ParsedFile(loaded_file)

        if loaded_file.language == "python":
            self._parse_python(parsed)
        elif loaded_file.language in ("javascript", "typescript"):
            self._parse_javascript(parsed)
        elif loaded_file.language == "java":
            self._parse_java(parsed)
        elif loaded_file.language == "go":
            self._parse_go(parsed)
        else:
            self._parse_generic(parsed)

        return parsed

    def parse_batch(self, files: list[LoadedFile]) -> list[ParsedFile]:
        """Parse multiple files."""
        return [self.parse(f) for f in files]

    def _parse_python(self, parsed: ParsedFile) -> None:
        """Parse Python-specific structures."""
        lines = parsed.content.split("\n")

        # Imports
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                parsed.imports.append(stripped)

        # Functions
        func_pattern = re.compile(
            r'^(\s*)(?:@(\w+)(?:\([^)]*\))?\s*\n\s*)*def\s+(\w+)\s*\(([^)]*)\)',
            re.MULTILINE,
        )
        for match in func_pattern.finditer(parsed.content):
            indent = len(match.group(1))
            name = match.group(3)
            params = [p.strip().split(":")[0].strip() for p in match.group(4).split(",") if p.strip()]
            start_line = parsed.content[:match.start()].count("\n") + 1

            # Find decorators above
            decorators = re.findall(r'@(\w+)', parsed.content[max(0, match.start() - 200):match.start()])

            parsed.functions.append(ParsedFunction(
                name=name,
                start_line=start_line,
                end_line=start_line + 10,  # Approximate
                params=params,
                decorators=decorators,
            ))

        # Routes (Flask/FastAPI/Django)
        route_patterns = [
            r'@\w+\.(?:route|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)',
            r'path\s*\(\s*["\']([^"\']+)',
            r'url\s*\(\s*r?["\']([^"\']+)',
        ]
        for pattern in route_patterns:
            for match in re.finditer(pattern, parsed.content):
                parsed.routes.append({"path": match.group(1), "source": "decorator"})

        # Strings (for secret detection)
        parsed.strings = re.findall(r'["\']([^"\']{8,})["\']', parsed.content)

    def _parse_javascript(self, parsed: ParsedFile) -> None:
        """Parse JavaScript/TypeScript structures."""
        lines = parsed.content.split("\n")

        # Imports
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("import ", "require(", "const ")) and ("require" in stripped or "import" in stripped):
                parsed.imports.append(stripped)

        # Functions
        func_patterns = [
            r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)',
        ]
        for pattern in func_patterns:
            for match in re.finditer(pattern, parsed.content):
                name = match.group(1)
                params = match.group(2).split(",") if match.lastindex >= 2 and match.group(2) else []
                start_line = parsed.content[:match.start()].count("\n") + 1
                parsed.functions.append(ParsedFunction(
                    name=name,
                    start_line=start_line,
                    end_line=start_line + 10,
                    params=[p.strip() for p in params if p.strip()],
                ))

        # Routes (Express)
        route_patterns = [
            r'(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)',
        ]
        for pattern in route_patterns:
            for match in re.finditer(pattern, parsed.content):
                parsed.routes.append({"path": match.group(1), "source": "express"})

        parsed.strings = re.findall(r'["\']([^"\']{8,})["\']', parsed.content)

    def _parse_java(self, parsed: ParsedFile) -> None:
        """Parse Java structures."""
        # Imports
        for match in re.finditer(r'^import\s+(.+);', parsed.content, re.MULTILINE):
            parsed.imports.append(match.group(1))

        # Classes
        for match in re.finditer(
            r'(?:public|private|protected)?\s*class\s+(\w+)(?:\s+extends\s+(\w+))?',
            parsed.content,
        ):
            start_line = parsed.content[:match.start()].count("\n") + 1
            parsed.classes.append(ParsedClass(
                name=match.group(1),
                start_line=start_line,
                end_line=start_line + 50,
                bases=[match.group(2)] if match.group(2) else [],
            ))

        # Routes (Spring)
        for match in re.finditer(
            r'@(?:Get|Post|Put|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)',
            parsed.content,
        ):
            parsed.routes.append({"path": match.group(1), "source": "spring"})

        parsed.strings = re.findall(r'"([^"]{8,})"', parsed.content)

    def _parse_go(self, parsed: ParsedFile) -> None:
        """Parse Go structures."""
        for match in re.finditer(r'^import\s+(?:\(([^)]+)\)|"([^"]+)")', parsed.content, re.MULTILINE):
            pkg = match.group(1) or match.group(2)
            parsed.imports.append(pkg.strip())

        for match in re.finditer(r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(([^)]*)\)', parsed.content):
            start_line = parsed.content[:match.start()].count("\n") + 1
            parsed.functions.append(ParsedFunction(
                name=match.group(1),
                start_line=start_line,
                end_line=start_line + 10,
                params=[p.strip() for p in match.group(2).split(",") if p.strip()],
            ))

        for match in re.finditer(
            r'\.(?:HandleFunc|Handle|Get|Post|Put|Delete)\s*\(\s*"([^"]+)"',
            parsed.content,
        ):
            parsed.routes.append({"path": match.group(1), "source": "go_http"})

        parsed.strings = re.findall(r'"([^"]{8,})"', parsed.content)

    def _parse_generic(self, parsed: ParsedFile) -> None:
        """Generic parsing for unsupported languages."""
        parsed.strings = re.findall(r'["\']([^"\']{8,})["\']', parsed.content)
