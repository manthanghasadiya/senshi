"""Tests for SAST scanners."""

from __future__ import annotations

import pytest

from senshi.sast.repo_loader import RepoLoader, LoadedFile, LANGUAGE_EXTENSIONS
from senshi.sast.file_parser import FileParser


class TestRepoLoader:
    """Test RepoLoader."""

    def test_language_detection(self):
        f = LoadedFile(path="test.py", content="print('hello')")
        assert f.language == "python"

    def test_language_detection_js(self):
        f = LoadedFile(path="app.js", content="console.log('hello')")
        assert f.language == "javascript"

    def test_language_detection_unknown(self):
        f = LoadedFile(path="readme.txt", content="hello")
        assert f.language == "unknown"

    def test_line_count(self):
        f = LoadedFile(path="test.py", content="line1\nline2\nline3")
        assert f.line_count == 3

    def test_supported_languages(self):
        expected = {"python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp", "rust", "c", "cpp"}
        assert set(LANGUAGE_EXTENSIONS.keys()) == expected


class TestFileParser:
    """Test FileParser."""

    def test_parse_python_imports(self):
        code = "import os\nfrom flask import Flask\n\ndef hello():\n    pass"
        loaded = LoadedFile(path="app.py", content=code)
        parser = FileParser()
        parsed = parser.parse(loaded)
        assert "import os" in parsed.imports
        assert "from flask import Flask" in parsed.imports

    def test_parse_python_functions(self):
        code = "def hello(name):\n    return name\n\ndef world():\n    pass"
        loaded = LoadedFile(path="app.py", content=code)
        parser = FileParser()
        parsed = parser.parse(loaded)
        func_names = [f.name for f in parsed.functions]
        assert "hello" in func_names
        assert "world" in func_names

    def test_parse_python_routes(self):
        code = '@app.route("/api/test")\ndef test():\n    pass'
        loaded = LoadedFile(path="app.py", content=code)
        parser = FileParser()
        parsed = parser.parse(loaded)
        assert len(parsed.routes) > 0
        assert parsed.routes[0]["path"] == "/api/test"

    def test_parse_javascript_imports(self):
        code = "import express from 'express';\nconst app = require('./app');"
        loaded = LoadedFile(path="app.js", content=code)
        parser = FileParser()
        parsed = parser.parse(loaded)
        assert len(parsed.imports) > 0

    def test_parse_javascript_routes(self):
        code = 'app.get("/api/users", handler);\napp.post("/api/login", authHandler);'
        loaded = LoadedFile(path="server.js", content=code)
        parser = FileParser()
        parsed = parser.parse(loaded)
        paths = [r["path"] for r in parsed.routes]
        assert "/api/users" in paths
        assert "/api/login" in paths
