"""
AI pattern scanner (SAST) — prompt injection sinks, unsafe eval, unsafe deserialization.
"""

from __future__ import annotations

from senshi.sast.scanners.base import BaseSastScanner
from senshi.sast.file_parser import ParsedFile


class AiPatternScanner(BaseSastScanner):
    """Find AI/LLM-specific vulnerabilities in source code."""

    def get_scanner_name(self) -> str:
        return "SAST AI Pattern Scanner"

    def get_analysis_prompt(self) -> str:
        return (
            "Focus specifically on AI/LLM-specific vulnerabilities: "
            "prompt injection sinks (user input concatenated into prompts), "
            "unsafe evaluation of LLM output (eval, exec on AI responses), "
            "missing input sanitization before LLM calls, "
            "system prompt exposure, cross-user data leakage in AI contexts, "
            "unsafe tool/function call execution from AI output, "
            "and insecure deserialization of AI responses."
        )

    def filter_relevant_files(self) -> list[ParsedFile]:
        keywords = [
            "openai", "anthropic", "llm", "gpt", "claude", "prompt",
            "completion", "chat", "assistant", "system_message",
            "langchain", "agent", "tool", "function_call",
            "embedding", "vector", "rag", "context", "inference",
            "deepseek", "groq", "ollama", "model",
        ]
        return [
            f for f in self.files
            if any(kw in f.content.lower() for kw in keywords)
        ]
