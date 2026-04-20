"""
Endpoint and Parameter models.

These are the *analyzed* representations built from raw CapturedRequest data.
An Endpoint is a unique (method, path, param_names) tuple with rich metadata
attached by EndpointAnalyzer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ParamLocation(Enum):
    QUERY = "query"
    BODY = "body"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class ContentType(Enum):
    JSON = "json"
    FORM = "form"
    MULTIPART = "multipart"
    XML = "xml"
    PLAIN = "plain"


@dataclass
class Parameter:
    """A single injectable parameter on an endpoint."""

    name: str
    location: ParamLocation
    sample_value: str = ""
    param_type: str = "string"   # string | numeric | email | uuid | url | boolean | json
    required: bool = False       # inferred from observation

    def __hash__(self) -> int:
        return hash((self.name, self.location))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Parameter):
            return NotImplemented
        return self.name == other.name and self.location == other.location

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location.value,
            "sample_value": self.sample_value,
            "type": self.param_type,
            "required": self.required,
        }


@dataclass
class Endpoint:
    """
    A single discovered endpoint with parameters and metadata.

    Uniqueness key: (method, path, frozenset(param_names))
    """

    url: str
    method: str
    path: str
    parameters: list[Parameter] = field(default_factory=list)
    content_type: ContentType = ContentType.PLAIN
    auth_required: bool = False

    # Sample exchange for reference/replay
    sample_curl: str = ""

    # Source metadata
    source: str = ""         # "traffic" | "dom" | "crawl" | "js_analysis"
    response_status: int = 0
    response_body_preview: str = ""

    def get_injectable_params(self) -> list[Parameter]:
        """
        Return parameters worth testing for injection.

        Excludes auth tokens, CSRF tokens, submit buttons, and other params
        that would break the session or waste time if mutated.
        """
        skip_names = {
            "csrf", "csrftoken", "_token", "authenticity_token",
            "csrfmiddlewaretoken", "__requestverificationtoken",
            "authorization", "x-api-key", "x-auth-token",
            "x-csrf-token", "x-xsrf-token",
            # Skip submit buttons — nobody finds SQLi in a Submit param
            "submit", "btn", "button",
        }
        # Skip by sample value — catches Submit=Submit, Login=Login, etc.
        skip_values = {"submit", "login", "go", "search", "send", "reset", "ok", "cancel"}
        return [
            p for p in self.parameters
            if p.name.lower() not in skip_names
            and p.location in (ParamLocation.QUERY, ParamLocation.BODY, ParamLocation.PATH)
            and (not p.sample_value or p.sample_value.lower() not in skip_values)
        ]

    def dedup_key(self) -> str:
        """Stable deduplication key across multiple observations."""
        param_names = sorted(
            p.name for p in self.parameters
            if p.location in (ParamLocation.QUERY, ParamLocation.BODY)
        )
        return f"{self.method}:{self.path}:{','.join(param_names)}"

    def __hash__(self) -> int:
        return hash(self.dedup_key())

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "path": self.path,
            "content_type": self.content_type.value,
            "auth_required": self.auth_required,
            "source": self.source,
            "parameters": [p.to_dict() for p in self.parameters],
            "injectable_count": len(self.get_injectable_params()),
            "sample_curl": self.sample_curl,
        }
