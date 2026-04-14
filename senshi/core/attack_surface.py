"""
Attack Surface Model - Unified representation of all discovered attack vectors.

Combines data from:
1. Traffic interception (actual requests)
2. DOM analysis (forms, inputs)
3. JavaScript analysis (API endpoints)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ParamLocation(Enum):
    QUERY = "query"
    BODY = "body"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class ContentType(Enum):
    FORM = "application/x-www-form-urlencoded"
    JSON = "application/json"
    MULTIPART = "multipart/form-data"
    XML = "application/xml"
    PLAIN = "text/plain"
    UNKNOWN = ""


@dataclass
class Parameter:
    """A single injectable parameter."""

    name: str
    location: ParamLocation
    value_type: str = "string"  # string, number, boolean, array, object
    sample_value: Optional[str] = None
    required: bool = False

    def __hash__(self) -> int:
        return hash((self.name, self.location))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Parameter):
            return False
        return self.name == other.name and self.location == other.location


@dataclass
class Endpoint:
    """A single endpoint with its associated parameters."""

    url: str
    method: str
    content_type: ContentType = ContentType.UNKNOWN
    parameters: list[Parameter] = field(default_factory=list)
    requires_auth: bool = False
    csrf_protected: bool = False
    csrf_token_param: Optional[str] = None

    # Discovery metadata
    source: str = ""  # "traffic", "dom", "javascript", "crawl"
    confidence: float = 1.0  # 0-1

    def __hash__(self) -> int:
        return hash((self.url, self.method))

    def get_params_by_location(self, location: ParamLocation) -> list[Parameter]:
        return [p for p in self.parameters if p.location == location]


@dataclass
class AttackSurface:
    """Complete attack surface model for a target."""

    target_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    auth_cookies: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    def add_endpoint(self, endpoint: Endpoint) -> None:
        """Add endpoint, merging parameters if URL+method already exists."""
        for existing in self.endpoints:
            if existing.url == endpoint.url and existing.method == endpoint.method:
                existing_keys = {(p.name, p.location) for p in existing.parameters}
                for param in endpoint.parameters:
                    if (param.name, param.location) not in existing_keys:
                        existing.parameters.append(param)
                # Upgrade confidence if new source is more reliable
                if endpoint.source == "traffic" and existing.source != "traffic":
                    existing.source = "traffic"
                    existing.confidence = max(existing.confidence, endpoint.confidence)
                return
        self.endpoints.append(endpoint)

    def get_injectable_params(self) -> list[tuple[Endpoint, Parameter]]:
        """Return all (endpoint, param) pairs eligible for injection testing."""
        results = []
        for ep in self.endpoints:
            for param in ep.parameters:
                if param.location in (ParamLocation.QUERY, ParamLocation.BODY, ParamLocation.PATH):
                    results.append((ep, param))
        return results

    def summary(self) -> str:
        injectable = len(self.get_injectable_params())
        return (
            f"{len(self.endpoints)} endpoints, "
            f"{injectable} injectable params, "
            f"sources={set(ep.source for ep in self.endpoints)}"
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target_url,
            "endpoint_count": len(self.endpoints),
            "injectable_params": len(self.get_injectable_params()),
            "endpoints": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "source": ep.source,
                    "confidence": ep.confidence,
                    "params": [
                        {"name": p.name, "location": p.location.value, "type": p.value_type}
                        for p in ep.parameters
                    ],
                }
                for ep in self.endpoints
            ],
        }
