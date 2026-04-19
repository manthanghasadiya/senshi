"""
AttackSurface -- the complete, structured output of reconnaissance.

This is what Senshi produces from Phase 1 recon and what Phase 2 exploit
agents consume. It is fully serializable to JSON and loadable from disk,
so recon and exploitation can run independently.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from senshi.models.endpoint import Endpoint


@dataclass
class AttackSurface:
    """
    Complete attack surface for a target application.

    Built by EndpointAnalyzer from captured traffic.
    Consumed by exploit agents for vulnerability testing.
    """

    target_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    auth_scheme: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ── Computed properties ──────────────────────────────────────────

    @property
    def total_endpoints(self) -> int:
        return len(self.endpoints)

    @property
    def total_params(self) -> int:
        return sum(len(ep.parameters) for ep in self.endpoints)

    @property
    def injectable_params(self) -> int:
        return sum(len(ep.get_injectable_params()) for ep in self.endpoints)

    # ── Queries ──────────────────────────────────────────────────────

    def get_endpoints_by_risk(self) -> list[Endpoint]:
        """
        Sort endpoints by likely risk based on structural heuristics.

        Heuristics (higher score = tested first):
          - More injectable params
          - POST/PUT/DELETE methods (state-changing)
          - Path contains dynamic segments
          - Responds with JSON (likely API)
          - Has body params (injection targets)
        """
        def risk_score(ep: Endpoint) -> float:
            score = 0.0
            score += len(ep.get_injectable_params()) * 3
            if ep.method in ("POST", "PUT", "PATCH", "DELETE"):
                score += 5
            if ep.content_type.value == "json":
                score += 2
            if any(p.location.value == "body" for p in ep.parameters):
                score += 3
            if any(p.location.value == "path" for p in ep.parameters):
                score += 2
            if any(p.param_type in ("numeric", "uuid", "objectid") for p in ep.parameters):
                score += 2  # Likely IDOR candidates
            if any(p.param_type == "url" for p in ep.parameters):
                score += 4  # Likely SSRF candidates
            return score

        return sorted(self.endpoints, key=risk_score, reverse=True)

    def get_endpoints_by_method(self, method: str) -> list[Endpoint]:
        """Filter endpoints by HTTP method."""
        return [ep for ep in self.endpoints if ep.method.upper() == method.upper()]

    def get_endpoints_with_param_type(self, param_type: str) -> list[Endpoint]:
        """Find endpoints that have at least one param of a given type."""
        return [
            ep for ep in self.endpoints
            if any(p.param_type == param_type for p in ep.parameters)
        ]

    def group_by_resource(self) -> dict[str, list[Endpoint]]:
        """
        Group endpoints by REST resource prefix.

        Example: /api/users/123 and /api/users/456/posts
        both map to resource "users".
        """
        groups: dict[str, list[Endpoint]] = {}
        for ep in self.endpoints:
            segments = [s for s in ep.path.split("/") if s]
            # Find the first non-numeric segment as the resource name
            resource = "root"
            for seg in segments:
                if not seg.isdigit() and len(seg) < 30:
                    resource = seg
                    break
            groups.setdefault(resource, []).append(ep)
        return groups

    def summary(self) -> str:
        """One-line summary for CLI output."""
        methods = {}
        for ep in self.endpoints:
            methods[ep.method] = methods.get(ep.method, 0) + 1
        method_str = ", ".join(f"{m}:{c}" for m, c in sorted(methods.items()))
        return (
            f"{self.total_endpoints} endpoints ({method_str}), "
            f"{self.injectable_params} injectable params"
        )

    # ── Persistence ──────────────────────────────────────────────────

    def save(self, path: str) -> None:
        """Save attack surface to JSON file."""
        data = self.to_dict()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> AttackSurface:
        """Load attack surface from JSON file."""
        from senshi.models.endpoint import ContentType, ParamLocation, Parameter

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        endpoints = []
        for ep_data in data.get("endpoints", []):
            params = []
            for p in ep_data.get("parameters", []):
                params.append(Parameter(
                    name=p["name"],
                    location=ParamLocation(p["location"]),
                    sample_value=p.get("sample_value", ""),
                    param_type=p.get("type", "string"),
                    required=p.get("required", False),
                ))
            endpoints.append(Endpoint(
                url=ep_data["url"],
                method=ep_data["method"],
                path=ep_data["path"],
                parameters=params,
                content_type=ContentType(ep_data.get("content_type", "plain")),
                auth_required=ep_data.get("auth_required", False),
                source=ep_data.get("source", ""),
                sample_curl=ep_data.get("sample_curl", ""),
            ))

        return cls(
            target_url=data.get("target_url", ""),
            endpoints=endpoints,
            auth_scheme=data.get("auth_scheme", {}),
            technologies=data.get("technologies", []),
            discovered_at=data.get("discovered_at", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "discovered_at": self.discovered_at,
            "summary": self.summary(),
            "auth_scheme": self.auth_scheme,
            "technologies": self.technologies,
            "total_endpoints": self.total_endpoints,
            "total_params": self.total_params,
            "injectable_params": self.injectable_params,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
        }
