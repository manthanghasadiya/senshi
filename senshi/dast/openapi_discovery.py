"""
OpenAPI / Swagger discovery — detect and parse API specifications.

Finds exposed openapi.json, swagger.json, etc and extracts
all endpoints, parameters, and auth requirements.
"""

from __future__ import annotations

import json
from typing import Any

from senshi.core.session import Session
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.openapi_discovery")

COMMON_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs",
    "/v1/openapi.json", "/v2/swagger.json", "/v3/openapi.json",
    "/api/openapi.json", "/api/swagger.json",
    "/docs/openapi.json", "/.well-known/openapi.json",
    "/swagger/v1/swagger.json", "/swagger-ui/swagger.json",
]


class OpenAPIDiscovery:
    """Discover and parse OpenAPI/Swagger specifications."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def discover(self, base_url: str) -> dict[str, Any] | None:
        """Try common paths to find an OpenAPI spec."""
        for path in COMMON_SPEC_PATHS:
            url = base_url.rstrip("/") + path
            try:
                r = self.session.get(url)
                if r.status_code == 200:
                    try:
                        spec = json.loads(r.body)
                        if self._is_openapi_spec(spec):
                            logger.info(f"Found OpenAPI spec: {url}")
                            return spec
                    except json.JSONDecodeError:
                        continue
            except Exception:
                continue
        return None

    def extract_endpoints(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract endpoints from an OpenAPI specification."""
        endpoints: list[dict[str, Any]] = []
        base_path = spec.get("basePath", "")
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, details in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    if not isinstance(details, dict):
                        continue

                    params: list[str] = []
                    for param in details.get("parameters", []):
                        if isinstance(param, dict):
                            params.append(param.get("name", ""))

                    # Check for request body params (OpenAPI 3.x)
                    request_body = details.get("requestBody", {})
                    if isinstance(request_body, dict):
                        content = request_body.get("content", {})
                        for media_type, schema in content.items():
                            if isinstance(schema, dict):
                                props = schema.get("schema", {}).get("properties", {})
                                params.extend(props.keys())

                    endpoint = {
                        "url": base_path + path,
                        "method": method.upper(),
                        "params": [p for p in params if p],
                        "summary": details.get("summary", ""),
                        "auth_required": bool(details.get("security")),
                        "content_type": self._get_content_type(details),
                    }
                    endpoints.append(endpoint)

        return endpoints

    def check_security(self, spec: dict[str, Any], spec_url: str) -> list[Finding]:
        """Check for security issues in the exposed spec."""
        findings: list[Finding] = []

        # Finding 1: API spec is publicly exposed
        findings.append(Finding(
            title=f"API specification exposed — {spec_url}",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            category="info_disclosure",
            description="OpenAPI/Swagger specification is publicly accessible",
            mode=ScanMode.DAST,
            endpoint=spec_url,
            evidence=f"Spec version: {spec.get('openapi', spec.get('swagger', 'unknown'))}",
        ))

        # Check for endpoints without security
        paths = spec.get("paths", {})
        global_security = spec.get("security", [])
        unprotected: list[str] = []

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                if not isinstance(details, dict):
                    continue
                if not details.get("security") and not global_security:
                    unprotected.append(f"{method.upper()} {path}")

        if unprotected:
            findings.append(Finding(
                title=f"API endpoints without authentication — {len(unprotected)} found",
                severity=Severity.MEDIUM,
                confidence=Confidence.POSSIBLE,
                category="auth",
                description="API specification shows endpoints without security requirements",
                mode=ScanMode.DAST,
                endpoint=spec_url,
                evidence="\n".join(unprotected[:10]),
            ))

        # Check for internal/debug endpoints
        debug_keywords = ["debug", "internal", "admin", "test", "health", "metrics"]
        sensitive: list[str] = []
        for path in paths:
            if any(kw in path.lower() for kw in debug_keywords):
                sensitive.append(path)

        if sensitive:
            findings.append(Finding(
                title=f"Internal/debug endpoints in API spec — {len(sensitive)} found",
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                category="info_disclosure",
                description="Potentially sensitive endpoints exposed in API specification",
                mode=ScanMode.DAST,
                endpoint=spec_url,
                evidence="\n".join(sensitive[:10]),
            ))

        return findings

    @staticmethod
    def _is_openapi_spec(data: dict) -> bool:
        """Check if JSON data looks like an OpenAPI/Swagger spec."""
        return (
            "openapi" in data
            or "swagger" in data
            or ("paths" in data and "info" in data)
        )

    @staticmethod
    def _get_content_type(details: dict) -> str:
        """Extract content type from operation details."""
        consumes = details.get("consumes", [])
        if "application/json" in consumes:
            return "application/json"
        if "multipart/form-data" in consumes:
            return "multipart/form-data"
        return "application/json"
