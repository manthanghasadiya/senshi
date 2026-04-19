"""
EndpointAnalyzer -- converts raw captured traffic into a structured AttackSurface.

Takes the bag of CapturedRequest/Response objects from TrafficInterceptor
and produces deduplicated Endpoint objects with parameter metadata,
content type detection, and auth inference.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Optional
from urllib.parse import urlparse

from senshi.models.attack_surface import AttackSurface
from senshi.models.endpoint import ContentType, Endpoint, ParamLocation, Parameter
from senshi.models.request import CapturedRequest, infer_param_type
from senshi.models.response import CapturedResponse

logger = logging.getLogger("senshi.browser.analyzer")


class EndpointAnalyzer:
    """
    Analyzes captured traffic to build a structured AttackSurface.

    Usage:
        analyzer = EndpointAnalyzer(
            requests=interceptor.get_all_endpoints(),
            responses=interceptor.responses,
        )
        surface = analyzer.build_attack_surface(
            target_url="https://target.com",
            auth_scheme=interceptor.detect_auth_scheme(),
        )
    """

    def __init__(
        self,
        requests: list[CapturedRequest],
        responses: dict[str, CapturedResponse],
    ) -> None:
        self.requests = requests
        self.responses = responses
        self._auth_params: set[str] = set()

    def build_attack_surface(
        self,
        target_url: str,
        auth_scheme: dict[str, str],
    ) -> AttackSurface:
        """
        Convert raw captured requests into a structured AttackSurface.

        Steps:
        1. Identify auth-related params (so we skip them during fuzzing)
        2. Deduplicate requests by (method, path, param_names)
        3. For each unique endpoint:
           - Extract and type all parameters
           - Determine content type
           - Infer if auth is required
           - Attach sample curl command
        4. Detect technologies from response headers
        5. Build and return AttackSurface

        No hardcoded endpoint patterns. Everything is inferred from
        the actual requests the application made.
        """
        self._auth_params = self._identify_auth_params()

        # Group requests by dedup key
        groups: dict[str, list[CapturedRequest]] = defaultdict(list)
        for req in self.requests:
            key = self._dedup_key(req)
            groups[key].append(req)

        endpoints: list[Endpoint] = []
        for key, req_group in groups.items():
            # Use the first request as representative, merge params from all
            ep = self._build_endpoint(req_group)
            if ep:
                endpoints.append(ep)

        techs = self._detect_technologies()

        surface = AttackSurface(
            target_url=target_url,
            endpoints=endpoints,
            auth_scheme=auth_scheme,
            technologies=techs,
        )

        logger.info(
            "Attack surface built: %d endpoints, %d injectable params",
            surface.total_endpoints,
            surface.injectable_params,
        )
        return surface

    # ── Endpoint building ────────────────────────────────────────────

    def _build_endpoint(self, requests: list[CapturedRequest]) -> Optional[Endpoint]:
        """Build an Endpoint from a group of deduplicated requests."""
        rep = requests[0]  # Representative request
        resp = self.responses.get(rep.url)

        # Merge parameters from all observations
        merged_params = self._merge_params(requests)

        # Determine content type
        ct = self._determine_content_type(rep)

        # Infer auth requirement
        auth_required = self._has_auth(rep)

        return Endpoint(
            url=rep.url,
            method=rep.method,
            path=rep.get_path(),
            parameters=merged_params,
            content_type=ct,
            auth_required=auth_required,
            sample_curl=rep.to_curl(),
            source="traffic",
            response_status=resp.status if resp else 0,
            response_body_preview=resp.body[:300] if resp else "",
        )

    def _merge_params(self, requests: list[CapturedRequest]) -> list[Parameter]:
        """
        Merge parameters from multiple observations of the same endpoint.

        If /api/users?id=1 and /api/users?id=42 were both seen, we get a
        single Parameter(name="id", type="numeric") with sample_value="1".

        Also infer 'required' from presence across all observations.
        """
        param_map: dict[tuple[str, str], dict[str, Any]] = {}
        total_observations = len(requests)

        for req in requests:
            for p in req.get_params():
                key = (p.name, p.location)
                if key not in param_map:
                    param_map[key] = {
                        "name": p.name,
                        "location": p.location,
                        "values": [],
                        "types": [],
                        "count": 0,
                    }
                param_map[key]["values"].append(p.value)
                param_map[key]["types"].append(p.param_type)
                param_map[key]["count"] += 1

        params: list[Parameter] = []
        for (name, location), data in param_map.items():
            # Determine best type from all observations
            type_counts: dict[str, int] = defaultdict(int)
            for t in data["types"]:
                type_counts[t] += 1
            best_type = max(type_counts, key=lambda t: type_counts[t])

            # Required if present in most observations
            required = data["count"] >= total_observations * 0.8

            try:
                loc = ParamLocation(location)
            except ValueError:
                loc = ParamLocation.QUERY

            params.append(Parameter(
                name=name,
                location=loc,
                sample_value=data["values"][0],
                param_type=best_type,
                required=required,
            ))

        return params

    # ── Auth inference ───────────────────────────────────────────────

    def _identify_auth_params(self) -> set[str]:
        """
        Identify parameter names that are likely auth-related.

        These should NOT be fuzzed because mutating them would break
        the session rather than find a vulnerability.
        """
        auth_names: set[str] = set()
        for req in self.requests:
            for p in req.get_params():
                lower = p.name.lower()
                if any(kw in lower for kw in (
                    "csrf", "token", "_token", "authenticity",
                    "nonce", "__requestverification",
                )):
                    auth_names.add(p.name)
                if p.location == "header" and lower in (
                    "authorization", "x-api-key", "x-auth-token",
                    "x-csrf-token", "x-xsrf-token",
                ):
                    auth_names.add(p.name)
        return auth_names

    def _has_auth(self, req: CapturedRequest) -> bool:
        """Check if a request carries authentication."""
        if req.headers.get("authorization"):
            return True
        cookie = req.headers.get("cookie", "")
        if cookie:
            session_names = [
                "phpsessid", "jsessionid", "sessionid", "session",
                "sid", "token", "connect.sid", "asp.net_sessionid",
            ]
            for pair in cookie.split(";"):
                name = pair.split("=", 1)[0].strip().lower()
                if any(sn in name for sn in session_names):
                    return True
        return False

    # ── Content type ─────────────────────────────────────────────────

    @staticmethod
    def _determine_content_type(req: CapturedRequest) -> ContentType:
        ct = req.get_content_type()
        mapping = {
            "json": ContentType.JSON,
            "form": ContentType.FORM,
            "multipart": ContentType.MULTIPART,
            "xml": ContentType.XML,
        }
        return mapping.get(ct, ContentType.PLAIN)

    # ── Technology detection ─────────────────────────────────────────

    def _detect_technologies(self) -> list[str]:
        """
        Detect technologies from response headers and body patterns.

        Unlike the old approach, this only looks at ACTUAL server responses,
        not guesses from the HTML shell.
        """
        techs: set[str] = set()

        for resp in self.responses.values():
            headers = resp.headers

            # Server header
            server = headers.get("server", "")
            if server:
                techs.add(f"server:{server}")

            # X-Powered-By
            powered = headers.get("x-powered-by", "")
            if powered:
                techs.add(f"powered-by:{powered}")

            # Framework-specific headers
            if headers.get("x-aspnet-version"):
                techs.add("framework:ASP.NET")
            if headers.get("x-drupal-cache"):
                techs.add("framework:Drupal")
            if "django" in headers.get("x-frame-options", "").lower():
                techs.add("framework:Django")

            # Cookie-based detection
            set_cookie = headers.get("set-cookie", "")
            if "PHPSESSID" in set_cookie:
                techs.add("language:PHP")
            if "JSESSIONID" in set_cookie:
                techs.add("language:Java")
            if "ASP.NET" in set_cookie:
                techs.add("framework:ASP.NET")
            if "connect.sid" in set_cookie:
                techs.add("framework:Express.js")
            if "csrftoken" in set_cookie:
                techs.add("framework:Django")
            if "_rails_session" in set_cookie or "_session_id" in set_cookie:
                techs.add("framework:Rails")

            # Content patterns in JSON responses
            if resp.is_json():
                body = resp.body.lower()
                if '"graphql"' in body or '"data"' in body and '"errors"' in body:
                    techs.add("api:GraphQL")

        return sorted(techs)

    # ── Dedup key ────────────────────────────────────────────────────

    @staticmethod
    def _dedup_key(req: CapturedRequest) -> str:
        param_names = sorted(
            p.name for p in req.get_params()
            if p.location in ("query", "body")
        )
        return f"{req.method}:{req.get_path()}:{','.join(param_names)}"
