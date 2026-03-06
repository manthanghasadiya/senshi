"""
Technology detector — fingerprint the target's tech stack.

Analyzes headers, responses, errors, and page content to identify
frameworks, servers, languages, and WAFs.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.core.session import Response, Session
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.tech_detector")

# Header-based signatures
HEADER_SIGNATURES: dict[str, list[tuple[str, str, str]]] = {
    # (header_name, pattern, tech_name)
    "server": [
        ("Server", r"nginx", "nginx"),
        ("Server", r"Apache", "Apache"),
        ("Server", r"Microsoft-IIS", "IIS"),
        ("Server", r"cloudflare", "Cloudflare"),
        ("Server", r"gunicorn", "Gunicorn"),
    ],
    "framework": [
        ("X-Powered-By", r"Express", "Express.js"),
        ("X-Powered-By", r"PHP", "PHP"),
        ("X-Powered-By", r"ASP\.NET", "ASP.NET"),
        ("X-Powered-By", r"Next\.js", "Next.js"),
        ("X-Powered-By", r"Flask", "Flask"),
        ("X-Powered-By", r"Django", "Django"),
    ],
    "waf": [
        ("Server", r"cloudflare", "Cloudflare WAF"),
        ("X-Sucuri-ID", r".*", "Sucuri WAF"),
        ("X-CDN", r"Imperva", "Imperva WAF"),
        ("Server", r"AkamaiGHost", "Akamai WAF"),
    ],
}

# Body-based signatures
BODY_SIGNATURES: list[tuple[str, str]] = [
    (r"wp-content|wordpress", "WordPress"),
    (r"django\.contrib|csrfmiddlewaretoken", "Django"),
    (r"laravel_session|laravel_token", "Laravel"),
    (r"rails|ruby on rails|action_controller", "Ruby on Rails"),
    (r"__next|_next/static", "Next.js"),
    (r"nuxt|__nuxt", "Nuxt.js"),
    (r"react|reactDOM|_reactRoot", "React"),
    (r"ng-app|angular|ng-controller", "Angular"),
    (r"vue\.js|v-bind|v-model", "Vue.js"),
    (r"flask|werkzeug", "Flask"),
    (r"spring|java\.lang", "Spring/Java"),
    (r"\.aspx|__VIEWSTATE|__EVENTVALIDATION", "ASP.NET"),
    (r"graphql|__schema", "GraphQL"),
]


class TechDetector:
    """Detect technology stack of a target."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def detect(self, url: str | None = None) -> dict[str, Any]:
        """
        Detect the technology stack of the target.

        Returns dict with server, framework, language, waf, and other tech.
        """
        target = url or self.session.base_url
        tech: dict[str, Any] = {
            "server": [],
            "framework": [],
            "language": [],
            "waf": [],
            "cdn": [],
            "other": [],
            "headers_info": {},
        }

        try:
            response = self.session.get(target)
        except Exception as e:
            logger.warning(f"Tech detection failed: {e}")
            return tech

        # Analyze headers
        self._detect_from_headers(response, tech)

        # Analyze body
        self._detect_from_body(response, tech)

        # Check for common paths
        self._detect_from_paths(tech)

        # Deduplicate
        for key in ["server", "framework", "language", "waf", "cdn", "other"]:
            tech[key] = list(set(tech[key]))

        logger.info(f"Detected tech stack: {tech}")
        return tech

    def _detect_from_headers(self, response: Response, tech: dict[str, Any]) -> None:
        """Detect tech from HTTP headers."""
        headers = response.headers

        # Store interesting headers
        interesting = [
            "Server", "X-Powered-By", "X-AspNet-Version",
            "X-Runtime", "X-Generator", "X-Drupal-Cache",
        ]
        for header in interesting:
            value = headers.get(header, headers.get(header.lower(), ""))
            if value:
                tech["headers_info"][header] = value

        # Match signatures
        for category, signatures in HEADER_SIGNATURES.items():
            for header_name, pattern, tech_name in signatures:
                value = headers.get(header_name, headers.get(header_name.lower(), ""))
                if value and re.search(pattern, value, re.IGNORECASE):
                    tech[category].append(tech_name)

        # Cookie analysis
        cookies = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        if "PHPSESSID" in cookies:
            tech["language"].append("PHP")
        if "JSESSIONID" in cookies:
            tech["language"].append("Java")
        if "ASP.NET_SessionId" in cookies:
            tech["framework"].append("ASP.NET")
        if "connect.sid" in cookies:
            tech["framework"].append("Express.js")

    def _detect_from_body(self, response: Response, tech: dict[str, Any]) -> None:
        """Detect tech from response body content."""
        body = response.body

        for pattern, tech_name in BODY_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                # Classify into appropriate category
                if tech_name in ("React", "Angular", "Vue.js"):
                    tech["framework"].append(tech_name)
                else:
                    tech["framework"].append(tech_name)

    def _detect_from_paths(self, tech: dict[str, Any]) -> None:
        """Detect tech by probing common paths."""
        probes = [
            ("/wp-admin/", "WordPress"),
            ("/wp-login.php", "WordPress"),
            ("/.env", "Laravel/Node.js"),
            ("/server-status", "Apache"),
            ("/elmah.axd", "ASP.NET"),
            ("/actuator/health", "Spring Boot"),
        ]

        for path, tech_name in probes:
            try:
                response = self.session.get(path)
                if response.status_code not in (404, 403, 500):
                    tech["framework"].append(tech_name)
            except Exception:
                continue

    def get_summary(self, tech: dict[str, Any] | None = None) -> str:
        """Get a human-readable summary of detected technologies."""
        if tech is None:
            tech = self.detect()

        parts: list[str] = []
        if tech["server"]:
            parts.append(f"Server: {', '.join(tech['server'])}")
        if tech["framework"]:
            parts.append(f"Framework: {', '.join(tech['framework'])}")
        if tech["language"]:
            parts.append(f"Language: {', '.join(tech['language'])}")
        if tech["waf"]:
            parts.append(f"WAF: {', '.join(tech['waf'])}")

        return " | ".join(parts) if parts else "Unknown"
