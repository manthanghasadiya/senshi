"""
GraphQL introspection + security testing.

Auto-detects GraphQL endpoints, runs introspection queries,
extracts schema (queries, mutations, types), and generates
targeted payloads based on field types.
"""

from __future__ import annotations

import json
from typing import Any

from senshi.ai.brain import Brain
from senshi.core.session import Session
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.graphql")

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}
"""

COMMON_GRAPHQL_PATHS = [
    "/graphql", "/gql", "/api/graphql", "/v1/graphql",
    "/graphql/v1", "/query", "/api/gql",
]


class GraphQLTester:
    """Test GraphQL endpoints for security issues."""

    def __init__(self, session: Session, brain: Brain | None = None) -> None:
        self.session = session
        self.brain = brain

    def discover_endpoints(self, base_url: str) -> list[str]:
        """Try common GraphQL paths to find endpoints."""
        found: list[str] = []
        for path in COMMON_GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                # Try introspection query
                r = self.session.post(url, json_data={"query": "{ __typename }"})
                if r.status_code == 200 and "__typename" in r.body:
                    found.append(url)
                    logger.info(f"Found GraphQL endpoint: {url}")
            except Exception:
                continue
        return found

    def introspect(self, endpoint: str) -> dict[str, Any] | None:
        """Run introspection query to extract the full schema."""
        try:
            r = self.session.post(endpoint, json_data={"query": INTROSPECTION_QUERY})
            if r.status_code == 200:
                data = json.loads(r.body)
                schema = data.get("data", {}).get("__schema")
                if schema:
                    logger.info(f"Introspection successful: {len(schema.get('types', []))} types")
                    return schema
        except Exception as e:
            logger.debug(f"Introspection failed: {e}")
        return None

    def analyze_schema(self, schema: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract interesting queries, mutations, and types from schema."""
        interesting: list[dict[str, Any]] = []

        for type_def in schema.get("types", []):
            name = type_def.get("name", "")
            if name.startswith("__"):
                continue

            fields = type_def.get("fields") or []
            for field in fields:
                field_name = field.get("name", "")
                args = field.get("args", [])

                # Identify interesting patterns
                entry: dict[str, Any] = {
                    "type": name,
                    "field": field_name,
                    "args": [a["name"] for a in args],
                    "vuln_hints": [],
                }

                # Check for injection-prone fields
                field_lower = field_name.lower()
                if any(p in field_lower for p in ["search", "filter", "query", "where"]):
                    entry["vuln_hints"].append("injection")
                if any(p in field_lower for p in ["user", "profile", "account"]):
                    entry["vuln_hints"].append("idor")
                if any(p in field_lower for p in ["file", "url", "path", "import"]):
                    entry["vuln_hints"].append("ssrf")
                if any(p in field_lower for p in ["delete", "update", "create"]):
                    entry["vuln_hints"].append("mutation")

                # Check args for ID types
                for arg in args:
                    arg_name = arg["name"].lower()
                    if "id" in arg_name:
                        entry["vuln_hints"].append("idor")
                    if "url" in arg_name or "file" in arg_name:
                        entry["vuln_hints"].append("ssrf")

                if entry["vuln_hints"]:
                    interesting.append(entry)

        return interesting

    def test(self, endpoint: str) -> list[Finding]:
        """Full GraphQL security test: introspect → analyze → test."""
        findings: list[Finding] = []

        # Test 1: Introspection enabled (should be disabled in prod)
        schema = self.introspect(endpoint)
        if schema:
            findings.append(Finding(
                title=f"GraphQL introspection enabled — {endpoint}",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category="config",
                description="GraphQL introspection is enabled, exposing the full API schema",
                mode=ScanMode.DAST,
                endpoint=endpoint,
                evidence=f"{len(schema.get('types', []))} types exposed",
            ))

            # Analyze schema for interesting fields
            interesting = self.analyze_schema(schema)

            # Test 2: Query depth limit
            depth_result = self._test_query_depth(endpoint)
            if depth_result:
                findings.append(depth_result)

            # Test 3: Batch query attack
            batch_result = self._test_batch_query(endpoint)
            if batch_result:
                findings.append(batch_result)

        # Test 4: Field suggestion leak (even without introspection)
        suggestion = self._test_field_suggestions(endpoint)
        if suggestion:
            findings.append(suggestion)

        return findings

    def _test_query_depth(self, endpoint: str) -> Finding | None:
        """Test for missing query depth limits (DoS vector)."""
        # Generate deeply nested query
        query = "{ __typename " + "{ __typename " * 20 + "}" * 20 + " }"
        try:
            r = self.session.post(endpoint, json_data={"query": query})
            if r.status_code == 200 and "error" not in r.body.lower():
                return Finding(
                    title=f"GraphQL missing query depth limit — {endpoint}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    category="config",
                    description="GraphQL endpoint accepts deeply nested queries (DoS vector)",
                    mode=ScanMode.DAST,
                    endpoint=endpoint,
                    evidence="20-level deep query accepted",
                )
        except Exception:
            pass
        return None

    def _test_batch_query(self, endpoint: str) -> Finding | None:
        """Test if batch queries are allowed (amplification attack)."""
        batch = [{"query": "{ __typename }"} for _ in range(50)]
        try:
            r = self.session.post(endpoint, json_data=batch)
            if r.status_code == 200:
                results = json.loads(r.body)
                if isinstance(results, list) and len(results) >= 50:
                    return Finding(
                        title=f"GraphQL batch queries unlimited — {endpoint}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category="rate_limit",
                        description="GraphQL allows unlimited batch queries (amplification DoS)",
                        mode=ScanMode.DAST,
                        endpoint=endpoint,
                        evidence=f"Batch of 50 queries accepted in single request",
                    )
        except Exception:
            pass
        return None

    def _test_field_suggestions(self, endpoint: str) -> Finding | None:
        """Test if error messages suggest valid field names."""
        query = '{ user_DOESNOTEXIST_xyz }'
        try:
            r = self.session.post(endpoint, json_data={"query": query})
            if r.status_code in (200, 400):
                body = r.body.lower()
                if "did you mean" in body or "suggestion" in body:
                    return Finding(
                        title=f"GraphQL field suggestion leakage — {endpoint}",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        category="info_disclosure",
                        description="GraphQL error messages suggest valid field names",
                        mode=ScanMode.DAST,
                        endpoint=endpoint,
                        response_snippet=r.body[:500],
                    )
        except Exception:
            pass
        return None
