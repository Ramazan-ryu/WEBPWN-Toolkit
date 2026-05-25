#!/usr/bin/env python3
"""
GraphQL Security Tester
------------------------
Tests: Introspection, Batch attacks, Alias bypass, DoS via depth,
       Field suggestion leak, Query injection, Auth bypass via fragments.
"""

import json
import requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/gql",
    "/query",
    "/api/query",
    "/v1/graphql",
    "/graphiql",
    "/playground",
]

INTROSPECTION_QUERY = {"query": "{ __schema { types { name fields { name } } } }"}

BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

DEPTH_BOMB = {
    "query": "{ a { a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } } }"
}

FIELD_SUGGESTIONS = {"query": "{ usr { nam } }"}  # Typo to trigger suggestion leak

ALIAS_BYPASS = {"query": """
    {
        a1: user(id: 1) { email }
        a2: user(id: 2) { email }
        a3: user(id: 3) { email }
        a4: user(id: 4) { email }
        a5: user(id: 5) { email }
    }
    """}

SQLI_QUERY = {"query": '{ user(id: "1 OR 1=1") { id email } }'}

AUTH_BYPASS_FRAGMENT = {"query": """
    fragment on User { email password }
    { users { ...on User { ...userFields } } }
    """}


class GraphQLTester:
    def __init__(self, target: str, session=None, timeout: int = 15):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {
                "User-Agent": "WebPwnToolkit/2.2",
                "Content-Type": "application/json",
            }
        )
        self.results: List[Dict] = []
        self.gql_url: Optional[str] = None

    def _post(self, url: str, payload) -> Optional[requests.Response]:
        try:
            return self.session.post(
                url, json=payload, timeout=self.timeout, verify=False
            )
        except Exception:
            return None

    def _discover_endpoint(self) -> Optional[str]:
        for path in GRAPHQL_PATHS:
            url = self.target + path
            resp = self._post(url, {"query": "{ __typename }"})
            if resp and resp.status_code in (200, 400):
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        console.print(f"  [green]GraphQL endpoint: {path}[/green]")
                        return url
                except Exception:
                    pass
        return None

    def _test_introspection(self, url: str) -> Optional[Dict]:
        resp = self._post(url, INTROSPECTION_QUERY)
        if not resp:
            return None
        try:
            data = resp.json()
            if "__schema" in str(data):
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                type_names = [
                    t["name"]
                    for t in types
                    if t["name"] and not t["name"].startswith("__")
                ]
                return {
                    "url": url,
                    "type": "GraphQL — Introspection Enabled",
                    "severity": "medium",
                    "cvss": 5.3,
                    "detail": (
                        f"GraphQL introspection is enabled. {len(type_names)} types exposed: "
                        f"{', '.join(type_names[:10])}"
                    ),
                    "evidence": f"Types: {type_names[:15]}",
                    "owasp": "A05:2021 – Security Misconfiguration",
                    "remediation": "Disable introspection in production. Whitelist allowed queries.",
                }
        except Exception:
            pass
        return None

    def _test_batch_attack(self, url: str) -> Optional[Dict]:
        resp = self._post(url, BATCH_QUERY)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) >= 5:
                    return {
                        "url": url,
                        "type": "GraphQL — Batch Query Attack (Rate Limit Bypass)",
                        "severity": "high",
                        "cvss": 7.5,
                        "detail": "GraphQL accepts batch queries. Attacker can send 1000s of queries in single HTTP request, bypassing rate limits.",
                        "evidence": f"Batch response: {len(data)} results",
                        "owasp": "A04:2021 – Insecure Design",
                        "remediation": "Disable batching or enforce per-query rate limits. Use query complexity analysis.",
                    }
            except Exception:
                pass
        return None

    def _test_depth_bomb(self, url: str) -> Optional[Dict]:
        import time

        t0 = time.time()
        resp = self._post(url, DEPTH_BOMB)
        elapsed = time.time() - t0
        if resp and elapsed > 3.0:
            return {
                "url": url,
                "type": "GraphQL — DoS via Deep Query (No Depth Limit)",
                "severity": "high",
                "cvss": 7.5,
                "detail": f"Deep nested query caused {elapsed:.1f}s response delay. No query depth limit enforced.",
                "evidence": f"Response time: {elapsed:.1f}s for 10-level nested query",
                "owasp": "A04:2021 – Insecure Design",
                "remediation": "Implement query depth limiting (max 5-7 levels). Use query complexity scoring.",
            }
        return None

    def _test_field_suggestion(self, url: str) -> Optional[Dict]:
        resp = self._post(url, FIELD_SUGGESTIONS)
        if resp:
            try:
                body = resp.text.lower()
                if "did you mean" in body or "suggestion" in body:
                    return {
                        "url": url,
                        "type": "GraphQL — Field Suggestion Information Leak",
                        "severity": "low",
                        "cvss": 3.7,
                        "detail": "GraphQL returns field suggestions on typos, leaking schema information even when introspection is disabled.",
                        "evidence": resp.text[:200],
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "remediation": "Disable field suggestions in production GraphQL configuration.",
                    }
            except Exception:
                pass
        return None

    def _test_alias_idor(self, url: str) -> Optional[Dict]:
        resp = self._post(url, ALIAS_BYPASS)
        if resp and resp.status_code == 200:
            try:
                data = resp.json().get("data", {})
                emails = [
                    v.get("email")
                    for v in data.values()
                    if isinstance(v, dict) and v.get("email")
                ]
                if len(emails) >= 2:
                    return {
                        "url": url,
                        "type": "GraphQL — IDOR via Alias Batching",
                        "severity": "critical",
                        "cvss": 9.1,
                        "detail": f"GraphQL aliases allow fetching multiple users in one query. {len(emails)} emails exposed.",
                        "evidence": f"Emails: {emails[:5]}",
                        "owasp": "A01:2021 – Broken Access Control",
                        "remediation": "Implement per-user authorization on all resolver fields. Check ownership on every query.",
                    }
            except Exception:
                pass
        return None

    def _test_sqli_in_query(self, url: str) -> Optional[Dict]:
        resp = self._post(url, SQLI_QUERY)
        if resp and resp.status_code == 200:
            body = resp.text.lower()
            if any(
                s in body
                for s in ["sql", "syntax error", "ora-", "mysql", "postgresql"]
            ):
                return {
                    "url": url,
                    "type": "GraphQL — SQL Injection via Query Variables",
                    "severity": "critical",
                    "cvss": 9.8,
                    "detail": "SQL error triggered via GraphQL query variable injection.",
                    "evidence": resp.text[:300],
                    "owasp": "A03:2021 – Injection",
                    "remediation": "Use parameterized queries in GraphQL resolvers. Never interpolate user input into SQL.",
                }
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ GraphQL Security Tester on {self.target}[/bold yellow]"
        )

        url = self._discover_endpoint()
        if not url:
            console.print("  [dim]No GraphQL endpoint found[/dim]")
            return []

        self.gql_url = url
        tests = [
            ("Introspection", self._test_introspection),
            ("Batch Attack", self._test_batch_attack),
            ("Depth Bomb DoS", self._test_depth_bomb),
            ("Field Suggestions", self._test_field_suggestion),
            ("Alias IDOR", self._test_alias_idor),
            ("SQLi in Query", self._test_sqli_in_query),
        ]

        for name, fn in tests:
            console.print(f"  [dim]Testing: {name}...[/dim]")
            try:
                result = fn(url)
                if result:
                    self.results.append(result)
                    console.print(f"  [bold red][!] {result['type']}[/bold red]")
            except Exception as e:
                console.print(f"  [dim]Test '{name}' error: {e}[/dim]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} GraphQL issue(s) found[/]")
        return self.results
