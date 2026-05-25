#!/usr/bin/env python3
"""
Mobile API Tester Module
-------------------------
Tests for:
  • IDOR (Insecure Direct Object Reference)
  • Missing authentication on API endpoints
  • HTTP methods (PUT/DELETE without auth)
  • Mass assignment vulnerabilities
  • Rate limiting absence
  • API versioning issues
  • Sensitive data in responses
"""

import time
import json
import requests
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Common API endpoint patterns to discover
API_ENDPOINTS = [
    # Auth
    "/api/login",
    "/api/register",
    "/api/logout",
    "/api/forgot-password",
    "/api/reset-password",
    "/api/refresh-token",
    "/api/verify",
    # Users
    "/api/user",
    "/api/users",
    "/api/users/1",
    "/api/users/2",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/v1/users",
    "/api/v1/users/1",
    "/api/v2/users",
    # Admin
    "/api/admin",
    "/api/admin/users",
    "/api/admin/settings",
    # Data
    "/api/data",
    "/api/export",
    "/api/import",
    "/api/files",
    "/api/upload",
    "/api/download",
    "/api/reports",
    "/api/logs",
    # Config
    "/api/config",
    "/api/settings",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/info",
    # Resources
    "/api/orders",
    "/api/orders/1",
    "/api/products",
    "/api/payments",
    "/api/invoices",
    "/api/invoices/1",
    # GraphQL
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
]

# HTTP methods to test on each endpoint
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# Sensitive data patterns in API responses
SENSITIVE_PATTERNS = [
    ("password", "critical", "Password field exposed in API response"),
    ("secret", "high", "Secret field exposed in API response"),
    ("token", "high", "Token exposed in API response"),
    ("api_key", "critical", "API key exposed in API response"),
    ("credit_card", "critical", "Credit card data exposed"),
    ("ssn", "critical", "Social Security Number exposed"),
    ("private_key", "critical", "Private key exposed"),
    ("access_token", "high", "Access token exposed"),
    ("refresh_token", "high", "Refresh token exposed"),
    ("auth", "medium", "Auth data in response"),
    ("internal_ip", "medium", "Internal IP address exposed"),
    ("stack_trace", "medium", "Stack trace exposed — information disclosure"),
    ("exception", "medium", "Exception details exposed"),
    ("sql", "high", "SQL query/error in response"),
    ("debug", "medium", "Debug information exposed"),
]


class APITester:
    """Mobile API security tester."""

    def __init__(
        self, base_url: str, timeout: int = 10, auth_token: Optional[str] = None
    ):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "WebPwnMobile/1.0",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        if auth_token:
            self.session.headers["Authorization"] = f"Bearer {auth_token}"
        self.results: List[Dict] = []

    # ── Endpoint discovery ─────────────────────────────────────────────

    def _discover_endpoints(self) -> List[str]:
        """Probe known API paths — return reachable ones."""
        alive = []
        for path in API_ENDPOINTS:
            url = self.base + path
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=False
                )
                if resp.status_code not in (404,):
                    alive.append(path)
            except Exception:
                pass
        console.print(f"  [dim]-> {len(alive)} API endpoint(s) reachable[/dim]")
        return alive

    # ── IDOR test ──────────────────────────────────────────────────────

    def _test_idor(self, paths: List[str]) -> List[Dict]:
        findings = []
        id_paths = [p for p in paths if p.split("/")[-1].isdigit()]

        for path in id_paths:
            base_id = int(path.split("/")[-1])
            base_path = "/".join(path.split("/")[:-1])

            # Try accessing neighboring IDs
            for test_id in [base_id + 1, base_id - 1, 0, 9999]:
                if test_id < 0:
                    continue
                test_url = self.base + base_path + f"/{test_id}"
                try:
                    resp = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data:
                                findings.append(
                                    {
                                        "url": test_url,
                                        "type": "IDOR — Insecure Direct Object Reference",
                                        "severity": "high",
                                        "detail": f"Resource ID {test_id} accessible without ownership check",
                                        "evidence": f"HTTP 200 on {test_url} — returned data: {str(data)[:80]}",
                                        "owasp": "A01:2021 – Broken Access Control",
                                        "cvss": 8.1,
                                        "remediation": (
                                            "Implement object-level authorization checks. "
                                            "Verify the authenticated user owns the requested resource. "
                                            "Use indirect references (UUIDs instead of sequential IDs)."
                                        ),
                                    }
                                )
                        except Exception:
                            pass
                except Exception:
                    pass

        return findings

    # ── Unauthenticated method test ────────────────────────────────────

    def _test_methods(self, paths: List[str]) -> List[Dict]:
        findings = []
        # Fresh session — no auth headers
        bare = requests.Session()
        bare.headers["User-Agent"] = "WebPwnMobile/1.0"

        for path in paths[:10]:  # limit to first 10 endpoints
            url = self.base + path
            for method in ["DELETE", "PUT", "PATCH"]:
                try:
                    resp = bare.request(
                        method, url, timeout=self.timeout, verify=False, json={}
                    )
                    if resp.status_code in (200, 201, 204):
                        findings.append(
                            {
                                "url": url,
                                "type": f"Unauthenticated {method} Allowed",
                                "severity": "high",
                                "detail": (
                                    f"HTTP {method} on {path} returned {resp.status_code} "
                                    f"without authentication"
                                ),
                                "evidence": f"{method} {url} -> HTTP {resp.status_code}",
                                "owasp": "A01:2021 – Broken Access Control",
                                "cvss": 8.8,
                                "remediation": (
                                    f"Require authentication for {method} operations. "
                                    "Implement proper authorization Senior ware."
                                ),
                            }
                        )
                except Exception:
                    pass

        return findings

    # ── GraphQL Introspection test ─────────────────────────────────────

    def _test_graphql(self, paths: List[str]) -> List[Dict]:
        findings = []
        graphql_paths = [
            p for p in paths if "graphql" in p.lower() or "query" in p.lower()
        ]

        introspection_query = {
            "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        types {\n          ...FullType\n        }\n      }\n    }\n    fragment FullType on __Type {\n      kind\n      name\n      fields(includeDeprecated: true) {\n        name\n      }\n    }\n  "
        }

        for path in graphql_paths:
            url = self.base + path
            try:
                resp = self.session.post(
                    url, timeout=self.timeout, verify=False, json=introspection_query
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    findings.append(
                        {
                            "url": url,
                            "type": "GraphQL Introspection Enabled",
                            "severity": "high",
                            "detail": "GraphQL endpoint allows introspection queries, exposing the entire API schema.",
                            "evidence": f"HTTP 200 | Found '__schema' in response",
                            "owasp": "A05:2021 – Security Misconfiguration",
                            "cvss": 7.3,
                            "remediation": "Disable GraphQL introspection in production environments.",
                        }
                    )
            except Exception:
                pass
        return findings

    # ── SSRF in API test ───────────────────────────────────────────────

    def _test_ssrf(self, paths: List[str]) -> List[Dict]:
        findings = []
        payloads = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]

        for path in paths[:5]:  # Limit to 5 endpoints for speed
            url = self.base + path

            for payload in payloads:
                # Test URL parameter injection
                try:
                    resp = self.session.get(
                        url,
                        params={"url": payload, "endpoint": payload},
                        timeout=self.timeout,
                        verify=False,
                    )
                    if resp.status_code == 200 and (
                        "127.0.0.1" in resp.text
                        or "ami-id" in resp.text
                        or "instance-id" in resp.text
                    ):
                        findings.append(
                            {
                                "url": url,
                                "type": "Server-Side Request Forgery (SSRF)",
                                "severity": "critical",
                                "detail": f"Endpoint reflects content from internal URL '{payload}' via parameters.",
                                "evidence": f"HTTP 200 | Content fetched from {payload}",
                                "owasp": "A10:2021 – Server-Side Request Forgery",
                                "cvss": 9.1,
                                "remediation": "Validate and sanitize all user-supplied URLs. Implement an allowlist of permitted domains.",
                            }
                        )
                        break
                except Exception:
                    pass
        return findings

    # ── Rate limiting test ─────────────────────────────────────────────

    def _test_rate_limit(self) -> Optional[Dict]:
        """Send 20 rapid requests — check if rate limiting kicks in."""
        test_url = self.base + "/api/login"
        statuses = []
        for _ in range(20):
            try:
                resp = self.session.post(
                    test_url,
                    timeout=5,
                    verify=False,
                    json={"username": "test", "password": "test"},
                )
                statuses.append(resp.status_code)
            except Exception:
                pass
            time.sleep(0.05)

        if statuses and 429 not in statuses:
            return {
                "url": test_url,
                "type": "No Rate Limiting on Login",
                "severity": "medium",
                "detail": "20 rapid login requests sent — no HTTP 429 (Too Many Requests) received",
                "evidence": f"Status codes: {set(statuses)}",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "cvss": 5.3,
                "remediation": (
                    "Implement rate limiting (e.g., max 5 requests/minute per IP). "
                    "Return HTTP 429 with Retry-After header."
                ),
            }
        return None

    # ── Sensitive data exposure ────────────────────────────────────────

    def _test_data_exposure(self, paths: List[str]) -> List[Dict]:
        findings = []
        for path in paths:
            url = self.base + path
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if resp.status_code != 200:
                    continue

                try:
                    body = resp.text.lower()
                    for keyword, severity, description in SENSITIVE_PATTERNS:
                        if f'"{keyword}"' in body or f"'{keyword}'" in body:
                            findings.append(
                                {
                                    "url": url,
                                    "type": "Sensitive Data Exposure",
                                    "severity": severity,
                                    "detail": f"{description} — field '{keyword}' found in {path}",
                                    "evidence": f"Response contains JSON key '{keyword}'",
                                    "owasp": "A02:2021 – Cryptographic Failures",
                                    "cvss": {
                                        "critical": 9.1,
                                        "high": 7.5,
                                        "medium": 5.3,
                                    }.get(severity, 5.0),
                                    "remediation": (
                                        f"Remove field '{keyword}' from API responses. "
                                        "Apply response filtering / field whitelisting."
                                    ),
                                }
                            )
                except Exception:
                    pass
            except Exception:
                pass
        return findings

    # ── SSL/TLS check ──────────────────────────────────────────────────

    def _test_ssl(self) -> List[Dict]:
        findings = []
        if not self.base.startswith("https://"):
            findings.append(
                {
                    "url": self.base,
                    "type": "API Uses HTTP (Not HTTPS)",
                    "severity": "high",
                    "detail": "API communicates over unencrypted HTTP — data in transit is exposed",
                    "evidence": f"URL scheme: http://",
                    "owasp": "M3: Insecure Communication",
                    "cvss": 7.4,
                    "remediation": "Enforce HTTPS for all API endpoints. Redirect HTTP to HTTPS.",
                }
            )
        else:
            # Test certificate validity
            try:
                requests.get(self.base, timeout=self.timeout, verify=True)
            except requests.exceptions.SSLError as e:
                findings.append(
                    {
                        "url": self.base,
                        "type": "SSL Certificate Issue",
                        "severity": "high",
                        "detail": f"SSL verification failed: {str(e)[:120]}",
                        "evidence": str(e)[:120],
                        "owasp": "M3: Insecure Communication",
                        "cvss": 7.4,
                        "remediation": (
                            "Install a valid SSL certificate from a trusted CA. "
                            "Implement certificate pinning in the mobile app."
                        ),
                    }
                )
        return findings

    # ── Mass assignment test ───────────────────────────────────────────

    def _test_mass_assignment(self, paths: List[str]) -> List[Dict]:
        findings = []
        for path in paths:
            if not any(
                x in path for x in ["/user", "/profile", "/account", "/register"]
            ):
                continue
            url = self.base + path
            # Inject privileged fields
            payload = {
                "role": "admin",
                "is_admin": True,
                "is_verified": True,
                "credits": 99999,
                "balance": 99999,
            }
            try:
                resp = self.session.post(
                    url, timeout=self.timeout, verify=False, json=payload
                )
                if resp.status_code in (200, 201):
                    body = resp.text.lower()
                    for field in payload:
                        if field in body:
                            findings.append(
                                {
                                    "url": url,
                                    "type": "Mass Assignment Vulnerability",
                                    "severity": "high",
                                    "detail": (
                                        f"Field '{field}' echoed back in response — "
                                        "server may accept mass-assigned privileged fields"
                                    ),
                                    "evidence": f"POST payload with '{field}' reflected in HTTP {resp.status_code}",
                                    "owasp": "A08:2021 – Software and Data Integrity Failures",
                                    "cvss": 8.6,
                                    "remediation": (
                                        "Use allowlisting for accepted fields. "
                                        "Never bind request body directly to model. "
                                        "Explicitly define which fields users can modify."
                                    ),
                                }
                            )
                            break
            except Exception:
                pass
        return findings

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print("  [dim]-> Discovering API endpoints...[/dim]")
        paths = self._discover_endpoints()

        if not paths:
            console.print("  [yellow]No reachable API endpoints found.[/yellow]")
            return []

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Testing API security...[/cyan]"),
            console=console,
        ) as progress:
            progress.add_task("api", total=None)

            console.print("  [dim]-> Testing IDOR...[/dim]")
            self.results.extend(self._test_idor(paths))

            console.print("  [dim]-> Testing unauthenticated methods...[/dim]")
            self.results.extend(self._test_methods(paths))

            console.print("  [dim]-> Testing rate limiting...[/dim]")
            rl = self._test_rate_limit()
            if rl:
                self.results.append(rl)

            console.print("  [dim]-> Testing sensitive data exposure...[/dim]")
            self.results.extend(self._test_data_exposure(paths))

            console.print("  [dim]-> Testing SSL/TLS...[/dim]")
            self.results.extend(self._test_ssl())

            console.print("  [dim]-> Testing mass assignment...[/dim]")
            self.results.extend(self._test_mass_assignment(paths))

            console.print("  [dim]-> Testing GraphQL...[/dim]")
            self.results.extend(self._test_graphql(paths))

            console.print("  [dim]-> Testing SSRF...[/dim]")
            self.results.extend(self._test_ssrf(paths))

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' API issue(s) found!' if self.results else '✅ No API issues found'}"
            f"[/]"
        )
        return self.results
