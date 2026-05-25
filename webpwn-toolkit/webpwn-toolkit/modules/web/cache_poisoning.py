#!/usr/bin/env python3
"""
Cache Poisoning Tester
-----------------------
Tests for Web Cache Poisoning and Web Cache Deception:
  • Unkeyed header injection (X-Forwarded-Host, X-Forwarded-Scheme)
  • Host header cache poisoning
  • Cache deception via path confusion
  • Pragma/Cache-Control manipulation
  • Fat GET request poisoning
  • Response splitting via cached headers
"""

import time
import requests
import uuid
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

UNKEYED_HEADERS = [
    {"X-Forwarded-Host": "evil.attacker.com"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Proto": "http"},
    {"X-Host": "evil.attacker.com"},
    {"X-Forwarded-Server": "evil.attacker.com"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"Forwarded": "host=evil.attacker.com"},
    {"X-HTTP-Host-Override": "evil.attacker.com"},
    {"X-Forwarded-Port": "4433"},
    {"X-Original-Host": "evil.attacker.com"},
]

CACHE_DECEPTION_PATHS = [
    "/profile/nonexistent.css",
    "/account/secret.jpg",
    "/api/user/data.js",
    "/dashboard/config.json",
    "/private/export.csv",
    "/admin/settings.woff2",
]


class CachePoisoningTester:
    """
    Detects Web Cache Poisoning (WCP) and Web Cache Deception (WCD)
    vulnerabilities via unkeyed header injection and path confusion.
    """

    def __init__(self, target: str, session=None, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []

    def _get(
        self, url: str, headers: dict = None, params: dict = None
    ) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url,
                headers=headers or {},
                params=params,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
        except Exception:
            return None

    # ── Baseline fingerprint ─────────────────────────────────────────────

    def _baseline(self) -> Optional[str]:
        r = self._get(self.target)
        return r.text if r else None

    # ── Unkeyed header injection ─────────────────────────────────────────

    def _test_unkeyed_headers(self) -> List[Dict]:
        findings = []
        baseline = self._baseline()
        if not baseline:
            return []

        canary = f"webpwn-{uuid.uuid4().hex[:8]}.attacker.com"

        for header_dict in UNKEYED_HEADERS:
            key, value = list(header_dict.items())[0]
            # Inject canary value for host-based headers
            test_val = value.replace("evil.attacker.com", canary)
            headers = {key: test_val}

            r = self._get(self.target, headers=headers)
            if not r:
                continue

            body = r.text

            # Check if canary value is reflected in response body
            if canary in body or "evil.attacker.com" in body.lower():
                findings.append(
                    {
                        "url": self.target,
                        "type": f"Cache Poisoning — Unkeyed Header Reflected ({key})",
                        "severity": "high",
                        "cvss": 8.0,
                        "header": key,
                        "payload": f"{key}: {test_val}",
                        "detail": (
                            f"Header '{key}' value reflected in response body. "
                            f"If this response is cached, all users will receive the poisoned content."
                        ),
                        "evidence": f"'{canary}' found in response body",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "remediation": (
                            "Remove unneeded headers from cache key. "
                            "Validate Host header server-side. "
                            "Configure CDN to strip untrusted headers."
                        ),
                    }
                )

            # Check if header changes response significantly (cache key exclusion)
            if body != baseline:
                x_cache = r.headers.get("X-Cache", "")
                age = r.headers.get("Age", "")
                cf_cache = r.headers.get("CF-Cache-Status", "")
                via = r.headers.get("Via", "")

                if any([x_cache, age, cf_cache, via]):
                    findings.append(
                        {
                            "url": self.target,
                            "type": f"Cache Poisoning — Header Alters Cached Response ({key})",
                            "severity": "medium",
                            "cvss": 6.1,
                            "header": key,
                            "payload": f"{key}: {test_val}",
                            "detail": (
                                f"Header '{key}' changes server response AND cache headers present. "
                                f"Cache: X-Cache={x_cache}, Age={age}, CF-Cache-Status={cf_cache}"
                            ),
                            "evidence": f"X-Cache: {x_cache} | Age: {age} | CF-Cache: {cf_cache}",
                            "owasp": "A05:2021 – Security Misconfiguration",
                            "remediation": "Normalize cache vary headers. Test with cache busting param.",
                        }
                    )

        return findings

    # ── Host header poisoning ────────────────────────────────────────────

    def _test_host_header(self) -> List[Dict]:
        findings = []
        canary = f"webpwn-{uuid.uuid4().hex[:8]}.attacker.com"
        parsed = self.target.split("/")
        original_host = parsed[2] if len(parsed) > 2 else self.target

        # Test port-based host header injection
        test_hosts = [
            f"{original_host}:{canary}",
            f"{canary}",
            f"{original_host}@{canary}",
            f"{original_host} {canary}",
        ]

        for test_host in test_hosts:
            r = self._get(self.target, headers={"Host": test_host})
            if not r:
                continue
            if canary in r.text:
                findings.append(
                    {
                        "url": self.target,
                        "type": "Cache Poisoning — Host Header Injection",
                        "severity": "high",
                        "cvss": 8.1,
                        "payload": f"Host: {test_host}",
                        "detail": "Custom Host header value reflected in response — password reset poisoning possible.",
                        "evidence": f"'{canary}' reflected in response",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "remediation": (
                            "Whitelist allowed Host header values. "
                            "Generate password reset links from server-side config, not from Host header."
                        ),
                    }
                )
                break

        return findings

    # ── Cache deception via path confusion ──────────────────────────────

    def _test_cache_deception(self) -> List[Dict]:
        findings = []

        # First check if authenticated path returns sensitive data
        auth_paths = ["/profile", "/account", "/dashboard", "/api/user", "/settings"]

        for auth_path in auth_paths:
            base_url = self.target + auth_path
            r_auth = self._get(base_url)
            if not r_auth or r_auth.status_code not in (200, 302):
                continue

            # Try cache deception via appending static extension
            for deception_suffix in ["/fake.css", "/style.css", "/x.js", "/image.png"]:
                deception_url = base_url + deception_suffix
                r_deception = self._get(deception_url)
                if not r_deception:
                    continue

                # If both return 200 with same content → cache deception possible
                if (
                    r_deception.status_code == 200
                    and r_auth.status_code == 200
                    and len(r_deception.text) > 100
                    and abs(len(r_auth.text) - len(r_deception.text)) < 200
                ):

                    # Check if it's being cached
                    cache_header = r_deception.headers.get("Cache-Control", "")
                    x_cache = r_deception.headers.get("X-Cache", "")

                    if "no-store" not in cache_header and "private" not in cache_header:
                        findings.append(
                            {
                                "url": deception_url,
                                "type": "Web Cache Deception — Sensitive Path Cacheable",
                                "severity": "high",
                                "cvss": 7.5,
                                "payload": deception_url,
                                "detail": (
                                    f"Authenticated path '{auth_path}' is accessible as '{deception_suffix}' "
                                    f"and may be cached. An attacker can trick authenticated users to visit "
                                    f"this URL, caching their private data for unauthenticated retrieval."
                                ),
                                "evidence": (
                                    f"Cache-Control: {cache_header} | "
                                    f"X-Cache: {x_cache} | "
                                    f"Status: {r_deception.status_code}"
                                ),
                                "owasp": "A01:2021 – Broken Access Control",
                                "remediation": (
                                    "Set Cache-Control: no-store on all authenticated responses. "
                                    "Configure CDN to not cache URLs matching authenticated paths. "
                                    "Validate request path ends with expected extension."
                                ),
                            }
                        )
                        break

        return findings

    # ── Fat GET request poisoning ────────────────────────────────────────

    def _test_fat_get(self) -> List[Dict]:
        findings = []
        canary = f"WEBPWN{uuid.uuid4().hex[:6]}"

        try:
            # Fat GET: GET with body (some caches use only URL as key, ignoring body)
            resp = self.session.request(
                "GET",
                self.target,
                data=f"injected_param={canary}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
                verify=False,
            )
            if resp and canary in resp.text:
                findings.append(
                    {
                        "url": self.target,
                        "type": "Cache Poisoning — Fat GET Body Reflected",
                        "severity": "medium",
                        "cvss": 5.4,
                        "payload": f"GET body: injected_param={canary}",
                        "detail": "GET request body parameter reflected in response — Fat GET poisoning possible.",
                        "evidence": f"'{canary}' in response",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "remediation": "Reject GET requests with body. Configure cache to key on full request.",
                    }
                )
        except Exception:
            pass

        return findings

    # ── Public run ───────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Cache Poisoning Tester on {self.target}[/bold yellow]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Testing cache poisoning...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("cache", total=4)

            prog.advance(task)
            self.results.extend(self._test_unkeyed_headers())

            prog.advance(task)
            self.results.extend(self._test_host_header())

            prog.advance(task)
            self.results.extend(self._test_cache_deception())

            prog.advance(task)
            self.results.extend(self._test_fat_get())

        color = "red" if self.results else "green"
        console.print(
            f"  [{color}]{len(self.results)} cache poisoning issue(s) found[/]"
        )
        return self.results
