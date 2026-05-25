#!/usr/bin/env python3
"""
Open Redirect Scanner
-----------------------
Tests for open redirect vulnerabilities via:
  • GET parameter injection (next, redirect, url, to, goto, return, etc.)
  • Header-based redirects
  • Double-slash, protocol-relative, and encoded bypass payloads
  • JavaScript-scheme redirects
"""

import requests
import concurrent.futures
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Common parameter names susceptible to open redirect
REDIRECT_PARAMS = [
    "next",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "uri",
    "return",
    "return_url",
    "returnUrl",
    "to",
    "goto",
    "go",
    "dest",
    "destination",
    "target",
    "link",
    "location",
    "forward",
    "continue",
    "success",
    "cancel",
    "callback",
    "ref",
    "redir",
    "jump",
    "out",
    "view",
]

# Redirect test targets
REDIRECT_TARGETS = [
    "https://evil.example.com",
    "//evil.example.com",
    "//evil.example.com/",
    "///evil.example.com",
    "/////evil.example.com",
    "https:evil.example.com",
    "https:/evil.example.com",
    "https;://evil.example.com",
    "javascript://evil.example.com/%0aalert(1)",
    "//google.com/%09/evil.example.com",
    "/%09/evil.example.com",
    "//evil%E3%80%82example%E3%80%82com",
    "%2F%2Fevil.example.com",
    "%2Fevil.example.com",
    "\\\\evil.example.com",
    "http://evil.example.com",
    "HTTP://evil.example.com",
    "http:///evil.example.com",
    "//0177.0.0.1",  # Octal encoding bypass
    "https://evil.example.com@trusted.com",
]

EVIL_DOMAIN = "evil.example.com"


class OpenRedirectScanner:
    """Open redirect vulnerability scanner."""

    def __init__(self, target: str, threads: int = 10, timeout: int = 8):
        self.target = target.rstrip("/")
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebPwnToolkit/1.0 (Security Assessment)"
        self.results: List[Dict] = []

    # ── Detect redirect to evil domain ─────────────────────────────────

    def _is_open_redirect(self, resp: requests.Response) -> Optional[str]:
        """Check if response redirects to an external (evil) domain."""
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if EVIL_DOMAIN in location or "evil.example.com" in location:
                return location

        # Meta refresh redirect
        if "<meta" in resp.text.lower() and "refresh" in resp.text.lower():
            try:
                soup = BeautifulSoup(resp.text, "lxml")
                meta = soup.find(
                    "meta", attrs={"http-equiv": lambda v: v and "refresh" in v.lower()}
                )
                if meta:
                    content = meta.get("content", "")
                    if EVIL_DOMAIN in content:
                        return f"meta-refresh: {content}"
            except Exception:
                pass

        return None

    # ── Test a single param + payload ──────────────────────────────────

    def _test_redirect(self, base_url: str, param: str, payload: str) -> Optional[Dict]:
        try:
            resp = self.session.get(
                base_url,
                params={param: payload},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,  # Don't follow — capture Location header directly
            )
            location = self._is_open_redirect(resp)
            if location:
                severity = "high"
                # JavaScript redirect is higher risk
                if payload.startswith("javascript"):
                    severity = "critical"

                return {
                    "url": base_url,
                    "method": "GET",
                    "parameter": param,
                    "payload": payload,
                    "type": "Open Redirect",
                    "severity": severity,
                    "evidence": f"Location: {location[:100]}",
                    "detail": (
                        f"Open redirect via '{param}' parameter — "
                        f"server redirected to: {location[:80]}"
                    ),
                    "owasp": "A01:2021 – Broken Access Control",
                    "cvss": 6.1,
                    "remediation": (
                        "Validate redirect URLs against a strict whitelist of allowed hosts. "
                        "Never use user-controlled data in redirect Location headers. "
                        "Use relative paths instead of absolute URLs for internal redirects."
                    ),
                }
        except Exception:
            pass
        return None

    # ── Collect candidate URLs from forms + crawl ──────────────────────

    def _collect_redirect_endpoints(self) -> List[Dict]:
        """Find all URLs + params that look like redirect candidates."""
        endpoints = []

        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "lxml")

            # Links with redirect-like params
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                parsed = urlparse(urljoin(self.target, href))
                qs = parse_qs(parsed.query)
                for p in qs:
                    if p.lower() in [r.lower() for r in REDIRECT_PARAMS]:
                        endpoints.append(
                            {
                                "url": urljoin(self.target, href).split("?")[0],
                                "param": p,
                            }
                        )

            # Forms
            for form in soup.find_all("form"):
                action = urljoin(self.target, form.get("action", ""))
                for inp in form.find_all(["input", "hidden"]):
                    name = inp.get("name", "")
                    if name.lower() in [r.lower() for r in REDIRECT_PARAMS]:
                        endpoints.append({"url": action, "param": name})
        except Exception:
            pass

        # Also test all standard redirect params on the base target
        for param in REDIRECT_PARAMS:
            endpoints.append({"url": self.target, "param": param})

        # Deduplicate
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep["url"], ep["param"])
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        endpoints = self._collect_redirect_endpoints()
        console.print(
            f"  [dim]-> {len(endpoints)} redirect-candidate endpoint(s) | "
            f"{len(REDIRECT_TARGETS)} payloads[/dim]"
        )

        all_tests = [
            (ep["url"], ep["param"], payload)
            for ep in endpoints
            for payload in REDIRECT_TARGETS
        ]

        # Track seen (url, param) pairs to avoid hundreds of duplicate findings
        seen_params: set = set()

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Open Redirect scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("redirect", total=len(all_tests))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {
                    ex.submit(self._test_redirect, url, param, payload): (
                        url,
                        param,
                        payload,
                    )
                    for url, param, payload in all_tests
                }
                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result:
                        # Deduplicate: one finding per (url, param) pair
                        dedup_key = (result.get("url", ""), result.get("parameter", ""))
                        if dedup_key not in seen_params:
                            seen_params.add(dedup_key)
                            self.results.append(result)

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' Open Redirect(s) found!' if self.results else '✅ No Open Redirects found'}"
            f"[/]"
        )
        return self.results
