#!/usr/bin/env python3
"""
CRLF Injection Scanner
------------------------
Tests for HTTP Response Splitting via \r\n injection in:
  • URL parameters, path segments, headers
  • Redirect destinations
  • Cookie values
"""

import requests
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

CRLF_PAYLOADS = [
    "%0d%0aX-CRLF-Injected: webpwn",
    "%0aX-CRLF-Injected: webpwn",
    "%0dX-CRLF-Injected: webpwn",
    "\r\nX-CRLF-Injected: webpwn",
    "%E5%98%8D%E5%98%8AX-CRLF-Injected: webpwn",
    "%0d%0a%20X-CRLF-Injected: webpwn",
    "%0d%0aSet-Cookie: crlfinjected=1",
    "%0d%0aLocation: https://evil.com",
    "crlf%0d%0aX-CRLF-Injected: webpwn",
    "crlf%250d%250aX-CRLF-Injected: webpwn",  # double-encoded
    "%09%0d%0aX-CRLF-Injected: webpwn",
    "\r\n\t X-CRLF-Injected: webpwn",
]

REDIRECT_PARAMS = [
    "url",
    "redirect",
    "next",
    "return",
    "redir",
    "location",
    "redirect_uri",
    "redirect_url",
    "return_url",
    "goto",
    "target",
]


class CRLFScanner:
    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []

    def _get(
        self, url: str, params: dict = None, allow_redirects: bool = False
    ) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                verify=False,
                allow_redirects=allow_redirects,
            )
        except Exception:
            return None

    def _check_injected(self, resp: requests.Response) -> bool:
        """Check if our canary header appears in response headers."""
        return "x-crlf-injected" in {k.lower() for k in resp.headers}

    def _test_param(self, url: str, param: str, payload: str) -> Optional[Dict]:
        resp = self._get(url, params={param: payload})
        if not resp:
            return None
        if self._check_injected(resp):
            return {
                "url": url,
                "type": "CRLF Injection — Header Injection via Parameter",
                "severity": "high",
                "cvss": 7.2,
                "parameter": param,
                "payload": payload,
                "detail": (
                    f"CRLF sequence in parameter '{param}' injected custom header "
                    f"'X-CRLF-Injected' into HTTP response. Enables response splitting, "
                    f"XSS via Set-Cookie, and cache poisoning."
                ),
                "evidence": f"X-CRLF-Injected header found in response headers",
                "owasp": "A03:2021 – Injection",
                "remediation": (
                    "Strip \\r and \\n from all values used in HTTP headers and redirects. "
                    "Use allowlist validation. Never reflect user input into Location or Set-Cookie."
                ),
            }
        # Check if Location header contains our injection
        loc = resp.headers.get("Location", "")
        if "X-CRLF-Injected" in loc or "crlfinjected" in loc.lower():
            return {
                "url": url,
                "type": "CRLF Injection — Open Redirect + Header Injection",
                "severity": "critical",
                "cvss": 8.8,
                "parameter": param,
                "payload": payload,
                "detail": f"CRLF injection in redirect Location header via param '{param}'.",
                "evidence": f"Location: {loc[:200]}",
                "owasp": "A03:2021 – Injection",
                "remediation": "Sanitize all redirect values. Never write raw user input to Location header.",
            }
        return None

    def _test_path_crlf(self) -> List[Dict]:
        findings = []
        for payload in CRLF_PAYLOADS[:6]:
            try:
                url = f"{self.target}/{payload}"
                resp = self.session.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=False
                )
                if resp and self._check_injected(resp):
                    findings.append(
                        {
                            "url": url,
                            "type": "CRLF Injection — Path Segment Injection",
                            "severity": "high",
                            "cvss": 7.2,
                            "payload": payload,
                            "detail": "CRLF in URL path segment injected custom header into response.",
                            "evidence": "X-CRLF-Injected header present",
                            "owasp": "A03:2021 – Injection",
                            "remediation": "URL-decode and sanitize path segments before processing.",
                        }
                    )
                    break
            except Exception:
                pass
        return findings

    def _test_redirect_params(self) -> List[Dict]:
        findings = []
        for param in REDIRECT_PARAMS:
            for payload in CRLF_PAYLOADS[:4]:
                test = f"https://evil.com{payload}"
                resp = self._get(
                    self.target, params={param: test}, allow_redirects=False
                )
                if not resp:
                    continue
                if self._check_injected(resp):
                    findings.append(
                        {
                            "url": self.target,
                            "type": f"CRLF Injection — Redirect Param '{param}'",
                            "severity": "critical",
                            "cvss": 8.2,
                            "parameter": param,
                            "payload": test,
                            "detail": f"Redirect parameter '{param}' allows CRLF header injection.",
                            "evidence": "X-CRLF-Injected found in response",
                            "owasp": "A03:2021 – Injection",
                            "remediation": "Validate redirect targets against allowlist. Strip CRLF chars.",
                        }
                    )
                    break
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ CRLF Injection Scanner on {self.target}[/bold yellow]"
        )

        # Test common parameters
        common_params = ["q", "search", "id", "name", "page", "lang", "ref", "source"]
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]CRLF scanning...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task(
                "crlf", total=len(CRLF_PAYLOADS) * len(common_params) + 2
            )
            for param in common_params:
                for payload in CRLF_PAYLOADS:
                    prog.advance(task)
                    r = self._test_param(self.target, param, payload)
                    if r and r not in self.results:
                        self.results.append(r)
                        console.print(f"  [bold red][!] {r['type']}[/bold red]")

            prog.advance(task)
            self.results.extend(self._test_path_crlf())
            prog.advance(task)
            self.results.extend(self._test_redirect_params())

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} CRLF issue(s) found[/]")
        return self.results
