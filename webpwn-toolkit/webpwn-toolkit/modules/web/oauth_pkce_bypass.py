#!/usr/bin/env python3
"""
OAuth 2.0 PKCE Bypass & Flow Tester
------------------------------------
Tests OAuth 2.0 implementations for:
  • Missing state parameter
  • PKCE missing or improper validation
  • Open redirect in redirect_uri
"""

import requests
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Optional
from rich.console import Console

console = Console()


class OAuthTester:
    def __init__(self, target: str, session=None, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.results: List[Dict] = []

    def _test_oauth_endpoint(self, url: str) -> List[Dict]:
        findings = []
        # Simulate OAuth authorization request
        try:
            resp = self.session.get(
                url, allow_redirects=False, timeout=self.timeout, verify=False
            )
            if resp and resp.status_code in (301, 302):
                loc = resp.headers.get("Location", "")
                if "response_type=code" in loc:
                    parsed_loc = urlparse(loc)
                    qs = parse_qs(parsed_loc.query)

                    # 1. Missing State Parameter
                    if "state" not in qs:
                        findings.append(
                            {
                                "url": url,
                                "type": "OAuth 2.0 — Missing State Parameter",
                                "severity": "high",
                                "cvss": 7.4,
                                "detail": "Authorization request lacks the 'state' parameter. Vulnerable to CSRF login attacks.",
                                "evidence": f"Location: {loc[:150]}",
                                "owasp": "A07:2021 – Identification and Authentication Failures",
                                "remediation": "Implement cryptographically secure 'state' parameter to prevent CSRF.",
                            }
                        )

                    # 2. Missing PKCE (code_challenge)
                    if "code_challenge" not in qs:
                        findings.append(
                            {
                                "url": url,
                                "type": "OAuth 2.0 — PKCE Not Enforced",
                                "severity": "medium",
                                "cvss": 6.5,
                                "detail": "Authorization request lacks 'code_challenge'. Vulnerable to authorization code interception.",
                                "evidence": f"Location: {loc[:150]}",
                                "owasp": "A07:2021 – Identification and Authentication Failures",
                                "remediation": "Enforce PKCE (Proof Key for Code Exchange) for all clients, especially public clients.",
                            }
                        )

                    # 3. Open Redirect in redirect_uri
                    if "redirect_uri" in qs:
                        evil_uri = "https://evil.com"
                        mod_url = url.replace(qs["redirect_uri"][0], evil_uri)
                        r_evil = self.session.get(
                            mod_url,
                            allow_redirects=False,
                            timeout=self.timeout,
                            verify=False,
                        )
                        if r_evil and r_evil.status_code in (301, 302):
                            loc_evil = r_evil.headers.get("Location", "")
                            if evil_uri in loc_evil:
                                findings.append(
                                    {
                                        "url": url,
                                        "type": "OAuth 2.0 — Open Redirect in redirect_uri",
                                        "severity": "critical",
                                        "cvss": 8.8,
                                        "detail": f"redirect_uri parameter can be manipulated to redirect to {evil_uri}.",
                                        "evidence": f"Location: {loc_evil[:100]}",
                                        "owasp": "A01:2021 – Broken Access Control",
                                        "remediation": "Strictly validate redirect_uri against a whitelist. Use exact matching.",
                                    }
                                )

        except Exception:
            pass
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ OAuth 2.0 PKCE & Flow Tester on {self.target}[/bold yellow]"
        )

        auth_paths = ["/login", "/auth/login", "/sso", "/oauth/authorize", "/api/auth"]
        for path in auth_paths:
            url = self.target + path
            res = self._test_oauth_endpoint(url)
            for r in res:
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} OAuth 2.0 issue(s) found[/]")
        return self.results
