#!/usr/bin/env python3
"""
HTTP Security Header Analyzer
-------------------------------
Checks for presence and correct configuration of security headers:
  • Content-Security-Policy (CSP)
  • Strict-Transport-Security (HSTS)
  • X-Frame-Options
  • X-Content-Type-Options
  • Referrer-Policy
  • Permissions-Policy
  • X-XSS-Protection (legacy, but notable if missing/disabled)
  • Cross-Origin-Opener-Policy (COOP)
  • Cross-Origin-Resource-Policy (CORP)

References: OWASP Secure Headers Project
"""

import requests
from typing import List, Dict, Tuple
from rich.console import Console

console = Console()


# Each entry: (header_name, required, description, remediation, severity, cvss)
SECURITY_HEADERS: List[Tuple] = [
    (
        "Content-Security-Policy",
        True,
        "CSP prevents XSS and data injection attacks by controlling allowed resource sources.",
        "Add a strict CSP: 'default-src \\'self\\'; script-src \\'self\\'; object-src \\'none\\';'",
        "high",
        7.5,
    ),
    (
        "Strict-Transport-Security",
        True,
        "HSTS forces HTTPS connections and prevents SSL-stripping attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "high",
        7.5,
    ),
    (
        "X-Frame-Options",
        True,
        "Missing X-Frame-Options allows clickjacking attacks (embedding site in iframes).",
        "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors directive instead)",
        "medium",
        6.1,
    ),
    (
        "X-Content-Type-Options",
        True,
        "Missing header allows MIME-type sniffing, enabling content injection.",
        "Add: X-Content-Type-Options: nosniff",
        "low",
        3.1,
    ),
    (
        "Referrer-Policy",
        True,
        "Missing Referrer-Policy may leak sensitive URL information to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "low",
        3.1,
    ),
    (
        "Permissions-Policy",
        False,  # Not critical but notable
        "Missing Permissions-Policy allows access to powerful browser APIs (camera, mic, etc.).",
        "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "info",
        2.0,
    ),
    (
        "Cross-Origin-Opener-Policy",
        False,
        "Missing COOP allows cross-origin pages to access window references.",
        "Add: Cross-Origin-Opener-Policy: same-origin",
        "info",
        2.0,
    ),
    (
        "Cross-Origin-Resource-Policy",
        False,
        "Missing CORP allows cross-origin pages to load this site's resources.",
        "Add: Cross-Origin-Resource-Policy: same-origin",
        "info",
        2.0,
    ),
]

# Headers that, if present with bad values, are themselves a finding
BAD_HEADER_CHECKS = [
    (
        "X-Powered-By",
        "Server technology disclosure may aid attacker fingerprinting.",
        "Remove X-Powered-By header from all responses.",
        "info",
        2.0,
    ),
    (
        "Server",
        "Server version disclosure may aid attacker fingerprinting.",
        "Configure web server to omit or genericize the Server header.",
        "info",
        2.0,
    ),
    (
        "X-XSS-Protection",
        "X-XSS-Protection: 0 disables browser XSS filter (though deprecated, still notable).",
        "Remove X-XSS-Protection or set to '1; mode=block'.",
        "low",
        3.1,
    ),
]


class HeaderAnalyzer:
    """Analyse HTTP response headers for security misconfigurations."""

    def __init__(self, target: str, timeout: int = 10, session=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self._session = session  # optional authenticated session
        self.results: List[Dict] = []

    def run(self) -> List[Dict]:
        console.print(f"  [dim]-> Fetching headers from {self.target}[/dim]")
        try:
            if self._session:
                resp = self._session.get(
                    self.target,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
            else:
                import requests as _req

                resp = _req.get(
                    self.target,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "WebPwn-Toolkit/2.0"},
                )
        except Exception as e:
            console.print(f"  [red]Header check failed: {e}[/red]")
            return []

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # ── Check missing / required security headers ─────────────────
        for hdr, required, desc, fix, sev, cvss in SECURITY_HEADERS:
            if hdr.lower() not in headers_lower:
                self.results.append(
                    {
                        "url": self.target,
                        "type": f"Missing Header: {hdr}",
                        "severity": sev if required else "info",
                        "detail": desc,
                        "evidence": f"Header '{hdr}' not present in response",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "cvss": cvss if required else 2.0,
                        "remediation": fix,
                    }
                )
            else:
                val = headers_lower[hdr.lower()]
                # ── CSP quality check ──────────────────────────────────
                if hdr == "Content-Security-Policy":
                    if "unsafe-inline" in val.lower():
                        self.results.append(
                            {
                                "url": self.target,
                                "type": "Weak CSP: unsafe-inline Allowed",
                                "severity": "medium",
                                "detail": "CSP contains 'unsafe-inline' which negates XSS protection.",
                                "evidence": f"CSP: {val[:120]}",
                                "owasp": "A05:2021 – Security Misconfiguration",
                                "cvss": 5.5,
                                "remediation": "Remove 'unsafe-inline' from CSP. Use nonces or hashes instead.",
                            }
                        )
                    if "unsafe-eval" in val.lower():
                        self.results.append(
                            {
                                "url": self.target,
                                "type": "Weak CSP: unsafe-eval Allowed",
                                "severity": "medium",
                                "detail": "CSP contains 'unsafe-eval' which allows dynamic code execution.",
                                "evidence": f"CSP: {val[:120]}",
                                "owasp": "A05:2021 – Security Misconfiguration",
                                "cvss": 5.5,
                                "remediation": "Remove 'unsafe-eval' from CSP.",
                            }
                        )

                # ── HSTS max-age check ─────────────────────────────────
                if hdr == "Strict-Transport-Security":
                    import re

                    m = re.search(r"max-age\s*=\s*(\d+)", val, re.IGNORECASE)
                    if m and int(m.group(1)) < 31536000:
                        self.results.append(
                            {
                                "url": self.target,
                                "type": "Weak HSTS: max-age Too Low",
                                "severity": "low",
                                "detail": f"HSTS max-age={m.group(1)} is below recommended 31536000 (1 year).",
                                "evidence": f"HSTS: {val}",
                                "owasp": "A05:2021 – Security Misconfiguration",
                                "cvss": 3.1,
                                "remediation": "Set HSTS max-age to at least 31536000.",
                            }
                        )

        # ── Check bad/leaking headers ─────────────────────────────────
        for hdr, desc, fix, sev, cvss in BAD_HEADER_CHECKS:
            if hdr.lower() in headers_lower:
                val = headers_lower[hdr.lower()]
                # X-XSS-Protection: only flag if it's 0
                if hdr == "X-XSS-Protection" and val.strip() != "0":
                    continue
                self.results.append(
                    {
                        "url": self.target,
                        "type": f"Information Disclosure: {hdr}",
                        "severity": sev,
                        "detail": desc,
                        "evidence": f"{hdr}: {val}",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "cvss": cvss,
                        "remediation": fix,
                    }
                )

        console.print(
            f"  [dim]-> {len(resp.headers)} headers received, "
            f"{len(self.results)} issue(s) detected[/dim]"
        )
        console.print(
            f"  [{'red' if any(r['severity'] in ('critical','high') for r in self.results) else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' header issue(s) found!' if self.results else '✅ All security headers present'}"
            f"[/]"
        )
        return self.results
