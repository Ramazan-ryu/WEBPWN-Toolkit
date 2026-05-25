#!/usr/bin/env python3
"""
Cookie Security Checker
-------------------------
Inspects all cookies set by the target for security misconfigurations:
  • Missing HttpOnly flag (JavaScript can read session cookies)
  • Missing Secure flag (cookie sent over plain HTTP)
  • Missing SameSite attribute (CSRF risk)
  • SameSite=None without Secure (browser will reject, but still notable)
  • Session cookie with very long expiry (persistent instead of session cookie)
  • Predictable/weak cookie names indicating plain session IDs
  • Sensitive data in cookie values (base64-encoded JSON, JWT fragments)

OWASP: A02:2021 – Cryptographic Failures / A05:2021 – Security Misconfiguration
"""

import re
import base64
import json
import requests
from datetime import datetime
from typing import List, Dict
from rich.console import Console

console = Console()


class CookieChecker:
    """Check all cookies returned by the target for security flags."""

    SENSITIVE_PATTERNS = [
        (re.compile(r"eyJ[A-Za-z0-9_-]+\\.eyJ"), "JWT token fragment in cookie value"),
        (re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"), "Possible base64-encoded data"),
        (
            re.compile(r"\b(password|passwd|pwd|secret|token|key)\b", re.IGNORECASE),
            "Sensitive keyword in cookie value",
        ),
    ]

    WEAK_NAMES = {
        "PHPSESSID",
        "JSESSIONID",
        "ASP.NET_SessionId",
        "sessionid",
        "session",
        "sid",
        "auth",
        "token",
        "user_id",
    }

    def __init__(self, target: str, timeout: int = 10, session=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self._session = session
        self.results: List[Dict] = []

    def _analyze_cookie(self, cookie: requests.cookies.RequestsCookieJar) -> List[Dict]:
        """Analyze a single cookie object for security attributes."""
        findings = []
        name = cookie.name
        value = cookie.value or ""
        domain = cookie.domain or self.target

        base_info = {
            "url": self.target,
            "location": f"Cookie: {name}",
            "owasp": "A02:2021 – Cryptographic Failures",
        }

        # ── HttpOnly ───────────────────────────────────────────────────
        if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(
            cookie, "_rest", {}
        ).get("HttpOnly"):
            findings.append(
                {
                    **base_info,
                    "type": f"Cookie Missing HttpOnly: {name}",
                    "severity": "medium",
                    "detail": f"Cookie '{name}' lacks HttpOnly flag — readable by JavaScript, enabling XSS-based session theft.",
                    "evidence": f"Set-Cookie: {name}=... (no HttpOnly)",
                    "cvss": 5.4,
                    "remediation": f"Set HttpOnly attribute: Set-Cookie: {name}=...; HttpOnly",
                }
            )

        # ── Secure ─────────────────────────────────────────────────────
        if not cookie.secure:
            findings.append(
                {
                    **base_info,
                    "type": f"Cookie Missing Secure Flag: {name}",
                    "severity": "medium",
                    "detail": f"Cookie '{name}' lacks Secure flag — transmitted over HTTP, vulnerable to interception.",
                    "evidence": f"Set-Cookie: {name}=... (no Secure)",
                    "cvss": 5.4,
                    "remediation": f"Set Secure attribute: Set-Cookie: {name}=...; Secure",
                }
            )

        # ── SameSite ────────────────────────────────────────────────────
        rest = getattr(cookie, "_rest", {})
        samesite = rest.get("SameSite") or rest.get("samesite", "")
        if not samesite:
            findings.append(
                {
                    **base_info,
                    "type": f"Cookie Missing SameSite: {name}",
                    "severity": "medium",
                    "detail": f"Cookie '{name}' has no SameSite attribute — CSRF attacks may succeed.",
                    "evidence": f"Set-Cookie: {name}=... (no SameSite)",
                    "cvss": 4.3,
                    "remediation": f"Add SameSite=Lax or SameSite=Strict: Set-Cookie: {name}=...; SameSite=Strict",
                }
            )
        elif samesite.lower() == "none" and not cookie.secure:
            findings.append(
                {
                    **base_info,
                    "type": f"Cookie SameSite=None Without Secure: {name}",
                    "severity": "medium",
                    "detail": f"SameSite=None requires Secure flag but it is missing.",
                    "evidence": f"SameSite=None; (no Secure)",
                    "cvss": 4.3,
                    "remediation": "Add Secure flag when using SameSite=None.",
                }
            )

        # ── Long-lived session cookie ───────────────────────────────────
        if cookie.expires:
            try:
                expiry_dt = datetime.utcfromtimestamp(cookie.expires)
                days_left = (expiry_dt - datetime.utcnow()).days
                if days_left > 30 and name.upper() in self.WEAK_NAMES:
                    findings.append(
                        {
                            **base_info,
                            "type": f"Persistent Session Cookie: {name}",
                            "severity": "low",
                            "detail": f"Session cookie '{name}' persists for {days_left} days — session hijacking window is very long.",
                            "evidence": f"Expires: {expiry_dt.strftime('%Y-%m-%d')} ({days_left} days)",
                            "cvss": 3.7,
                            "remediation": "Use session-only cookies (no Expires/Max-Age) for authentication tokens.",
                        }
                    )
            except Exception:
                pass

        # ── Sensitive data in value ─────────────────────────────────────
        for pattern, desc in self.SENSITIVE_PATTERNS:
            if pattern.search(value):
                # Attempt to decode base64 → check if JSON
                preview = value[:60] + ("..." if len(value) > 60 else "")
                findings.append(
                    {
                        **base_info,
                        "type": f"Sensitive Data in Cookie: {name}",
                        "severity": "low",
                        "detail": f"{desc} detected in cookie '{name}' value.",
                        "evidence": f"{name}={preview}",
                        "cvss": 3.1,
                        "remediation": "Never store sensitive data directly in cookie values. Use server-side sessions.",
                    }
                )
                break  # one finding per cookie for value issues

        return findings

    def run(self) -> List[Dict]:
        console.print(f"  [dim]-> Requesting cookies from {self.target}[/dim]")
        try:
            if self._session:
                resp = self._session.get(
                    self.target,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
            else:
                resp = requests.get(
                    self.target,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "WebPwn-Toolkit/2.0"},
                )
        except Exception as e:
            console.print(f"  [red]Cookie check failed: {e}[/red]")
            return []

        cookies = list(resp.cookies)
        console.print(f"  [dim]-> {len(cookies)} cookie(s) received[/dim]")

        if not cookies:
            console.print("  [dim]-> No cookies to analyze[/dim]")
            return []

        for cookie in cookies:
            self.results.extend(self._analyze_cookie(cookie))

        console.print(
            f"  [{'red' if any(r['severity'] in ('critical','high') for r in self.results) else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' cookie issue(s) found!' if self.results else '✅ All cookies appear secure'}"
            f"[/]"
        )
        return self.results
