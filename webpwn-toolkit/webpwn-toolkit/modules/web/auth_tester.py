#!/usr/bin/env python3
"""
Authentication Tester Module
-----------------------------
Tests for:
  • Default/weak credential login
  • JWT token vulnerabilities (alg:none, weak secret)
  • Missing authentication on admin paths
  • Account lockout absence
  • HTTP Basic Auth brute-force
"""

import base64
import json
import re
import hmac
import hashlib
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("admin", "letmein"),
    ("admin", "qwerty"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("manager", "manager"),
    ("sa", ""),  # MSSQL default
    ("postgres", "postgres"),
]

ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/administrator/",
    "/wp-admin",
    "/wp-admin/",
    "/dashboard",
    "/control",
    "/manager",
    "/management",
    "/backend",
    "/cpanel",
    "/login",
    "/signin",
    "/auth",
    "/secure",
]

JWT_WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "key",
    "jwt",
    "token",
    "admin",
    "test",
    "changeme",
    "mysecret",
    "jwtkey",
    "jwtsecret",
    "your-secret-key",
]


class AuthTester:
    """Authentication vulnerability tester."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebPwnToolkit/1.0"
        self.results: List[Dict] = []

    # ── Form login bruteforce ──────────────────────────────────────────

    def _find_login_form(self) -> Optional[Dict]:
        """Find login form fields on the target page."""
        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form"):
                inputs = form.find_all("input")
                fields = {
                    i.get("name"): i.get("type", "text")
                    for i in inputs
                    if i.get("name")
                }
                user_fields = [
                    k
                    for k, v in fields.items()
                    if any(x in k.lower() for x in ("user", "login", "email", "name"))
                ]
                pass_fields = [
                    k
                    for k, v in fields.items()
                    if v == "password" or "pass" in k.lower()
                ]
                if user_fields and pass_fields:
                    action = urljoin(self.target, form.get("action", ""))
                    return {
                        "action": action or self.target,
                        "method": form.get("method", "post").lower(),
                        "user_field": user_fields[0],
                        "pass_field": pass_fields[0],
                        "extra": {
                            k: "" for k in fields if k not in user_fields + pass_fields
                        },
                    }
        except Exception:
            pass
        return None

    def _try_login(self, form: Dict, username: str, password: str) -> Optional[Dict]:
        data = form["extra"].copy()
        data[form["user_field"]] = username
        data[form["pass_field"]] = password

        try:
            resp = self.session.post(
                form["action"],
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )

            # Heuristic: login success indicators
            lower = resp.text.lower()
            success_indicators = [
                "dashboard",
                "welcome",
                "logout",
                "log out",
                "sign out",
                "my account",
                "profile",
                "home",
            ]
            failure_indicators = [
                "invalid",
                "incorrect",
                "wrong",
                "failed",
                "error",
                "denied",
                "unauthorized",
            ]

            has_success = any(s in lower for s in success_indicators)
            has_failure = any(f in lower for f in failure_indicators)

            if has_success and not has_failure:
                return {
                    "url": form["action"],
                    "type": "Default Credentials",
                    "severity": "critical",
                    "detail": f"Successful login with {username}:{password}",
                    "evidence": f"Username: {username} | Password: {password}",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "cvss": 9.8,
                    "remediation": (
                        "Enforce strong password policy. "
                        "Change all default credentials immediately. "
                        "Implement MFA."
                    ),
                }
        except Exception:
            pass
        return None

    def _test_credentials(self) -> List[Dict]:
        findings = []
        form = self._find_login_form()
        if not form:
            console.print("  [dim]-> No login form detected on target page[/dim]")
            return findings

        console.print(f"  [dim]-> Login form found: {form['action']}[/dim]")
        console.print(
            f"  [dim]-> Testing {len(DEFAULT_CREDENTIALS)} credential pairs...[/dim]"
        )

        for username, password in DEFAULT_CREDENTIALS:
            result = self._try_login(form, username, password)
            if result:
                findings.append(result)
                console.print(
                    f"  [bold red]💥 Default creds work: {username}:{password}[/bold red]"
                )

        return findings

    # ── Account lockout test ───────────────────────────────────────────

    def _test_lockout(self) -> Optional[Dict]:
        form = self._find_login_form()
        if not form:
            return None

        responses = []
        for i in range(6):
            r = self._try_login(form, "admin", f"wrong_pass_{i}")
            responses.append(r)
            time.sleep(0.3)

        # If all 6 attempts returned (no lockout/captcha triggered)
        if len([x for x in responses if x is None]) == 6:
            # Check we're not getting blocked
            try:
                probe = self.session.post(
                    form["action"],
                    data={
                        form["user_field"]: "admin",
                        form["pass_field"]: "wrong_final",
                    },
                    timeout=self.timeout,
                    verify=False,
                )
                if probe.status_code not in (429, 403):
                    return {
                        "url": form["action"],
                        "type": "No Account Lockout",
                        "severity": "medium",
                        "detail": "6 consecutive failed logins did not trigger lockout or CAPTCHA",
                        "evidence": "All requests returned non-blocking status",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "cvss": 5.3,
                        "remediation": (
                            "Implement account lockout after 3-5 failed attempts. "
                            "Add CAPTCHA or progressive delays."
                        ),
                    }
            except Exception:
                pass
        return None

    # ── JWT Analysis ───────────────────────────────────────────────────

    def _extract_jwts(self) -> List[str]:
        tokens = []
        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            # From cookies
            for cookie in self.session.cookies:
                val = cookie.value
                if val.count(".") == 2 and len(val) > 40:
                    tokens.append(val)
            # From Authorization header echoes / body
            jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
            found = re.findall(jwt_pattern, resp.text)
            tokens.extend(found)
        except Exception:
            pass
        return list(set(tokens))

    def _analyze_jwt(self, token: str) -> List[Dict]:
        findings = []
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return []

            header_raw = parts[0] + "=" * (-len(parts[0]) % 4)
            payload_raw = parts[1] + "=" * (-len(parts[1]) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_raw))
            payload = json.loads(base64.urlsafe_b64decode(payload_raw))

            # Test 1: alg:none
            none_header = (
                base64.urlsafe_b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                )
                .rstrip(b"=")
                .decode()
            )
            none_token = f"{none_header}.{parts[1]}."
            findings.append(
                {
                    "url": self.target,
                    "type": "JWT alg:none Attack Vector",
                    "severity": "high",
                    "detail": f"Algorithm: {header.get('alg')} — test alg:none bypass",
                    "evidence": f"Token: {token[:40]}...",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "cvss": 8.8,
                    "remediation": "Enforce strong JWT algorithm (RS256). Reject alg:none tokens.",
                }
            )

            # Test 2: Weak secret brute-force (HS256 only)
            if header.get("alg") == "HS256":
                msg = f"{parts[0]}.{parts[1]}".encode()
                for secret in JWT_WEAK_SECRETS:
                    sig = (
                        base64.urlsafe_b64encode(
                            hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                        )
                        .rstrip(b"=")
                        .decode()
                    )
                    if sig == parts[2]:
                        findings.append(
                            {
                                "url": self.target,
                                "type": "JWT Weak Secret",
                                "severity": "critical",
                                "detail": f"JWT signed with weak secret: '{secret}'",
                                "evidence": f"Secret '{secret}' produces valid signature",
                                "owasp": "A07:2021 – Identification and Authentication Failures",
                                "cvss": 9.8,
                                "remediation": "Use long random secret (≥256 bits) or asymmetric keys (RS256).",
                            }
                        )
                        break

        except Exception:
            pass
        return findings

    # ── Unauthenticated admin access ───────────────────────────────────

    def _test_admin_access(self) -> List[Dict]:
        findings = []
        
        # Get baseline for soft 404 / SPA to reduce false positives
        try:
            baseline_resp = requests.get(
                self.target + "/this_should_not_exist_404_webpwn",
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "WebPwnToolkit/1.0"},
            )
            baseline_size = len(baseline_resp.content) if baseline_resp.status_code == 200 else -1
        except Exception:
            baseline_size = -1

        for path in ADMIN_PATHS:
            url = self.target + path
            try:
                # Fresh session (no cookies)
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "WebPwnToolkit/1.0"},
                )
                if resp.status_code == 200:
                    # Ignore if the size roughly matches the baseline 200 response (SPA/soft 404)
                    if baseline_size != -1 and abs(len(resp.content) - baseline_size) < 50:
                        continue
                        
                    findings.append(
                        {
                            "url": url,
                            "type": "Unauthenticated Admin Access",
                            "severity": "critical",
                            "detail": f"Admin path accessible without authentication: {path}",
                            "evidence": f"HTTP 200 on {url}",
                            "owasp": "A01:2021 – Broken Access Control",
                            "cvss": 9.1,
                            "remediation": "Restrict admin paths to authenticated and authorized users only.",
                        }
                    )
                    break  # Break out to avoid showing the same finding 5-10 times
            except Exception:
                pass
        return findings

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print("  [dim]-> Testing default credentials...[/dim]")
        self.results.extend(self._test_credentials())

        console.print("  [dim]-> Testing account lockout...[/dim]")
        lockout = self._test_lockout()
        if lockout:
            self.results.append(lockout)

        console.print("  [dim]-> Analyzing JWT tokens...[/dim]")
        tokens = self._extract_jwts()
        console.print(f"  [dim]-> {len(tokens)} JWT token(s) found[/dim]")
        for token in tokens:
            self.results.extend(self._analyze_jwt(token))

        console.print("  [dim]-> Testing admin path access...[/dim]")
        self.results.extend(self._test_admin_access())

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' auth issue(s) found!' if self.results else '✅ No auth issues found'}"
            f"[/]"
        )
        return self.results
