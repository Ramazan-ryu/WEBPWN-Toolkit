#!/usr/bin/env python3
"""
IDOR Scanner
-------------
Insecure Direct Object Reference vulnerability detection.
Tests sequential ID enumeration, UUID patterns, parameter pollution, method override.
"""

import re
import hashlib
import requests
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

IDOR_PATTERNS = [
    "/api/user/{id}",
    "/api/users/{id}",
    "/api/account/{id}",
    "/api/profile/{id}",
    "/api/order/{id}",
    "/api/invoice/{id}",
    "/api/payment/{id}",
    "/api/document/{id}",
    "/api/file/{id}",
    "/api/ticket/{id}",
    "/api/message/{id}",
    "/api/admin/user/{id}",
    "/user/{id}",
    "/profile/{id}",
    "/account/{id}",
    "/order/{id}",
    "/invoice/{id}",
    "/download/{id}",
    "/view/{id}",
    "/edit/{id}",
    "/files/{id}",
    "/documents/{id}",
    "/exports/{id}",
]

PII_RE = re.compile(
    r"(?:email|username|first_?name|last_?name|phone|address|"
    r"password|token|api_?key|balance|account_?number|ssn)",
    re.IGNORECASE,
)


class IDORScanner:
    def __init__(
        self,
        target: str,
        session=None,
        timeout: int = 10,
        threads: int = 10,
        max_ids: int = 50,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.max_ids = max_ids
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _capture_baseline(self, pattern: str) -> Optional[Tuple[str, int]]:
        url1 = self.target + pattern.replace("{id}", "1")
        url2 = self.target + pattern.replace("{id}", "99999")
        r1 = self._get(url1)
        r2 = self._get(url2)
        if not r1 or r1.status_code not in (200, 201):
            return None
        if (
            r2
            and r2.status_code == r1.status_code
            and abs(len(r1.text) - len(r2.text)) < 30
        ):
            return None  # No meaningful difference
        return (pattern, len(r1.text))

    def _enumerate_ids(self, pattern: str, base_len: int) -> List[Dict]:
        findings = []
        seen = set()

        def test_id(i: int) -> Optional[Dict]:
            url = self.target + pattern.replace("{id}", str(i))
            resp = self._get(url)
            if not resp or resp.status_code not in (200, 201):
                return None
            body = resp.text
            if abs(len(body) - base_len) < 20:
                return None
            sig = body[:60]
            if sig in seen:
                return None
            seen.add(sig)
            pii = PII_RE.findall(body)
            if pii or len(body) > 80:
                return {"id": i, "pii": list(set(pii))[:5], "preview": body[:150]}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for r in concurrent.futures.as_completed(
                {ex.submit(test_id, i): i for i in range(1, self.max_ids + 1)}
            ):
                res = r.result()
                if res:
                    findings.append(res)
        return findings

    # ── Dual-session IDOR test ───────────────────────────────────────────

    def _dual_session_test(self) -> List[Dict]:
        """
        Real IDOR detection: fetch a resource as User A (authenticated session),
        then fetch the SAME resource with an unauthenticated second session.
        If both return identical content — IDOR is confirmed.
        """
        findings = []
        anon_session = requests.Session()
        anon_session.verify = False
        anon_session.headers["User-Agent"] = "WebPwnToolkit/2.2-anon"

        for pattern in IDOR_PATTERNS[:10]:
            for test_id_val in [1, 2, 3, 5, 10]:
                url = self.target + pattern.replace("{id}", str(test_id_val))

                r_auth = self._get(url)
                if not r_auth or r_auth.status_code not in (200, 201):
                    continue
                if len(r_auth.text) < 30:
                    continue

                try:
                    r_anon = anon_session.get(url, timeout=self.timeout, verify=False)
                except Exception:
                    continue

                if not r_anon or r_anon.status_code not in (200, 201):
                    continue

                hash_auth = hashlib.blake2b(
                    r_auth.text.encode(), digest_size=16
                ).hexdigest()
                hash_anon = hashlib.blake2b(
                    r_anon.text.encode(), digest_size=16
                ).hexdigest()

                if hash_auth == hash_anon:
                    pii = PII_RE.findall(r_auth.text)
                    findings.append(
                        {
                            "url": url,
                            "type": "IDOR — Confirmed: Unauthenticated Access to Private Resource",
                            "severity": "critical",
                            "cvss": 9.1,
                            "detail": (
                                f"'{pattern.replace('{id}', str(test_id_val))}' returns identical content "
                                f"to both authenticated and unauthenticated sessions. "
                                f"PII fields: {list(set(pii))[:5]}"
                            ),
                            "evidence": (
                                f"Auth hash == Anon hash ({hash_auth}). "
                                f"Preview: {r_auth.text[:150]}"
                            ),
                            "owasp": "A01:2021 – Broken Access Control",
                            "remediation": (
                                "Implement authorization Senior ware on every endpoint. "
                                "Verify that the requesting user owns the requested object. "
                                "Return 401/403 for unauthenticated access."
                            ),
                        }
                    )
                    break
        return findings

    def _test_method_override(self) -> List[Dict]:
        findings = []
        for path in ["/api/user/1", "/api/account/1", "/api/order/1"]:
            url = self.target + path
            for method in ["DELETE", "PUT", "PATCH"]:
                try:
                    resp = self.session.request(
                        method, url, timeout=self.timeout, verify=False
                    )
                    if resp and resp.status_code in (200, 204):
                        findings.append(
                            {
                                "url": url,
                                "type": f"IDOR — Unauthorized {method}",
                                "severity": "critical",
                                "cvss": 9.1,
                                "detail": f"HTTP {method} on {path} succeeded without authorization.",
                                "evidence": f"HTTP {resp.status_code}",
                                "owasp": "A01:2021 – Broken Access Control",
                                "remediation": "Enforce authorization on all HTTP methods.",
                            }
                        )
                except Exception:
                    pass
        return findings

    def run(self) -> List[Dict]:
        console.print(f"\n  [bold yellow]▶ IDOR Scanner on {self.target}[/bold yellow]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]IDOR scanning...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("idor", total=len(IDOR_PATTERNS) + 1)

            for pattern in IDOR_PATTERNS:
                prog.advance(task)
                baseline = self._capture_baseline(pattern)
                if not baseline:
                    continue
                tmpl, base_len = baseline
                id_findings = self._enumerate_ids(tmpl, base_len)
                if len(id_findings) >= 2:
                    self.results.append(
                        {
                            "url": self.target + tmpl.replace("{id}", "N"),
                            "type": "IDOR — Horizontal Privilege Escalation",
                            "severity": "critical",
                            "cvss": 9.1,
                            "detail": (
                                f"Pattern '{tmpl}' exposes {len(id_findings)} objects without auth. "
                                f"PII fields: {id_findings[0].get('pii', [])}"
                            ),
                            "evidence": f"IDs accessible: {[f['id'] for f in id_findings[:8]]}",
                            "owasp": "A01:2021 – Broken Access Control",
                            "remediation": "Verify requesting user owns each object. Use authorization Senior ware.",
                        }
                    )

            # Dual-session: authenticated vs anonymous
            prog.advance(task)
            console.print("  [dim]Dual-session test (auth vs anonymous)...[/dim]")
            dual = self._dual_session_test()
            if dual:
                console.print(
                    f"  [bold red][!] {len(dual)} dual-session IDOR confirmed![/bold red]"
                )
            self.results.extend(dual)

        self.results.extend(self._test_method_override())

        # Deduplicate
        seen_keys: set = set()
        unique = []
        for r in self.results:
            key = (r.get("url", ""), r.get("type", ""))
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(r)
        self.results = unique

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} IDOR finding(s)[/]")
        return self.results
