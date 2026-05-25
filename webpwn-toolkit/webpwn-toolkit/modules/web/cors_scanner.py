#!/usr/bin/env python3
"""
CORS Misconfiguration Scanner
-------------------------------
Tests for Cross-Origin Resource Sharing misconfigurations:
  • Wildcard origin (Access-Control-Allow-Origin: *)
  • Arbitrary origin reflection (attacker.com → trusted)
  • Null origin allowance
  • Credentials + wildcard (impossible but some servers try)
  • Pre-flight bypass
"""

import requests
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Origins to test — attacker-controlled domains
TEST_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.com",
    "null",
    "https://trusted.com.evil.com",  # suffix bypass
    "https://subdomain.evil.com",
]


class CORSScanner:
    """Detect CORS misconfigurations that allow cross-origin data theft."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.results: List[Dict] = []

    def _test_origin(self, url: str, origin: str) -> List[Dict]:
        findings = []
        headers = {
            "Origin": origin,
            "User-Agent": "WebPwn-Toolkit/1.0",
        }
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            # Case 1: Wildcard
            if acao == "*":
                findings.append(
                    {
                        "url": url,
                        "type": "CORS Wildcard Origin",
                        "severity": "medium",
                        "detail": "Server returns Access-Control-Allow-Origin: * — any origin can read responses.",
                        "evidence": f"ACAO: {acao}",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "cvss": 5.3,
                        "remediation": (
                            "Restrict ACAO to a specific trusted origin. "
                            "Never use wildcard when credentials are involved."
                        ),
                    }
                )

            # Case 2: Reflected arbitrary origin
            elif acao == origin and origin != "null":
                severity = "critical" if acac.lower() == "true" else "high"
                cvss = 9.1 if acac.lower() == "true" else 7.5
                findings.append(
                    {
                        "url": url,
                        "type": "CORS Arbitrary Origin Reflection"
                        + (" + Credentials" if acac.lower() == "true" else ""),
                        "severity": severity,
                        "detail": (
                            f"Server reflects attacker origin '{origin}' in ACAO header"
                            + (
                                ", and allows credentials — full cross-origin session theft possible."
                                if acac.lower() == "true"
                                else "."
                            )
                        ),
                        "evidence": f"Origin: {origin} → ACAO: {acao} | ACAC: {acac or 'false'}",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "cvss": cvss,
                        "remediation": (
                            "Validate Origin against a server-side allowlist. "
                            "Never reflect arbitrary Origin values. "
                            "Do not combine ACAO: * with Allow-Credentials: true."
                        ),
                    }
                )

            # Case 3: null origin accepted
            elif origin == "null" and acao == "null":
                findings.append(
                    {
                        "url": url,
                        "type": "CORS Null Origin Allowed",
                        "severity": "high",
                        "detail": "Server accepts 'null' origin, which can be triggered from sandboxed iframes.",
                        "evidence": f"Origin: null → ACAO: null | ACAC: {acac}",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "cvss": 7.4,
                        "remediation": "Explicitly reject null Origin. Allowlist only specific trusted domains.",
                    }
                )

        except Exception:
            pass
        return findings

    def _test_preflight(self, url: str) -> List[Dict]:
        """Test OPTIONS pre-flight for dangerous Allow-Headers."""
        findings = []
        try:
            resp = requests.options(
                url,
                headers={
                    "Origin": "https://evil.example.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
                    "User-Agent": "WebPwn-Toolkit/1.0",
                },
                timeout=self.timeout,
                verify=False,
            )
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            acah = resp.headers.get("Access-Control-Allow-Headers", "")
            if resp.status_code == 200 and acam:
                if any(m in acam for m in ["DELETE", "PUT", "PATCH"]):
                    findings.append(
                        {
                            "url": url,
                            "type": "CORS Pre-flight Allows Dangerous Methods",
                            "severity": "medium",
                            "detail": f"Pre-flight response allows: {acam}",
                            "evidence": f"ACAM: {acam} | ACAH: {acah}",
                            "owasp": "A05:2021 – Security Misconfiguration",
                            "cvss": 5.8,
                            "remediation": "Restrict allowed methods to only those required by the API.",
                        }
                    )
        except Exception:
            pass
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"  [dim]-> Testing {len(TEST_ORIGINS)} malicious origins against {self.target}[/dim]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]CORS scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("cors", total=len(TEST_ORIGINS) + 1)
            for origin in TEST_ORIGINS:
                progress.advance(task)
                self.results.extend(self._test_origin(self.target, origin))
            progress.advance(task)
            self.results.extend(self._test_preflight(self.target))

        # De-duplicate by type+url
        seen = set()
        dedup = []
        for r in self.results:
            key = (r["url"], r["type"])
            if key not in seen:
                seen.add(key)
                dedup.append(r)
        self.results = dedup

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' CORS issue(s) found!' if self.results else '✅ No CORS issues found'}"
            f"[/]"
        )
        return self.results
