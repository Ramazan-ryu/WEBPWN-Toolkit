#!/usr/bin/env python3
"""
DOM XSS Scanner (Playwright Headless Browser)
-----------------------------------------------
Detects XSS in dynamically rendered content that passive HTTP scanners miss:
  • SPA pages (React, Vue, Angular)
  • JavaScript event handlers
  • DOM-based sinks (document.write, innerHTML, location.href)
  • Template injection that only triggers on render

Falls back gracefully if Playwright is not installed.
"""

import uuid
import time
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Check Playwright availability
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# DOM sinks to monitor for XSS execution
DOM_SINKS = [
    "document.write",
    "innerHTML",
    "outerHTML",
    "document.domain",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "location.hash",
    "window.location",
]

# Test payloads — all use a unique session marker
_MARKER = uuid.uuid4().hex[:8].upper()

DOM_PAYLOADS = [
    f"<script>document.title='{_MARKER}'</script>",
    f"<img src=x onerror=\"document.title='{_MARKER}'\">",
    f"javascript:void(document.title='{_MARKER}')",
    f"'-alert('{_MARKER}')-'",
    f"\";document.title='{_MARKER}';\"",
    f"</script><script>document.title='{_MARKER}'</script>",
    f"<svg onload=\"document.title='{_MARKER}'\">",
    f"<iframe srcdoc=\"<script>parent.document.title='{_MARKER}'</script>\">",
    f"{{{{'{_MARKER}'}}}}",  # AngularJS template injection
    f"${{{_MARKER}}}",  # Handlebars/Mustache
]


class DOMScanner:
    """
    Playwright-based DOM XSS scanner.

    Detects XSS in dynamically rendered JavaScript applications
    that static HTTP scanners cannot reach.
    """

    def __init__(
        self, target: str, timeout: int = 15, session=None, headless: bool = True
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.headless = headless
        self.results: List[Dict] = []
        self._marker = _MARKER

    # ── Availability check ────────────────────────────────────────────

    @staticmethod
    def is_available() -> bool:
        return PLAYWRIGHT_AVAILABLE

    @staticmethod
    def install_hint() -> str:
        return "pip install playwright && " "playwright install chromium"

    # ── Inject & detect via Playwright ───────────────────────────────

    def _test_url_param(
        self, page, base_url: str, param: str, payload: str
    ) -> Optional[Dict]:
        """Inject payload into a URL parameter and check for execution."""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(base_url)
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        qs[param] = payload

        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs)}"

        try:
            # Listen for dialog (alert/confirm/prompt) as XSS indicator
            dialog_fired = []

            def on_dialog(dialog):
                dialog_fired.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", on_dialog)

            page.goto(test_url, timeout=self.timeout * 1000, wait_until="networkidle")
            page.wait_for_timeout(1500)  # allow JS to execute

            # Check dialog fired
            if dialog_fired:
                return self._make_finding(
                    url=test_url,
                    param=param,
                    payload=payload,
                    evidence=f"JavaScript dialog fired: {dialog_fired[0][:60]}",
                    method="dialog",
                )

            # Check document.title mutated to marker
            title = page.title()
            if self._marker in title:
                return self._make_finding(
                    url=test_url,
                    param=param,
                    payload=payload,
                    evidence=f"document.title set to marker: {title[:80]}",
                    method="title_mutation",
                )

            # Check DOM content for reflected marker
            content = page.content()
            if self._marker in content:
                # Check if it's inside a script-executable context
                idx = content.find(self._marker)
                ctx = content[max(0, idx - 50) : idx + 50]
                if any(s in ctx for s in ["<script", "onerror", "onload", "eval"]):
                    return self._make_finding(
                        url=test_url,
                        param=param,
                        payload=payload,
                        evidence=f"Marker in executable DOM context: ...{ctx}...",
                        method="dom_reflection",
                    )

        except Exception:
            pass
        return None

    def _test_hash_fragment(self, page, base_url: str, payload: str) -> Optional[Dict]:
        """Test DOM XSS via URL hash fragment (common in SPAs)."""
        test_url = f"{base_url}#{payload}"
        try:
            dialog_fired = []

            def on_dialog(dialog):
                dialog_fired.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", on_dialog)
            page.goto(test_url, timeout=self.timeout * 1000, wait_until="networkidle")
            page.wait_for_timeout(1500)

            if dialog_fired or self._marker in page.title():
                return self._make_finding(
                    url=test_url,
                    param="#fragment",
                    payload=payload,
                    evidence=f"DOM XSS via hash fragment",
                    method="hash_fragment",
                )
        except Exception:
            pass
        return None

    def _collect_url_params(self) -> List[Dict]:
        """Collect URL parameters from target page links/forms."""
        from urllib.parse import urlparse, parse_qs
        import requests

        params = []
        try:
            resp = requests.get(
                self.target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "WebPwnToolkit/2.0"},
            )
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "lxml")

            # From <a href> links
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if "?" in href:
                    parsed = urlparse(href)
                    qs = parse_qs(parsed.query)
                    for key in qs:
                        params.append({"url": self.target + href, "param": key})

            # From URL itself
            parsed = urlparse(self.target)
            for key in parse_qs(parsed.query):
                params.append({"url": self.target, "param": key})

        except Exception:
            pass
        return params

    # ── Finding factory ───────────────────────────────────────────────

    def _make_finding(
        self, url: str, param: str, payload: str, evidence: str, method: str
    ) -> Dict:
        return {
            "url": url,
            "parameter": param,
            "payload": payload[:120],
            "type": f"DOM XSS ({method.replace('_', ' ').title()})",
            "severity": "high",
            "evidence": evidence,
            "detail": (
                f"DOM-based XSS confirmed in parameter '{param}' via Playwright "
                f"headless browser execution. Method: {method}."
            ),
            "owasp": "A03:2021 – Injection",
            "cvss": 7.4,
            "remediation": (
                "Sanitize all values before inserting into the DOM. "
                "Use textContent instead of innerHTML. "
                "Implement a strict Content-Security-Policy. "
                "Use DOMPurify for client-side sanitization."
            ),
        }

    # ── Public run ────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        if not PLAYWRIGHT_AVAILABLE:
            console.print(
                f"  [yellow]⚠ Playwright not installed — DOM XSS scan skipped.[/yellow]\n"
                f"  [dim]Install: {self.install_hint()}[/dim]"
            )
            return []

        console.print(f"  [dim]→ Launching headless Chromium for DOM XSS...[/dim]")
        url_params = self._collect_url_params()
        console.print(
            f"  [dim]→ {len(url_params)} URL parameter(s) | "
            f"{len(DOM_PAYLOADS)} payloads each[/dim]"
        )

        total = len(url_params) * len(DOM_PAYLOADS) + len(DOM_PAYLOADS)

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=self.headless)
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers={"User-Agent": "WebPwnToolkit/2.0"},
                )
                page = ctx.new_page()

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[cyan]DOM XSS scanning...[/cyan]"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console,
                ) as progress:
                    task = progress.add_task("dom", total=max(total, 1))

                    # Test URL parameters
                    for entry in url_params:
                        for payload in DOM_PAYLOADS:
                            progress.advance(task)
                            result = self._test_url_param(
                                page, entry["url"], entry["param"], payload
                            )
                            if result and result not in self.results:
                                self.results.append(result)

                    # Test hash fragments
                    for payload in DOM_PAYLOADS:
                        progress.advance(task)
                        result = self._test_hash_fragment(page, self.target, payload)
                        if result and result not in self.results:
                            self.results.append(result)

                browser.close()

        except Exception as e:
            console.print(f"  [red]DOM scan error: {e}[/red]")

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' DOM XSS issue(s) found!' if self.results else '✅ No DOM XSS found'}"
            f"[/]"
        )
        return self.results
