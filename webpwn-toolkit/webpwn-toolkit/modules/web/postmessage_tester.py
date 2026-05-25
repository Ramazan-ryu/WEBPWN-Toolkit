#!/usr/bin/env python3
"""
PostMessage Listener Injection Tester — Senior Level
----------------------------------------------------------
Detects vulnerable window.postMessage implementations via:
  • JS source code analysis for event listeners without origin validation
  • Sink detection (eval, innerHTML, document.write, location.href)
  • postMessage origin wildcard detection in postMessage() calls
  • Frame injection possibility (if page is frameable)
  • Cross-origin data exfiltration pattern detection
"""

import re
import requests
import concurrent.futures
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Dangerous sinks that, if reached from postMessage data, lead to XSS/redirect
DANGEROUS_SINKS = [
    r"eval\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"\.src\s*=",
    r"\.action\s*=",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"Function\s*\(",
    r"insertAdjacentHTML\s*\(",
]

# Patterns indicating origin is NOT validated
NO_ORIGIN_CHECK_PATTERNS = [
    r"addEventListener\(['\"]message['\"]",
    r"on\s*message\s*=",
]

ORIGIN_CHECK_PATTERNS = [
    r"event\.origin",
    r"e\.origin",
    r"msg\.origin",
    r"message\.origin",
    r"\.origin\s*[!=]=",
    r"trustedOrigins",
    r"allowedOrigins",
    r"whitelist",
]

# Patterns indicating postMessage is sent to wildcard origin
WILDCARD_PATTERNS = [
    r"postMessage\s*\([^)]+,\s*['\"\*]['\"]",
    r"postMessage\s*\([^)]+,\s*['\*']",
]


class PostMessageTester:
    """
    Senior PostMessage security tester.
    Analyzes JS files and inline scripts for insecure postMessage
    usage patterns without relying on a headless browser.
    """

    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 5):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []
        self._js_urls: List[str] = []

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except Exception:
            return None

    # ── Discover JS files ────────────────────────────────────────────────

    def _discover_js(self, html: str) -> List[str]:
        js_urls = []
        # Find <script src="..."> tags
        for match in re.finditer(
            r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE
        ):
            src = match.group(1)
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("//"):
                js_urls.append("https:" + src)
            elif src.startswith("/"):
                js_urls.append(self.target + src)
            else:
                js_urls.append(self.target + "/" + src)
        return list(set(js_urls))

    # ── Analyze JS content ────────────────────────────────────────────────

    def _analyze_js(self, url: str, js_code: str) -> List[Dict]:
        findings = []

        # Check for message listener
        has_listener = any(
            re.search(pat, js_code, re.IGNORECASE) for pat in NO_ORIGIN_CHECK_PATTERNS
        )
        if not has_listener:
            return []

        # Check if origin is validated
        has_origin_check = any(
            re.search(pat, js_code, re.IGNORECASE) for pat in ORIGIN_CHECK_PATTERNS
        )

        # Find which dangerous sinks appear after addEventListener
        found_sinks = []
        for sink_pat in DANGEROUS_SINKS:
            if re.search(sink_pat, js_code, re.IGNORECASE):
                # Extract the matched sink name
                m = re.search(sink_pat, js_code, re.IGNORECASE)
                if m:
                    found_sinks.append(m.group(0).split("(")[0].strip())

        # No origin check + dangerous sinks = high severity
        if not has_origin_check and found_sinks:
            findings.append(
                {
                    "url": url,
                    "type": "PostMessage — No Origin Check + Dangerous Sink (DOM XSS)",
                    "severity": "high",
                    "cvss": 7.5,
                    "detail": (
                        f"addEventListener('message') found with NO event.origin validation. "
                        f"Dangerous sinks detected: {', '.join(set(found_sinks)[:5])}. "
                        f"Any cross-origin page can inject malicious data into these sinks."
                    ),
                    "evidence": f"File: {url} | Sinks: {set(found_sinks)}",
                    "owasp": "A03:2021 – Injection",
                    "remediation": (
                        "Always validate event.origin against a strict allowlist before processing event.data. "
                        "Never pass event.data directly to eval(), innerHTML, or location.href."
                    ),
                }
            )
        elif not has_origin_check:
            findings.append(
                {
                    "url": url,
                    "type": "PostMessage — Missing Origin Validation",
                    "severity": "medium",
                    "cvss": 5.4,
                    "detail": (
                        "addEventListener('message') found without event.origin validation. "
                        "No immediate dangerous sinks found, but any future code change could introduce XSS."
                    ),
                    "evidence": f"File: {url}",
                    "owasp": "A03:2021 – Injection",
                    "remediation": "Add strict origin whitelist check to all message event handlers.",
                }
            )

        # Check for wildcard postMessage send
        for pat in WILDCARD_PATTERNS:
            if re.search(pat, js_code):
                findings.append(
                    {
                        "url": url,
                        "type": "PostMessage — Wildcard Origin (*) in postMessage()",
                        "severity": "medium",
                        "cvss": 5.3,
                        "detail": (
                            "postMessage() called with '*' as target origin. "
                            "Any cross-origin frame can receive sensitive data being posted."
                        ),
                        "evidence": f"File: {url} — postMessage with '*' origin detected.",
                        "owasp": "A02:2021 – Cryptographic Failures",
                        "remediation": "Specify exact target origin in postMessage(data, 'https://trusted.com').",
                    }
                )
                break

        return findings

    # ── Check if page is frameable (clickjacking + postMessage risk) ──────

    def _check_frameable(
        self, resp: requests.Response, page_url: str
    ) -> Optional[Dict]:
        xfo = resp.headers.get("X-Frame-Options", "").lower()
        csp = resp.headers.get("Content-Security-Policy", "").lower()
        frame_ancestors = "frame-ancestors" in csp

        if not xfo and not frame_ancestors:
            return {
                "url": page_url,
                "type": "PostMessage — Page is Frameable (Clickjacking + postMessage Risk)",
                "severity": "medium",
                "cvss": 5.4,
                "detail": (
                    "No X-Frame-Options or CSP frame-ancestors header found. "
                    "Attacker can embed this page in a frame and use postMessage to "
                    "inject data into any vulnerable message listeners."
                ),
                "evidence": f"Missing X-Frame-Options and CSP frame-ancestors",
                "owasp": "A05:2021 – Security Misconfiguration",
                "remediation": "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.",
            }
        return None

    # ── Scan inline scripts ───────────────────────────────────────────────

    def _analyze_inline(self, html: str, page_url: str) -> List[Dict]:
        inline_scripts = re.findall(
            r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE
        )
        combined = "\n".join(inline_scripts)
        if not combined.strip():
            return []
        return self._analyze_js(page_url + " [inline]", combined)

    # ── Public run ────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ PostMessage Injection Tester on {self.target}[/bold yellow]"
        )

        # Fetch main page
        resp = self._get(self.target)
        if not resp:
            console.print("  [red]Target unreachable[/red]")
            return []

        html = resp.text
        js_urls = self._discover_js(html)
        console.print(
            f"  [dim]Found {len(js_urls)} external JS file(s) + inline scripts[/dim]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Analyzing JS for postMessage...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("postmsg", total=len(js_urls) + 2)

            # 1. Analyze inline scripts
            prog.advance(task)
            for r in self._analyze_inline(html, self.target):
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

            # 2. Check framing
            prog.advance(task)
            frameable = self._check_frameable(resp, self.target)
            if frameable:
                self.results.append(frameable)
                console.print(f"  [bold yellow][!] {frameable['type']}[/bold yellow]")

            # 3. Fetch and analyze each external JS file
            def analyze_js_url(js_url: str) -> List[Dict]:
                r = self._get(js_url)
                if r and r.status_code == 200 and len(r.text) > 50:
                    return self._analyze_js(js_url, r.text)
                return []

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(analyze_js_url, url): url for url in js_urls}
                for future in concurrent.futures.as_completed(futures):
                    prog.advance(task)
                    for r in future.result():
                        if r not in self.results:
                            self.results.append(r)
                            console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} PostMessage issue(s) found[/]")
        return self.results
