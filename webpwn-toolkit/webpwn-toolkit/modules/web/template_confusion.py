#!/usr/bin/env python3
"""
Template Confusion Scanner — Senior Level
----------------------------------------------
Tests for framework misconfigurations where server-side routing
or templating logic handles paths unexpectedly, leading to source code disclosure
or template injection.
"""

import requests
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()


class TemplateConfusionScanner(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.session = session or requests.Session()
            self.session.verify = False
            self.results = []
        self.endpoints = ["/login", "/", "/about"]

    def _test_confusion(self, base_url: str) -> List[Dict]:
        findings = []

        test_cases = [
            ("URL Encoded NUL", "%00"),
            ("Template Extension", ".jsp"),
            ("Template Extension", ".vm"),
            ("Template Extension", ".twig"),
            ("Path Truncation", "/" + "a" * 4096),
        ]

        for name, payload in test_cases:
            url = base_url + payload
            if hasattr(self, "_get"):
                r = self._get(url)
            else:
                try:
                    r = self.session.get(url, timeout=self.timeout, verify=False)
                except Exception:
                    r = None

            if r and r.status_code == 200:
                # Check for source code disclosure
                if (
                    "<%@" in r.text
                    or "<?php" in r.text
                    or "#set(" in r.text
                    or "{{" in r.text
                ):
                    # Ignore if the original page also has it (rare, but possible)
                    orig = self.session.get(base_url, verify=False)
                    if orig and r.text[:100] != orig.text[:100]:
                        findings.append(
                            {
                                "url": url,
                                "type": f"Template Confusion ({name})",
                                "severity": "high",
                                "cvss": 7.5,
                                "detail": f"Appending {payload} revealed raw template source code.",
                                "evidence": f"Raw template code found in response.",
                                "owasp": "A05:2021 – Security Misconfiguration",
                                "remediation": "Ensure web server does not serve template files directly.",
                            }
                        )
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Template Confusion Scanner on {self.target}[/bold yellow]"
        )
        for path in self.endpoints:
            url = self.target + path
            res = self._test_confusion(url)
            for r in res:
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(
            f"  [{color}]{len(self.results)} Template Confusion issue(s) found[/]"
        )
        return self.results
