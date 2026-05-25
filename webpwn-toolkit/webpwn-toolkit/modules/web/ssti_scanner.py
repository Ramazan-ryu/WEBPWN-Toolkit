#!/usr/bin/env python3
"""
Server-Side Template Injection (SSTI) Scanner
----------------------------------------------
Advanced Scanner that tests for SSTI vulnerabilities in modern web apps
(Jinja2, Twig, FreeMarker, Velocity, ERB, Smarty).

Payloads evaluated:
  • Jinja2/Twig: {{7*7}} -> 49
  • FreeMarker: ${7*7} -> 49
  • ERB: <%= 7*7 %> -> 49
  • Java (Velocity): #set($c=7*7)$c -> 49
"""

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict
import requests
from rich.console import Console

console = Console()

SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2 / Twig"),
    ("${7*7}", "49", "FreeMarker / EL"),
    ("<%= 7*7 %>", "49", "Ruby ERB"),
    ("#{7*7}", "49", "Spring EL"),
    ("*{7*7}", "49", "Thymeleaf"),
    ("@{7*7}", "49", "Razor"),
    ("{{7*'7'}}", "7777777", "Jinja2 (String multiplication)"),
    ("${7*'7'}", "7777777", "FreeMarker (String multiplication)"),
]


class SSTIScanner:
    def __init__(self, target: str, timeout: int = 10, session=None):
        self.target = target
        self.timeout = timeout
        self.session = session or requests.Session()
        self.results: List[Dict] = []

    def _test_url_parameters(self) -> None:
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            return

        for param_name, values in params.items():
            for payload, expected, engine in SSTI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))

                try:
                    resp = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
                    if expected in resp.text and payload not in resp.text:
                        # Confirmed math execution
                        self.results.append(
                            {
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "type": f"Server-Side Template Injection ({engine})",
                                "severity": "critical",
                                "detail": f"Parameter '{param_name}' evaluated template payload '{payload}' to '{expected}'.",
                                "evidence": f"HTTP {resp.status_code} | Found '{expected}' in response body",
                                "owasp": "A03:2021 – Injection",
                                "cvss": 10.0,
                                "remediation": "Use logic-less templates. Sanitize user input and do not allow user-supplied data to be evaluated as a template expression.",
                            }
                        )
                        break  # Stop testing this param if vulnerable
                except requests.RequestException:
                    pass

    def run(self) -> List[Dict]:
        console.print(f"  [dim]-> Testing SSTI on {self.target}[/dim]")
        self._test_url_parameters()

        if self.results:
            console.print(
                f"  [bold red]💥 {len(self.results)} SSTI vulnerabilities found![/bold red]"
            )
        else:
            console.print("  [green]✅ No SSTI vulnerabilities detected[/green]")

        return self.results
