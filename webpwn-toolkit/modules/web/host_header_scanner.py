#!/usr/bin/env python3
"""
Host Header Injection / Cache Poisoning Scanner
------------------------------------------------
Injects arbitrary Host and X-Forwarded-Host headers to detect
if the application dynamically uses them to construct URLs
(leading to password reset poisoning or web cache poisoning).
"""

import requests
from typing import List, Dict
from rich.console import Console

console = Console()


class HostHeaderScanner:
    def __init__(self, target: str, timeout: int = 10, session=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.results: List[Dict] = []
        self.evil_host = "evil-host-header-injection.com"

    def run(self) -> List[Dict]:
        console.print(f"  [dim]-> Testing Host Header Injection on {self.target}[/dim]")

        headers_to_test = [
            {"Host": self.evil_host},
            {"X-Forwarded-Host": self.evil_host},
            {"X-Host": self.evil_host},
        ]

        for h in headers_to_test:
            try:
                # Keep original headers but override the specific one
                req_headers = self.session.headers.copy()
                req_headers.update(h)

                resp = requests.get(
                    self.target,
                    headers=req_headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )

                # Check reflection in body
                if self.evil_host in resp.text:
                    self.results.append(
                        {
                            "url": self.target,
                            "type": "Host Header Injection",
                            "severity": "high",
                            "detail": f"Injected Header {list(h.keys())[0]} reflected in response body. Potential Cache Poisoning / Password Reset Poisoning.",
                            "evidence": f"Header sent: {h} | Reflected in response.",
                            "owasp": "A05:2021 – Security Misconfiguration",
                            "cvss": 7.4,
                            "remediation": "Do not trust the Host header dynamically. Use a predefined allowed hosts list.",
                        }
                    )

                # Check reflection in redirects
                elif resp.status_code in (301, 302, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if self.evil_host in loc:
                        self.results.append(
                            {
                                "url": self.target,
                                "type": "Host Header Injection (Redirect)",
                                "severity": "high",
                                "detail": f"Injected Header {list(h.keys())[0]} reflected in HTTP Redirect Location.",
                                "evidence": f"Header sent: {h} | Location: {loc}",
                                "owasp": "A05:2021 – Security Misconfiguration",
                                "cvss": 7.2,
                                "remediation": "Use absolute URLs with a trusted domain for redirects, or use relative paths.",
                            }
                        )

            except requests.RequestException:
                pass

        if self.results:
            console.print(
                f"  [bold red]💥 {len(self.results)} Host Header vulnerabilities found![/bold red]"
            )
        else:
            console.print("  [green]✅ No Host Header Injection detected[/green]")

        return self.results
