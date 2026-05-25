#!/usr/bin/env python3
"""
Subdomain Hijack V2 — Senior Level
--------------------------------------
Automates CNAME and DNS wildcard takeover detection by resolving
subdomains and checking the response bodies/headers against known
cloud service provider signatures.
"""

import requests
import socket
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()

TAKEOVER_SIGNATURES = {
    "github": {"cname": "github.io", "sig": "There isn't a GitHub Pages site here."},
    "heroku": {"cname": "herokuapp.com", "sig": "No such app"},
    "s3": {"cname": "s3.amazonaws.com", "sig": "NoSuchBucket"},
    "azure": {"cname": "azurewebsites.net", "sig": "404 Web Site not found"},
    "zendesk": {"cname": "zendesk.com", "sig": "Help Center Closed"},
    "bitbucket": {"cname": "bitbucket.io", "sig": "Repository not found"},
    "ghost": {
        "cname": "ghost.io",
        "sig": "The thing you were looking for is no longer here",
    },
}


class SubdomainHijackV2Scanner(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.session = session or requests.Session()
            self.session.verify = False
            self.results = []

        from urllib.parse import urlparse

        self.domain = urlparse(self.target).netloc
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]

    def _get_cname(self, domain: str) -> str:
        try:
            import dns.resolver

            answers = dns.resolver.resolve(domain, "CNAME")
            for rdata in answers:
                return str(rdata.target)
        except Exception:
            pass
        return ""

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Subdomain Hijack V2 Scanner on {self.domain}[/bold yellow]"
        )

        # Determine subdomains to test. We will test the main domain for now.
        # In a real run, this would take output from subdomain_enum.py
        test_domains = [self.domain]
        if self.domain.startswith("www."):
            test_domains.append(self.domain[4:])

        for d in test_domains:
            try:
                # 1. Resolve CNAME
                cname = self._get_cname(d)

                # 2. Check HTTP Response
                if hasattr(self, "_get"):
                    r = self._get("http://" + d)
                else:
                    r = self.session.get(
                        "http://" + d, timeout=self.timeout, verify=False
                    )

                if not r:
                    continue

                body = r.text

                for provider, data in TAKEOVER_SIGNATURES.items():
                    if data["sig"] in body or (cname and data["cname"] in cname):
                        # Double check if CNAME actually points to the provider
                        if cname and data["cname"] in cname and data["sig"] in body:
                            self.results.append(
                                {
                                    "url": d,
                                    "type": f"Subdomain Takeover ({provider})",
                                    "severity": "high",
                                    "cvss": 8.5,
                                    "detail": f"Subdomain {d} has a dangling CNAME pointing to {provider} and returns a 'not found' signature. It can likely be claimed.",
                                    "evidence": f"CNAME: {cname} | Signature matched: {data['sig']}",
                                    "owasp": "A05:2021 – Security Misconfiguration",
                                    "remediation": "Remove the DNS record if the service is no longer in use.",
                                }
                            )
                            console.print(
                                f"  [bold red][!] Subdomain Takeover ({provider}) on {d}[/bold red]"
                            )
            except Exception:
                pass

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} Takeover issue(s) found[/]")
        return self.results
