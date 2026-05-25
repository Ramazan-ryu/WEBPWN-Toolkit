#!/usr/bin/env python3
"""
Subdomain Takeover Scanner
---------------------------
Detects dangling DNS records that point to unclaimed third-party services
(e.g., GitHub Pages, AWS S3, Heroku, Azure).

Fingerprints sourced from EdOverflow's "can-i-take-over-xyz".
"""

import requests
import dns.resolver
from typing import List, Dict
from rich.console import Console

console = Console()

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {
        "cname": ["github.io"],
        "pattern": "There isn't a GitHub Pages site here.",
    },
    "AWS S3": {
        "cname": ["s3.amazonaws.com"],
        "pattern": "The specified bucket does not exist",
    },
    "Heroku": {"cname": ["herokuapp.com"], "pattern": "No such app"},
    "Azure": {
        "cname": ["azurewebsites.net", "cloudapp.net"],
        "pattern": "404 Web Site not found",
    },
    "Zendesk": {"cname": ["zendesk.com"], "pattern": "Help Center Closed"},
    "Shopify": {
        "cname": ["myshopify.com"],
        "pattern": "Sorry, this shop is currently unavailable.",
    },
    "Fastly": {"cname": ["fastly.net"], "pattern": "Fastly error: unknown domain"},
    "Ghost": {
        "cname": ["ghost.io"],
        "pattern": "The thing you were looking for is no longer here",
    },
}


class SubdomainTakeoverScanner:
    def __init__(self, target: str, timeout: int = 10):
        # Clean target to just the domain
        from urllib.parse import urlparse

        if target.startswith("http"):
            self.domain = urlparse(target).netloc.split(":")[0]
        else:
            self.domain = target
        self.timeout = timeout
        self.results: List[Dict] = []

    def run(self) -> List[Dict]:
        console.print(f"  [dim]-> Checking Subdomain Takeover on {self.domain}[/dim]")

        try:
            answers = dns.resolver.resolve(self.domain, "CNAME")
            cname = str(answers[0].target).rstrip(".")

            # Check if CNAME matches a vulnerable service
            for service, fp in TAKEOVER_FINGERPRINTS.items():
                if any(service_cname in cname for service_cname in fp["cname"]):

                    # Fetch the page to confirm the pattern
                    try:
                        resp = requests.get(
                            f"http://{self.domain}", timeout=self.timeout
                        )
                        if fp["pattern"] in resp.text:
                            self.results.append(
                                {
                                    "url": self.domain,
                                    "type": f"Subdomain Takeover ({service})",
                                    "severity": "critical",
                                    "detail": f"Domain {self.domain} points to unclaimed {service} instance via CNAME {cname}.",
                                    "evidence": f"CNAME: {cname} | Body matches: '{fp['pattern']}'",
                                    "owasp": "A05:2021 – Security Misconfiguration",
                                    "cvss": 9.8,
                                    "remediation": f"Remove the dangling CNAME record pointing to {cname} or claim the namespace on {service}.",
                                }
                            )
                            break
                    except requests.RequestException:
                        pass

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass

        if self.results:
            console.print(
                f"  [bold red]💥 Subdomain Takeover vulnerable: {self.domain}[/bold red]"
            )
        else:
            console.print("  [green]✅ No Subdomain Takeover detected[/green]")

        return self.results
