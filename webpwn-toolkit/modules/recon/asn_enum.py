#!/usr/bin/env python3
"""
Infrastructure & ASN Enumerator
-------------------------------
Finds Autonomous System Numbers (ASN) and associated BGP IP prefixes
for the target domain to uncover the entire corporate IP space.
"""

import requests
from typing import List, Dict
from rich.console import Console

console = Console()


class ASNEnumerator:
    def __init__(self, target_domain: str):
        self.target = target_domain
        self.results: List[Dict] = []
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebPwnToolkit/2.0 (ASN Enum)"

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ ASN & Infrastructure Enumerator for '{self.target}'...[/bold yellow]"
        )

        # 1. Resolve domain to IP or find host info
        ip_address = None
        try:
            import socket

            ip_address = socket.gethostbyname(self.target)
            console.print(f"  [dim]→ Target IP: {ip_address}[/dim]")
        except Exception:
            console.print("  [red]Failed to resolve target IP.[/red]")
            return self.results

        # 2. Get ASN for IP
        asn = None
        asn_name = None
        try:
            resp = self.session.get(
                f"https://api.hackertarget.com/aslookup/?q={ip_address}", timeout=10
            )
            if resp.status_code == 200 and "," in resp.text:
                parts = resp.text.strip().split(",")
                if len(parts) >= 3:
                    ip, asn, asn_name = (
                        parts[0].strip('"'),
                        parts[1].strip('"'),
                        parts[2].strip('"'),
                    )
                    console.print(
                        f"  [green]✅ ASN Found: AS{asn} ({asn_name})[/green]"
                    )
                    self.results.append(
                        {
                            "type": "Infrastructure",
                            "severity": "info",
                            "evidence": f"ASN: AS{asn}",
                            "detail": f"Company: {asn_name}",
                        }
                    )
        except Exception as e:
            console.print(f"  [red]ASN Lookup failed: {e}[/red]")
            return self.results

        # 3. Find all prefixes for ASN
        if asn:
            try:
                resp = self.session.get(
                    f"https://api.hackertarget.com/aslookup/?q=AS{asn}", timeout=10
                )
                if resp.status_code == 200:
                    lines = resp.text.strip().split("\n")
                    prefixes = []
                    for line in lines[1:]:  # Skip the first header line usually
                        if line.strip():
                            prefixes.append(line.strip())

                    if prefixes:
                        console.print(
                            f"  [dim]→ Discovered {len(prefixes)} IP Prefixes (CIDR blocks) owned by {asn_name}.[/dim]"
                        )
                        self.results.append(
                            {
                                "type": "IP Prefixes",
                                "severity": "info",
                                "evidence": f"Found {len(prefixes)} CIDR blocks",
                                "detail": ", ".join(prefixes[:10])
                                + ("..." if len(prefixes) > 10 else ""),
                            }
                        )
            except Exception:
                pass

        return self.results
