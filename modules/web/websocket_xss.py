#!/usr/bin/env python3
"""
Websocket XSS Scanner — Senior Level
----------------------------------------
Connects to discovered WebSocket endpoints, injects XSS payloads
into the communication channel, and monitors the responses for reflections.
"""

import json
import time
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'\"><script>alert(1)</script>",
]


class WebSocketXSSScanner(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.results = []

        try:
            import websocket

            self.websocket_available = True
        except ImportError:
            self.websocket_available = False

    def _get_ws_url(self) -> str:
        if self.target.startswith("https://"):
            return self.target.replace("https://", "wss://")
        return self.target.replace("http://", "ws://")

    def _test_ws(self, ws_url: str) -> List[Dict]:
        findings = []
        if not self.websocket_available:
            return findings

        import websocket

        try:
            ws = websocket.WebSocket(sslopt={"cert_reqs": 0})
            ws.settimeout(5)
            ws.connect(ws_url)

            for payload in XSS_PAYLOADS:
                # Try sending as plain text
                ws.send(payload)
                try:
                    resp = ws.recv()
                    if payload in resp:
                        findings.append(
                            {
                                "url": ws_url,
                                "type": "WebSocket XSS (Plain Text)",
                                "severity": "high",
                                "cvss": 7.5,
                                "detail": "WebSocket endpoint reflects injected XSS payloads in plain text messages.",
                                "evidence": f"Reflected: {payload}",
                                "owasp": "A03:2021 – Injection",
                                "remediation": "Sanitize all data received and transmitted via WebSockets.",
                            }
                        )
                        break
                except Exception:
                    pass

                # Try sending as JSON
                json_payload = json.dumps(
                    {"message": payload, "data": payload, "id": payload}
                )
                ws.send(json_payload)
                try:
                    resp = ws.recv()
                    if payload in resp:
                        findings.append(
                            {
                                "url": ws_url,
                                "type": "WebSocket XSS (JSON)",
                                "severity": "high",
                                "cvss": 7.5,
                                "detail": "WebSocket endpoint reflects injected XSS payloads inside JSON structures.",
                                "evidence": f"Reflected: {payload}",
                                "owasp": "A03:2021 – Injection",
                                "remediation": "Sanitize all data received and transmitted via WebSockets.",
                            }
                        )
                        break
                except Exception:
                    pass

            ws.close()

            # Senior addition: Test for Cross-Site WebSocket Hijacking (CSWSH)
            try:
                ws_hijack = websocket.WebSocket(sslopt={"cert_reqs": 0})
                ws_hijack.settimeout(5)
                # Connect with an arbitrary Origin
                fake_origin = "https://evil-attacker.com"
                ws_hijack.connect(ws_url, origin=fake_origin)
                # If connection succeeds without exception, it might be vulnerable to CSWSH
                findings.append(
                    {
                        "url": ws_url,
                        "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                        "severity": "high",
                        "cvss": 8.1,
                        "detail": f"WebSocket endpoint does not validate the Origin header, allowing connections from arbitrary domains.",
                        "evidence": f"Successfully connected with Origin: {fake_origin}",
                        "owasp": "A01:2021 – Broken Access Control",
                        "remediation": "Validate the Origin header on the server side to ensure it matches your trusted domain(s).",
                    }
                )
                ws_hijack.close()
            except Exception:
                pass

        except Exception:
            pass

        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ WebSocket XSS Scanner on {self.target}[/bold yellow]"
        )
        if not self.websocket_available:
            console.print(
                "  [dim]websocket-client library not installed. Skipping.[/dim]"
            )
            return self.results

        # Common paths
        paths = ["/ws", "/socket", "/socket.io/", "/graphql", "/chat"]
        for path in paths:
            url = self._get_ws_url() + path
            res = self._test_ws(url)
            for r in res:
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} WebSocket XSS issue(s) found[/]")
        return self.results
