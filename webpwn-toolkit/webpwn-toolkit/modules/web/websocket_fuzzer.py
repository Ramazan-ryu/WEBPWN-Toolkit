#!/usr/bin/env python3
"""
WebSocket Fuzzer
-----------------
Tests WebSocket endpoints for injection, auth bypass, and information leakage.
"""

import json
import time
import requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()

WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/chat",
    "/live",
    "/stream",
    "/api/ws",
    "/api/socket",
    "/realtime",
    "/push",
]

INJECT_PAYLOADS = [
    '{"type":"ping","data":"<script>alert(1)</script>"}',
    '{"type":"msg","data":"\'OR 1=1--"}',
    '{"type":"cmd","data":"$(id)"}',
    '{"type":"user","id":1}',
    '{"type":"user","id":"../../../etc/passwd"}',
    '{"action":"subscribe","channel":"admin"}',
    '{"action":"getUser","userId":1}',
    '{"action":"getUser","userId":2}',
    '{"__proto__":{"admin":true}}',
    '{"constructor":{"prototype":{"admin":true}}}',
]


class WebSocketFuzzer:
    def __init__(self, target: str, session=None, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.results: List[Dict] = []

    def _discover_ws(self) -> List[str]:
        found = []
        for path in WS_PATHS:
            url = self.target + path
            try:
                resp = self.session.get(
                    url,
                    timeout=5,
                    verify=False,
                    headers={"Upgrade": "websocket", "Connection": "Upgrade"},
                )
                if resp.status_code in (101, 200, 400, 426):
                    found.append(
                        url.replace("http://", "ws://").replace("https://", "wss://")
                    )
            except Exception:
                pass
        return found

    def _fuzz_ws(self, ws_url: str) -> List[Dict]:
        findings = []
        try:
            import websocket
        except ImportError:
            console.print(
                "  [dim]websocket-client not installed. Run: pip install websocket-client[/dim]"
            )
            return self._simulate_findings(ws_url)

        for payload in INJECT_PAYLOADS:
            try:
                ws = websocket.create_connection(ws_url, timeout=self.timeout)
                ws.send(payload)
                time.sleep(0.5)
                resp = ws.recv()
                ws.close()

                body = resp.lower() if resp else ""

                if any(s in body for s in ["<script>", "alert(", "error in sql"]):
                    findings.append(
                        {
                            "url": ws_url,
                            "type": "WebSocket — XSS/Injection",
                            "severity": "high",
                            "cvss": 8.2,
                            "detail": f"Payload reflected in WS response: {payload[:80]}",
                            "evidence": resp[:200],
                            "owasp": "A03:2021 – Injection",
                            "remediation": "Sanitize all WebSocket message inputs server-side.",
                        }
                    )

                if "admin" in body or "true" in body and "admin" in payload:
                    findings.append(
                        {
                            "url": ws_url,
                            "type": "WebSocket — Prototype Pollution / Privilege Escalation",
                            "severity": "critical",
                            "cvss": 9.0,
                            "detail": f"Server accepted prototype pollution: {payload[:80]}",
                            "evidence": resp[:200],
                            "owasp": "A08:2021 – Software and Data Integrity Failures",
                            "remediation": "Validate and sanitize WS messages. Use JSON schema validation.",
                        }
                    )

                if '"userId":2' in payload and resp and len(resp) > 20:
                    findings.append(
                        {
                            "url": ws_url,
                            "type": "WebSocket — IDOR via Message",
                            "severity": "high",
                            "cvss": 7.5,
                            "detail": "Different user data returned via WS userId field manipulation.",
                            "evidence": resp[:200],
                            "owasp": "A01:2021 – Broken Access Control",
                            "remediation": "Authorize WebSocket messages server-side per user.",
                        }
                    )

            except Exception:
                pass

        return findings

    def _simulate_findings(self, ws_url: str) -> List[Dict]:
        """Fallback: detect WS endpoint and report for manual testing."""
        return [
            {
                "url": ws_url,
                "type": "WebSocket — Endpoint Detected (Manual Test Required)",
                "severity": "info",
                "cvss": 0.0,
                "detail": (
                    f"WebSocket endpoint found at {ws_url}. "
                    "Install websocket-client (pip install websocket-client) for full fuzzing. "
                    "Manually test: XSS in messages, IDOR via userId, prototype pollution."
                ),
                "evidence": f"WS endpoint: {ws_url}",
                "owasp": "A03:2021 – Injection",
                "remediation": "Validate all incoming WebSocket message fields server-side.",
            }
        ]

    def _check_no_auth(self, ws_url: str) -> Optional[Dict]:
        """Check if WS connects without any authentication."""
        try:
            import websocket

            ws = websocket.create_connection(ws_url, timeout=5)
            ws.close()
            return {
                "url": ws_url,
                "type": "WebSocket — No Authentication Required",
                "severity": "high",
                "cvss": 7.5,
                "detail": "WebSocket connection established without credentials or token.",
                "evidence": f"Connected to {ws_url} without auth",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "remediation": "Require valid session token / JWT in WS handshake headers.",
            }
        except Exception:
            pass
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ WebSocket Fuzzer on {self.target}[/bold yellow]"
        )
        ws_urls = self._discover_ws()

        if not ws_urls:
            console.print("  [dim]No WebSocket endpoints found[/dim]")
            return []

        console.print(f"  [green]Found {len(ws_urls)} WebSocket endpoint(s)[/green]")

        for ws_url in ws_urls:
            no_auth = self._check_no_auth(ws_url)
            if no_auth:
                self.results.append(no_auth)
            findings = self._fuzz_ws(ws_url)
            self.results.extend(findings)

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} WebSocket issue(s) found[/]")
        return self.results
