#!/usr/bin/env python3
"""
WebShell Uploader Scanner — Senior Level
--------------------------------------------
Tests file upload endpoints for restrictions bypass:
  • Null byte injection
  • Extension bypass (.php.jpg, .php5)
  • MIME type spoofing
  • Magic byte spoofing
"""

import requests
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()


class WebShellUploaderScanner(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.session = session or requests.Session()
            self.session.verify = False
            self.results = []
        self.endpoints = ["/upload", "/api/upload", "/profile/avatar", "/files"]

    def _test_upload(self, url: str) -> List[Dict]:
        findings = []

        # Fake PHP payload with GIF magic bytes
        payload_content = b"GIF89a\n<?php echo 'webpwn_shell_test'; ?>"

        test_cases = [
            ("MIME Spoofing", "shell.php", "image/gif", payload_content),
            (
                "Extension Bypass (Double)",
                "shell.php.jpg",
                "image/jpeg",
                payload_content,
            ),
            (
                "Extension Bypass (.php5)",
                "shell.php5",
                "application/x-php",
                payload_content,
            ),
            (
                "Extension Bypass (.phtml)",
                "shell.phtml",
                "application/x-php",
                payload_content,
            ),
            (
                "Extension Bypass (.phar)",
                "shell.phar",
                "application/x-php",
                payload_content,
            ),
            (
                "Extension Bypass (.inc)",
                "shell.inc",
                "application/x-php",
                payload_content,
            ),
            ("Null Byte", "shell.php%00.jpg", "image/jpeg", payload_content),
            (
                "Windows Alternate Data Stream",
                "shell.php::$DATA",
                "application/x-php",
                payload_content,
            ),
        ]

        for name, filename, mime, content in test_cases:
            files = {"file": (filename, content, mime)}
            if hasattr(self, "_post"):
                r = self._post(url, files=files)
            else:
                try:
                    r = self.session.post(
                        url, files=files, timeout=self.timeout, verify=False
                    )
                except Exception:
                    r = None

            if r and r.status_code in (200, 201):
                # If it succeeds, it might be vulnerable
                if any(
                    s in r.text.lower()
                    for s in ["success", "uploaded", "file path", "url"]
                ):
                    findings.append(
                        {
                            "url": url,
                            "type": f"Insecure File Upload ({name})",
                            "severity": "critical",
                            "cvss": 9.8,
                            "detail": f"Server accepted an executable file disguised using {name}. This can lead to Remote Code Execution (WebShell).",
                            "evidence": f"Accepted file '{filename}' with MIME '{mime}'",
                            "owasp": "A04:2021 – Insecure Design",
                            "remediation": "Validate file extensions via strict allowlist. Validate file contents. Store uploads outside the web root. Strip EXIF data.",
                        }
                    )
                    break  # One success is enough for this endpoint
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ WebShell Uploader Scanner on {self.target}[/bold yellow]"
        )
        for path in self.endpoints:
            url = self.target + path
            res = self._test_upload(url)
            for r in res:
                if r not in self.results:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} File upload issue(s) found[/]")
        return self.results
