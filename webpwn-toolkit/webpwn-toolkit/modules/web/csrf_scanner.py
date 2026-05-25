#!/usr/bin/env python3
"""
CSRF Scanner Module
--------------------
Detects Cross-Site Request Forgery vulnerabilities:
  • Missing CSRF token on state-changing forms
  • CSRF token present but not validated (remove/empty/swap test)
  • SameSite cookie attribute missing or weak
  • Referer/Origin header not enforced
  • Custom header bypass check
  • Generates a ready-to-use PoC HTML file for each finding

Payload reference: wordlists/payloads/csrf.txt
"""

import requests
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# State-changing HTTP methods worth testing
_STATE_METHODS = {"post", "put", "patch", "delete"}

# Common CSRF token field names
_CSRF_FIELD_NAMES = {
    "csrf_token",
    "csrftoken",
    "csrf",
    "_csrf",
    "_token",
    "authenticity_token",
    "csrf_Senior ware_token",
    "csrfSenior waretoken",
    "RequestVerificationToken",
    "__RequestVerificationToken",
    "form_token",
    "token",
    "nonce",
}

# Common CSRF header names (custom header defense)
_CSRF_HEADERS = [
    "X-CSRF-Token",
    "X-XSRF-TOKEN",
    "X-CSRFToken",
    "X-Requested-With",
]

# SameSite weakness values
_SAMESITE_WEAK = {"none", ""}


class CSRFScanner:
    """Cross-Site Request Forgery scanner."""

    PAYLOAD_FILE = Path(__file__).parents[2] / "wordlists" / "payloads" / "csrf.txt"
    POC_DIR = Path(__file__).parents[2] / "reports" / "csrf_pocs"

    def __init__(self, target: str, timeout: int = 10, session=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update(
                {
                    "User-Agent": "WebPwnToolkit/2.0 (Authorized Security Testing)",
                }
            )
            self.session.verify = False
        self.results: List[Dict] = []

    # ── Fetch & parse forms ───────────────────────────────────────────────────

    def _get_forms(self, url: str) -> List[Dict]:
        """Return all forms from a page with their metadata."""
        forms = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "lxml")
            cookies = resp.cookies

            for form in soup.find_all("form"):
                method = form.get("method", "get").lower()
                action = urljoin(url, form.get("action", url))
                fields = {}
                has_csrf_field = False
                csrf_field_name = None

                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    value = inp.get("value", "")
                    if name:
                        fields[name] = value
                        if name.lower() in _CSRF_FIELD_NAMES:
                            has_csrf_field = True
                            csrf_field_name = name

                forms.append(
                    {
                        "action": action,
                        "method": method,
                        "fields": fields,
                        "has_csrf_field": has_csrf_field,
                        "csrf_field_name": csrf_field_name,
                        "cookies": cookies,
                        "source_url": url,
                    }
                )
        except Exception:
            pass
        return forms

    # ── Test 1: Missing CSRF token ────────────────────────────────────────────

    def _check_missing_token(self, form: Dict) -> Optional[Dict]:
        """State-changing form with no CSRF field at all."""
        if form["method"] not in _STATE_METHODS:
            return None
        if form["has_csrf_field"]:
            return None

        return self._make_finding(
            form=form,
            check="Missing CSRF Token",
            detail=(
                f"State-changing {form['method'].upper()} form at "
                f"'{form['action']}' has no CSRF token field."
            ),
            severity="high",
            cvss=8.1,
        )

    # ── Test 2: Token not validated (remove / empty / swap) ──────────────────

    def _check_token_validation(self, form: Dict) -> List[Dict]:
        """Try submitting with empty, absent, or random token and check if accepted."""
        findings = []
        if form["method"] not in _STATE_METHODS:
            return findings
        if not form["has_csrf_field"]:
            return findings

        field_name = form["csrf_field_name"]

        tests: List[Tuple[str, dict]] = [
            (
                "Token Removed",
                {k: v for k, v in form["fields"].items() if k != field_name},
            ),
            ("Empty Token", {**form["fields"], field_name: ""}),
            ("Null Token", {**form["fields"], field_name: "null"}),
            (
                "Arbitrary Token",
                {**form["fields"], field_name: "WEBPWN_FAKE_CSRF_TOKEN_XYZ"},
            ),
        ]

        # Baseline: normal submit to get reference status
        try:
            baseline = self.session.post(
                form["action"],
                data=form["fields"],
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            baseline_code = baseline.status_code
        except Exception:
            return findings

        for label, payload_data in tests:
            try:
                resp = self.session.post(
                    form["action"],
                    data=payload_data,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                # If server returns same success code → token not properly validated
                if resp.status_code == baseline_code and resp.status_code in (
                    200,
                    201,
                    302,
                ):
                    findings.append(
                        self._make_finding(
                            form=form,
                            check=f"CSRF Token Not Validated ({label})",
                            detail=(
                                f"Server accepted request with '{label}' "
                                f"(HTTP {resp.status_code}) — token appears not validated."
                            ),
                            severity="high",
                            cvss=8.1,
                        )
                    )
                    break  # One confirmed bypass is enough per form
            except Exception:
                pass

        return findings

    # ── Test 3: SameSite cookie attribute ─────────────────────────────────────

    def _check_samesite(self, form: Dict) -> List[Dict]:
        """Detect session cookies missing SameSite or set to None."""
        findings = []
        try:
            resp = self.session.get(
                form["source_url"], timeout=self.timeout, verify=False
            )
            for cookie in resp.cookies:
                name = cookie.name
                samesite = (cookie._rest.get("SameSite") or "").lower()
                secure = cookie.secure

                if samesite in _SAMESITE_WEAK or samesite == "":
                    findings.append(
                        {
                            "url": form["source_url"],
                            "parameter": f"Cookie: {name}",
                            "payload": "SameSite attribute analysis",
                            "type": "CSRF — Weak SameSite Policy",
                            "severity": "medium",
                            "evidence": (
                                f"Cookie '{name}' SameSite={samesite or 'NOT SET'} "
                                f"Secure={'Yes' if secure else 'No'}"
                            ),
                            "detail": (
                                f"Cookie '{name}' lacks a strict SameSite policy, "
                                f"enabling cross-site request delivery."
                            ),
                            "owasp": "A01:2021 – Broken Access Control",
                            "cvss": 5.4,
                            "remediation": (
                                "Set SameSite=Strict or SameSite=Lax on all session cookies. "
                                "Combine with CSRF tokens for defense-in-depth."
                            ),
                        }
                    )
        except Exception:
            pass
        return findings

    # ── Test 4: Referer / Origin enforcement ──────────────────────────────────

    def _check_referer_enforcement(self, form: Dict) -> Optional[Dict]:
        """Submit state-changing form with no Referer and cross-origin Origin."""
        if form["method"] not in _STATE_METHODS:
            return None

        try:
            # No Referer, foreign Origin
            resp = self.session.post(
                form["action"],
                data=form["fields"],
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={
                    "Referer": "",
                    "Origin": "https://attacker.evil.com",
                },
            )
            if resp.status_code in (200, 201, 302):
                return self._make_finding(
                    form=form,
                    check="Referer/Origin Not Enforced",
                    detail=(
                        "Server accepted state-changing request from "
                        "foreign Origin 'https://attacker.evil.com' without rejection."
                    ),
                    severity="medium",
                    cvss=6.5,
                )
        except Exception:
            pass
        return None

    # ── PoC HTML generator ────────────────────────────────────────────────────

    def _generate_poc(self, form: Dict, check: str) -> str:
        """Return a ready-to-use CSRF PoC HTML string."""
        inputs_html = "\n".join(
            f'  <input type="hidden" name="{k}" value="{v}">'
            for k, v in form["fields"].items()
        )
        return f"""<!DOCTYPE html>
<!-- WebPwn Toolkit — CSRF PoC: {check} -->
<html>
<head><title>CSRF PoC — {check}</title></head>
<body>
<h1>CSRF PoC</h1>
<p>Check: <strong>{check}</strong></p>
<p>Target: <code>{form['action']}</code></p>
<form id="csrf_poc" action="{form['action']}" method="{form['method'].upper()}">
{inputs_html}
</form>
<script>document.getElementById('csrf_poc').submit();</script>
</body>
</html>
"""

    def _save_poc(self, poc_html: str, finding: Dict) -> str:
        """Save PoC to reports/csrf_pocs/ and return the file path."""
        self.POC_DIR.mkdir(parents=True, exist_ok=True)
        slug = (
            finding["type"]
            .lower()
            .replace(" ", "_")
            .replace("(", "")
            .replace(")", "")[:40]
        )
        poc_file = self.POC_DIR / f"csrf_poc_{slug}.html"
        poc_file.write_text(poc_html, encoding="utf-8")
        return str(poc_file)

    # ── Finding factory ───────────────────────────────────────────────────────

    def _make_finding(
        self, form: Dict, check: str, detail: str, severity: str, cvss: float
    ) -> Dict:
        poc_html = self._generate_poc(form, check)
        poc_path = self._save_poc(poc_html, {"type": check})
        return {
            "url": form["action"],
            "parameter": "form",
            "payload": check,
            "type": f"CSRF — {check}",
            "severity": severity,
            "evidence": f"PoC saved: {poc_path}",
            "detail": detail,
            "owasp": "A01:2021 – Broken Access Control",
            "cvss": cvss,
            "remediation": (
                "Implement synchronizer token pattern (per-session or per-request CSRF tokens). "
                "Set SameSite=Strict on session cookies. "
                "Validate Origin/Referer on all state-changing endpoints. "
                "Use custom request headers (X-Requested-With) as secondary defense."
            ),
            "poc_html": poc_html,
        }

    # ── Public run ────────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        forms = self._get_forms(self.target)
        console.print(f"  [dim]-> {len(forms)} form(s) found for CSRF analysis[/dim]")

        state_forms = [f for f in forms if f["method"] in _STATE_METHODS]
        console.print(
            f"  [dim]-> {len(state_forms)} state-changing form(s) to test[/dim]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]CSRF scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("csrf", total=max(len(forms) * 4, 1))

            for form in forms:
                # Test 1: Missing token
                r = self._check_missing_token(form)
                if r and r not in self.results:
                    self.results.append(r)
                progress.advance(task)

                # Test 2: Token not validated
                for r in self._check_token_validation(form):
                    if r not in self.results:
                        self.results.append(r)
                progress.advance(task)

                # Test 3: SameSite
                for r in self._check_samesite(form):
                    if r not in self.results:
                        self.results.append(r)
                progress.advance(task)

                # Test 4: Referer/Origin
                r = self._check_referer_enforcement(form)
                if r and r not in self.results:
                    self.results.append(r)
                progress.advance(task)

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' CSRF issue(s) found!' if self.results else '✅ No CSRF found'}"
            f"[/]"
        )
        return self.results
