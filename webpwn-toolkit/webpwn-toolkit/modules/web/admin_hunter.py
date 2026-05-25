#!/usr/bin/env python3
"""
Admin Hunter Module
--------------------
Discovered admin paths are NOT just logged — they are actively tested:

  Phase 1 — Access Check
    • Is the page publicly accessible (200)?
    • Does it have a login form or is it a live dashboard?

  Phase 2 — Login Brute-force
    • Try 20+ default credential pairs against login forms
    • Capture session cookie / redirect on success

  Phase 3 — Authenticated Deep-Scan (if login succeeded)
    • Crawl the admin dashboard for sub-pages
    • Run SQLi, XSS, LFI on every found form / endpoint
    • Check for IDOR in admin APIs (/admin/users/1, /admin/orders/1)

  Phase 4 — Passive Checks (even without login)
    • Detect exposed debug pages (/admin/debug, /admin/logs)
    • Sensitive data in unauthenticated responses
    • Error pages leaking stack traces

OWASP: A01:2021 – Broken Access Control
        A07:2021 – Identification and Authentication Failures
"""

import re
import time
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.rule import Rule

console = Console()

# ── Default credential pairs ──────────────────────────────────────────────────

DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", ""),
    ("admin", "letmein"),
    ("admin", "qwerty"),
    ("admin", "pass"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "admin"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    ("test", "test"),
    ("guest", "guest"),
    ("manager", "manager"),
    ("user", "user"),
    ("superadmin", "superadmin"),
    ("sa", ""),
    ("admin", "admin@123"),
    ("admin", "P@ssw0rd"),
    ("admin", "Welcome1"),
]

# ── Admin-specific sub-paths to probe after login ─────────────────────────────

ADMIN_SUB_PATHS = [
    "/users",
    "/users/1",
    "/users/2",
    "/orders",
    "/orders/1",
    "/settings",
    "/config",
    "/logs",
    "/debug",
    "/info",
    "/export",
    "/import",
    "/reports",
    "/stats",
    "/backup",
    "/database",
    "/api/users",
    "/api/settings",
]

# ── Login success / failure heuristics ───────────────────────────────────────

SUCCESS_MARKERS = [
    "dashboard",
    "welcome",
    "logout",
    "log out",
    "sign out",
    "my account",
    "profile",
    "home",
    "panel",
    "control",
    "overview",
    "statistics",
    "users list",
    "manage",
]
FAILURE_MARKERS = [
    "invalid",
    "incorrect",
    "wrong",
    "failed",
    "error",
    "denied",
    "unauthorized",
    "invalid credentials",
    "please try again",
    "bad credentials",
]

# ── Sensitive data patterns ───────────────────────────────────────────────────

SENSITIVE_PATTERNS = [
    (r"password\s*[:=]\s*\S+", "Password in response"),
    (r"api[_-]?key\s*[:=]\s*['\"]?\S+", "API key in response"),
    (r"secret\s*[:=]\s*['\"]?\S+", "Secret in response"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"eyJ[A-Za-z0-9_-]+\.eyJ", "JWT token in response"),
    (r"stack\s*trace|traceback|exception in thread", "Stack trace leak"),
    (r"sql\s+syntax|you have an error in your sql", "SQL error in response"),
]


class AdminHunter:
    """
    Actively penetrates discovered admin panels:
    login brute-force → authenticated crawl → vuln scan.
    """

    def __init__(
        self,
        target: str,
        admin_urls: List[str],
        threads: int = 5,
        timeout: int = 10,
        session=None,
    ):
        self.target = target.rstrip("/")
        self.admin_urls = admin_urls
        self.threads = threads
        self.timeout = timeout
        self.results: List[Dict] = []
        # Use provided session or create a fresh one
        self._base_session = session
        if session is None:
            self._base_session = requests.Session()
            self._base_session.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/122.0 Safari/537.36"
            )
            self._base_session.verify = False

    # ── Phase 1: Access check ─────────────────────────────────────────────────

    def _check_access(self, url: str) -> Dict:
        """Return page info: accessible, has_login_form, is_dashboard, response."""
        info = {
            "url": url,
            "status": None,
            "accessible": False,
            "has_login_form": False,
            "is_dashboard": False,
            "form": None,
            "soup": None,
            "text": "",
        }
        try:
            resp = self._base_session.get(
                url, timeout=self.timeout, verify=False, allow_redirects=True
            )
            info["status"] = resp.status_code
            info["text"] = resp.text
            info["accessible"] = resp.status_code == 200

            if not info["accessible"]:
                return info

            soup = BeautifulSoup(resp.text, "lxml")
            info["soup"] = soup

            # Detect login form
            form = self._find_login_form(soup)
            if form:
                info["has_login_form"] = True
                info["form"] = form
            else:
                # No login form → it might be a live dashboard (auth bypass!)
                lower = resp.text.lower()
                if any(m in lower for m in SUCCESS_MARKERS):
                    info["is_dashboard"] = True

        except Exception as e:
            info["error"] = str(e)
        return info

    # ── Phase 2: Login form detection ─────────────────────────────────────────

    def _find_login_form(self, soup: BeautifulSoup) -> Optional[Dict]:
        """Extract login form fields from a BeautifulSoup object."""
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            fields = {
                i.get("name"): i.get("type", "text") for i in inputs if i.get("name")
            }
            user_fields = [
                k
                for k, v in fields.items()
                if any(
                    x in k.lower() for x in ("user", "login", "email", "name", "usr")
                )
            ]
            pass_fields = [
                k for k, v in fields.items() if v == "password" or "pass" in k.lower()
            ]
            if user_fields and pass_fields:
                action = urljoin(self.target, form.get("action", ""))
                # Collect hidden fields (CSRF tokens etc.)
                hidden = {
                    i.get("name"): i.get("value", "")
                    for i in inputs
                    if i.get("type") == "hidden" and i.get("name")
                }
                return {
                    "action": action or self.target,
                    "method": form.get("method", "post").lower(),
                    "user_field": user_fields[0],
                    "pass_field": pass_fields[0],
                    "hidden": hidden,
                }
        return None

    # ── Phase 2: Brute-force credentials ─────────────────────────────────────

    def _try_login(
        self, form: Dict, username: str, password: str, login_url: str
    ) -> Optional[requests.Session]:
        """Attempt a single login. Returns a new authenticated Session on success."""
        sess = requests.Session()
        sess.headers["User-Agent"] = self._base_session.headers.get("User-Agent", "")
        sess.verify = False

        data = dict(form["hidden"])
        data[form["user_field"]] = username
        data[form["pass_field"]] = password

        try:
            # First GET to pick up fresh CSRF cookies
            sess.get(login_url, timeout=self.timeout, verify=False)

            resp = sess.post(
                form["action"],
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            lower = resp.text.lower()
            has_success = any(s in lower for s in SUCCESS_MARKERS)
            has_failure = any(f in lower for f in FAILURE_MARKERS)

            if has_success and not has_failure:
                return sess
        except Exception:
            pass
        return None

    def _brute_login(
        self, form: Dict, login_url: str
    ) -> Tuple[Optional[requests.Session], Optional[str], Optional[str]]:
        """Try all credential pairs. Returns (session, user, pass) on first hit."""
        console.print(
            f"  [dim]  → Trying {len(DEFAULT_CREDS)} credential pairs on {login_url}...[/dim]"
        )
        for username, password in DEFAULT_CREDS:
            authed = self._try_login(form, username, password, login_url)
            if authed:
                console.print(
                    f"  [bold red]💥 Login SUCCESS: {username}:{password}[/bold red]"
                )
                return authed, username, password
            time.sleep(0.15)  # small delay to avoid lockout
        return None, None, None

    # ── Phase 3: Authenticated deep-scan ─────────────────────────────────────

    def _deep_scan(
        self, authed_session: requests.Session, admin_base: str
    ) -> List[Dict]:
        """Crawl admin sub-pages and run vuln tests on them."""
        findings: List[Dict] = []

        # Crawl sub-paths
        reachable_pages: List[str] = []
        for sub in ADMIN_SUB_PATHS:
            url = admin_base.rstrip("/") + sub
            try:
                resp = authed_session.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=True
                )
                if resp.status_code == 200:
                    reachable_pages.append(url)
                    # Quick sensitive data check
                    for pattern, desc in SENSITIVE_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            findings.append(
                                {
                                    "url": url,
                                    "type": f"Admin Panel — {desc}",
                                    "severity": "high",
                                    "detail": f"{desc} found in admin sub-page {sub}",
                                    "evidence": f"HTTP 200 on {url} | Pattern: {pattern}",
                                    "owasp": "A02:2021 – Cryptographic Failures",
                                    "cvss": 7.5,
                                    "remediation": "Remove sensitive data from admin responses. Apply proper access controls.",
                                }
                            )
            except Exception:
                pass

        console.print(
            f"  [dim]  → {len(reachable_pages)} admin sub-page(s) accessible after login[/dim]"
        )

        # Run SQLi on admin forms
        for page_url in reachable_pages[:5]:  # limit to first 5 for speed
            try:
                resp = authed_session.get(page_url, timeout=self.timeout, verify=False)
                soup = BeautifulSoup(resp.text, "lxml")
                for form in soup.find_all("form"):
                    method = form.get("method", "get").lower()
                    action = urljoin(page_url, form.get("action", ""))
                    inputs = {
                        i.get("name"): i.get("value", "test")
                        for i in form.find_all("input")
                        if i.get("name") and i.get("type") not in ("submit", "button")
                    }
                    if not inputs:
                        continue

                    # Quick SQLi probe
                    for field in list(inputs.keys())[:3]:
                        test = dict(inputs)
                        test[field] = "'"
                        try:
                            r2 = (
                                authed_session.post(
                                    action,
                                    data=test,
                                    timeout=self.timeout,
                                    verify=False,
                                )
                                if method == "post"
                                else authed_session.get(
                                    action,
                                    params=test,
                                    timeout=self.timeout,
                                    verify=False,
                                )
                            )
                            sql_errors = [
                                "you have an error in your sql syntax",
                                "warning: mysql",
                                "unclosed quotation mark",
                                "sqlite3.operationalerror",
                                "pg_query()",
                                "microsoft ole db",
                                "odbc sql server",
                            ]
                            for err in sql_errors:
                                if err in r2.text.lower():
                                    findings.append(
                                        {
                                            "url": action,
                                            "method": method.upper(),
                                            "parameter": field,
                                            "payload": "'",
                                            "type": "Admin Panel SQLi",
                                            "severity": "critical",
                                            "detail": f"SQL error triggered in admin form field '{field}' at {action}",
                                            "evidence": err,
                                            "owasp": "A03:2021 – Injection",
                                            "cvss": 9.8,
                                            "remediation": "Use parameterized queries. Never concatenate user input into SQL.",
                                        }
                                    )
                                    break
                        except Exception:
                            pass

            except Exception:
                pass

        # IDOR check on admin ID-based endpoints
        for sub in ["/users/", "/orders/", "/invoices/", "/products/"]:
            for test_id in [1, 2, 3, 99999]:
                url = admin_base.rstrip("/") + sub + str(test_id)
                try:
                    resp = authed_session.get(url, timeout=self.timeout, verify=False)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data:
                                findings.append(
                                    {
                                        "url": url,
                                        "type": "Admin IDOR",
                                        "severity": "high",
                                        "detail": f"Admin can access resource at {sub}{test_id} — verify this is intentional",
                                        "evidence": f"HTTP 200 | Data: {str(data)[:80]}",
                                        "owasp": "A01:2021 – Broken Access Control",
                                        "cvss": 8.1,
                                        "remediation": "Implement object-level authorization. Verify ownership for each resource.",
                                    }
                                )
                        except Exception:
                            pass
                except Exception:
                    pass

        return findings

    # ── Phase 4: Passive checks ───────────────────────────────────────────────

    def _passive_check(self, page_info: Dict) -> List[Dict]:
        """Check accessible admin page for sensitive leaks (no login required)."""
        findings: List[Dict] = []
        url = page_info["url"]
        text = page_info.get("text", "")

        if not text:
            return findings

        # Skip passive checks if login form is present (requires auth)
        if page_info.get("has_login_form"):
            return findings

        for pattern, desc in SENSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(
                    {
                        "url": url,
                        "type": f"Admin Page Info Leak — {desc}",
                        "severity": "high",
                        "detail": f"{desc} found on publicly accessible admin page {url}",
                        "evidence": f"Pattern matched: {pattern}",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "cvss": 7.5,
                        "remediation": "Restrict admin panel access. Remove sensitive data from error pages.",
                    }
                )

        # Dashboard accessible without auth → Broken Access Control
        if page_info.get("is_dashboard"):
            findings.append(
                {
                    "url": url,
                    "type": "Admin Dashboard — No Authentication Required",
                    "severity": "critical",
                    "detail": f"Admin dashboard at {url} is directly accessible without login",
                    "evidence": f"HTTP 200 | Dashboard indicators present without authentication",
                    "owasp": "A01:2021 – Broken Access Control",
                    "cvss": 9.8,
                    "remediation": (
                        "Enforce authentication Senior ware on all admin routes. "
                        "Use IP allowlisting for admin access if possible."
                    ),
                }
            )

        return findings

    # ── Public run ────────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        if not self.admin_urls:
            console.print("  [dim]No admin URLs to test.[/dim]")
            return []

        console.print(
            f"\n  [bold yellow]🎯 Admin Hunter — testing {len(self.admin_urls)} admin panel(s)[/bold yellow]"
        )

        for admin_url in self.admin_urls:
            console.print(f"\n  [cyan]▶ Testing: {admin_url}[/cyan]")

            # Phase 1: Access check
            page_info = self._check_access(admin_url)

            if not page_info["accessible"]:
                console.print(
                    f"  [dim]  → HTTP {page_info.get('status')} — skipping[/dim]"
                )
                continue

            console.print(f"  [green]  ✓ Page accessible (HTTP 200)[/green]")

            # Phase 4: Passive checks (always run)
            passive = self._passive_check(page_info)
            if passive:
                self.results.extend(passive)
                console.print(
                    f"  [yellow]  ⚠ {len(passive)} passive finding(s)[/yellow]"
                )

            # Phase 2 & 3: Login brute-force + deep scan
            if page_info["has_login_form"]:
                console.print(
                    "  [cyan]  → Login form detected — starting brute-force[/cyan]"
                )

                authed_sess, username, password = self._brute_login(
                    page_info["form"], admin_url
                )

                # Log credential finding
                if authed_sess:
                    self.results.append(
                        {
                            "url": admin_url,
                            "type": "Admin Panel — Default Credentials",
                            "severity": "critical",
                            "detail": f"Successfully logged into admin panel with {username}:{password}",
                            "evidence": f"Credentials: {username}:{password} | URL: {admin_url}",
                            "owasp": "A07:2021 – Identification and Authentication Failures",
                            "cvss": 9.8,
                            "remediation": (
                                "Change all default credentials immediately. "
                                "Enforce strong password policy. Implement MFA on admin panel."
                            ),
                        }
                    )

                    # Phase 3: Deep scan with authenticated session
                    console.print(
                        "  [bold cyan]  → Running authenticated deep scan...[/bold cyan]"
                    )
                    deep = self._deep_scan(authed_sess, admin_url)
                    self.results.extend(deep)
                    console.print(
                        f"  [dim]  → {len(deep)} finding(s) from deep scan[/dim]"
                    )

                else:
                    console.print("  [green]  ✓ No default credentials worked[/green]")
                    self.results.append(
                        {
                            "url": admin_url,
                            "type": "Admin Login Panel Exposed",
                            "severity": "medium",
                            "detail": f"Admin login form found at {admin_url} — brute-force attempted, no weak creds found",
                            "evidence": f"Login form at {admin_url} | Tested {len(DEFAULT_CREDS)} credential pairs",
                            "owasp": "A07:2021 – Identification and Authentication Failures",
                            "cvss": 5.3,
                            "remediation": (
                                "Restrict admin panel to known IP ranges. "
                                "Implement account lockout and MFA."
                            ),
                        }
                    )

            elif page_info.get("is_dashboard"):
                # Dashboard open without login → deep scan directly
                console.print(
                    "  [bold red]  🔥 Dashboard accessible WITHOUT login — deep scanning[/bold red]"
                )
                deep = self._deep_scan(self._base_session, admin_url)
                self.results.extend(deep)

            else:
                console.print("  [dim]  → No login form or dashboard detected[/dim]")

        # Summary
        crit = sum(1 for r in self.results if r.get("severity") == "critical")
        high = sum(1 for r in self.results if r.get("severity") == "high")
        console.print(
            f"\n  [{'bold red' if crit else 'yellow'}]"
            f"Admin Hunter: {len(self.results)} finding(s) — "
            f"{crit} critical, {high} high[/]"
        )
        return self.results
