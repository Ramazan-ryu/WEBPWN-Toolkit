#!/usr/bin/env python3
"""
Directory & File Bruteforcer
-----------------------------
• Multi-threaded path enumeration
• Backup / config file detection
• Status-code + content-length analysis
"""

import re
import requests
import concurrent.futures
from pathlib import Path
from urllib.parse import urljoin
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# Interesting status codes to report
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 500}

# ── WAF / CDN challenge page signatures ───────────────────────────────────────
# When Cloudflare or similar CDNs block a request, they return HTTP 200
# but with a JavaScript challenge page. We must detect these to avoid
# false positives on ALL paths.
WAF_SIGNATURES = [
    "just a moment",  # Cloudflare
    "enable javascript and cookies",  # Cloudflare
    "cf-mitigated",  # Cloudflare header
    "challenges.cloudflare.com",  # Cloudflare
    "_cf_chl_opt",  # Cloudflare JS var
    "ray id",  # Cloudflare Ray ID
    "ddos-guard",  # DDoS-Guard
    "sucuri website firewall",  # Sucuri
    "imperva",  # Imperva
    "access denied | waf",  # Generic WAF
    "please wait while we check your browser",  # Generic
    "your request has been blocked",  # Generic
]

# Sensitive extensions to try
EXTENSIONS = [
    "",
    ".php",
    ".html",
    ".txt",
    ".bak",
    ".old",
    ".zip",
    ".tar.gz",
    ".sql",
    ".log",
    ".conf",
    ".env",
    ".json",
    ".xml",
]

# Backup / config patterns (always check)
SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    ".htaccess",
    "web.config",
    "config.php",
    "config.yml",
    "config.yaml",
    "settings.py",
    "database.yml",
    "wp-config.php",
    "phpinfo.php",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "admin/",
    "administrator/",
    "wp-admin/",
    "phpmyadmin/",
    "adminer.php",
    "api/",
    "api/v1/",
    "api/v2/",
    "swagger.json",
    "openapi.json",
    "api-docs/",
    "console/",
    "manager/",
    "cpanel/",
    ".DS_Store",
    "thumbs.db",
    "debug.log",
    "server-status",
    "server-info",
    "actuator/",
    "actuator/env",
    "actuator/health",
    "graphql",
    "graphiql",
]


class DirBruteforcer:
    """Directory and file enumeration scanner."""

    WORDLIST_FILE = Path(__file__).parents[2] / "wordlists" / "directories.txt"

    FALLBACK_DIRS = [
        "admin",
        "login",
        "dashboard",
        "api",
        "upload",
        "uploads",
        "backup",
        "backups",
        "test",
        "dev",
        "old",
        "new",
        "tmp",
        "temp",
        "config",
        "configs",
        "data",
        "db",
        "database",
        "logs",
        "log",
        "static",
        "assets",
        "media",
        "images",
        "files",
        "docs",
        "documentation",
        "help",
        "support",
        "shop",
        "store",
        "checkout",
        "user",
        "users",
        "account",
        "accounts",
        "profile",
        "auth",
        "register",
        "signup",
        "forgot",
        "reset",
        "logout",
        "server",
        "status",
        "health",
        "monitor",
        "metrics",
        "console",
        "manager",
        "cpanel",
        "phpmyadmin",
    ]

    def __init__(self, target: str, threads: int = 20, timeout: int = 8, session=None):
        self.target = target.rstrip("/")
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

    # ── Wordlist loader ────────────────────────────────────────────────

    def _load_words(self) -> List[str]:
        if self.WORDLIST_FILE.exists():
            with open(self.WORDLIST_FILE) as f:
                return [l.strip() for l in f if l.strip()]
        return self.FALLBACK_DIRS

    # ── WAF / Cloudflare detection ─────────────────────────────────────

    @staticmethod
    def _is_waf_block(resp: requests.Response) -> bool:
        """
        Return True if the response is a WAF/CDN challenge page
        (e.g. Cloudflare "Just a moment..."), not a real resource.
        These always return HTTP 200 but contain JS challenge code.
        """
        # Check headers first (faster)
        cf_headers = [
            resp.headers.get("cf-mitigated", ""),
            resp.headers.get("server", ""),
        ]
        if any("cloudflare" in h.lower() for h in cf_headers):
            # Server is Cloudflare — check if body is a challenge
            body_lower = resp.text[:2000].lower()
            if any(sig in body_lower for sig in WAF_SIGNATURES):
                return True

        # Check body regardless of server header
        body_lower = resp.text[:2000].lower()
        return sum(1 for sig in WAF_SIGNATURES if sig in body_lower) >= 2

    # ── Get baseline (404 size) ────────────────────────────────────────

    def _baseline_size(self) -> int:
        try:
            resp = self.session.get(
                f"{self.target}/WEBPWN_NONEXISTENT_8f4d2a",
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            # If baseline itself is a WAF block, note this
            if self._is_waf_block(resp):
                console.print(
                    "  [yellow]⚠ WAF/Cloudflare detected — "
                    "responses will be filtered for challenge pages[/yellow]"
                )
            return len(resp.content)
        except Exception:
            return -1

    # ── Probe single path ──────────────────────────────────────────────

    def _probe(self, path: str, baseline: int) -> Optional[Dict]:
        url = urljoin(self.target + "/", path)
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=False, allow_redirects=False
            )

            code = resp.status_code
            size = len(resp.content)

            if code not in INTERESTING_CODES:
                return None

            # ── KEY FIX: Skip Cloudflare/WAF challenge pages ───────────
            # These return HTTP 200 for EVERY path, causing mass false
            # positives. Detect them by body content and skip.
            if self._is_waf_block(resp):
                return None

            # Skip if response size matches 404 baseline closely (false positive/SPA)
            if code == 404 or (baseline > 0 and abs(size - baseline) < 100):
                return None

            severity = self._classify_severity(path, code)

            return {
                "url": url,
                "type": "Exposed Sensitive Path",
                "path": path,
                "status_code": code,
                "size": size,
                "severity": severity,
                "detail": self._detail(path, code),
                "evidence": f"HTTP {code} | Size: {size} bytes | No WAF block",
                "owasp": "A05:2021 – Security Misconfiguration",
                "cvss": self._cvss(severity),
                "remediation": self._remediation(path, code),
            }
        except Exception:
            return None

    @staticmethod
    def _classify_severity(path: str, code: int) -> str:
        very_sensitive = [
            ".env",
            ".git",
            "config",
            "backup",
            "db.",
            "sql",
            "secret",
            "password",
            "credential",
            "phpinfo",
            "wp-config",
            "adminer",
            "phpmyadmin",
            "actuator",
        ]
        if any(s in path.lower() for s in very_sensitive):
            return "critical" if code == 200 else "high"
        if code in (200, 201):
            return "medium"
        if code == 403:
            return "low"
        return "info"

    @staticmethod
    def _cvss(severity: str) -> float:
        return {
            "critical": 9.1,
            "high": 7.5,
            "medium": 5.3,
            "low": 3.1,
            "info": 0.0,
        }.get(severity, 0.0)

    @staticmethod
    def _detail(path: str, code: int) -> str:
        if ".env" in path:
            return "Environment file exposed — may contain credentials"
        if ".git" in path:
            return "Git repository exposed — source code leakage risk"
        if "backup" in path or ".zip" in path or ".tar" in path:
            return "Backup file accessible — may contain sensitive data"
        if "phpmyadmin" in path or "adminer" in path:
            return "Database management interface exposed"
        if "actuator" in path:
            return "Spring Boot Actuator exposed — may leak env/heap dumps"
        if "swagger" in path or "openapi" in path:
            return "API documentation exposed without authentication"
        if code == 403:
            return "Path exists but is forbidden — worth further investigation"
        if code == 500:
            return "Server error triggered — possible misconfiguration"
        return f"Path accessible with HTTP {code}"

    @staticmethod
    def _remediation(path: str, code: int) -> str:
        if ".env" in path or "config" in path:
            return "Move sensitive files outside web root. Never deploy .env to production."
        if ".git" in path:
            return "Block .git access in web server config. Use .gitignore properly."
        if "backup" in path:
            return "Remove backup files from web root. Store in secure, non-public storage."
        if code == 403:
            return (
                "Verify directory listing is disabled. Ensure proper access controls."
            )
        return "Review if this path should be publicly accessible. Add authentication if needed."

    # ── Admin pattern detection ────────────────────────────────────────

    ADMIN_KEYWORDS = [
        "admin",
        "administrator",
        "wp-admin",
        "dashboard",
        "backend",
        "manager",
        "cpanel",
        "control",
        "panel",
        "phpmyadmin",
        "adminer",
        "console",
        "manage",
    ]

    def _is_admin_path(self, path: str) -> bool:
        """Return True if the path looks like an admin panel."""
        p = path.lower().strip("/")
        return any(kw in p for kw in self.ADMIN_KEYWORDS)

    # ── Public run ─────────────────────────────────────────────────────

    def run(
        self,
        auto_hunt: bool = True,
        threads: int = None,
        timeout: int = None,
        session=None,
    ) -> List[Dict]:
        """
        Run directory bruteforce.
        If auto_hunt=True, automatically trigger AdminHunter
        on any discovered admin-related paths with HTTP 200.
        """
        words = self._load_words()
        baseline = self._baseline_size()

        all_paths = list(set(words + SENSITIVE_PATHS))
        console.print(
            f"  [dim]-> {len(all_paths)} paths to probe (baseline size: {baseline})[/dim]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Bruteforcing directories...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("dir", total=len(all_paths))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self._probe, p, baseline): p for p in all_paths}
                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result:
                        self.results.append(result)

        self.results.sort(key=lambda x: x["status_code"])
        console.print(
            f"  [{'yellow' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' path(s) found' if self.results else '✅ No interesting paths'}"
            f"[/]"
        )

        # ── Auto-hunt admin panels ─────────────────────────────────────
        if auto_hunt:
            admin_hits = [
                r["url"]
                for r in self.results
                if r.get("status_code") == 200
                and self._is_admin_path(r.get("path", ""))
            ]

            if admin_hits:
                console.print(
                    f"\n  [bold red]🎯 {len(admin_hits)} admin panel(s) found — "
                    f"launching Admin Hunter automatically![/bold red]"
                )
                try:
                    from modules.web.admin_hunter import AdminHunter

                    hunter = AdminHunter(
                        target=self.target,
                        admin_urls=admin_hits,
                        threads=threads or self.threads,
                        timeout=timeout or self.timeout,
                        session=session,
                    )
                    admin_findings = hunter.run()
                    self.results.extend(admin_findings)
                except Exception as e:
                    console.print(f"  [red]❌ Admin Hunter error: {e}[/red]")
            else:
                console.print("  [dim]-> No admin panels found to deep-test[/dim]")

        return self.results
