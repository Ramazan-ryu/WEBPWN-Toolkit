#!/usr/bin/env python3
"""
Session Manager — Authenticated Scanning Support
--------------------------------------------------
Provides:
  • Login with username/password (form-based)
  • Bearer token / API key injection
  • Cookie-based session persistence
  • Session health check (verify still authenticated)
  • Rate limiting with jitter
  • Proxy support (Burp Suite / ZAP)
"""

import time
import random
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Any
from rich.console import Console

console = Console()


class RateLimiter:
    """Token-bucket rate limiter with jitter to avoid detection."""

    def __init__(self, requests_per_second: float = 10.0, jitter: float = 0.05):
        self.min_interval = 1.0 / max(requests_per_second, 0.1)
        self.jitter = jitter
        self._last_call = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_call
        sleep = self.min_interval - elapsed
        if sleep > 0:
            sleep += random.uniform(0, self.jitter)
            time.sleep(sleep)
        self._last_call = time.monotonic()


from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SessionManager:
    """
    Manages authenticated HTTP sessions for WebPwn scanners.

    Usage:
        sm = SessionManager(config)
        sm.login(target, "/login", {"username": "admin", "password": "test"})
        session = sm.get_session()
        # Pass session to any scanner
    """

    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        self._session = requests.Session()

        # ── Connection Pool & Retries ─────────────────────────────────
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(
            pool_connections=100, pool_maxsize=100, max_retries=retry_strategy
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        # ── User-Agent ────────────────────────────────────────────────
        ua = config.get("scan", {}).get(
            "user_agent", "WebPwnToolkit/2.0 (Authorized Security Testing)"
        )
        self._session.headers["User-Agent"] = ua

        # ── Proxy ─────────────────────────────────────────────────────
        proxy_cfg = config.get("proxy", {})
        if proxy_cfg.get("enabled", False):
            self._session.proxies = {
                "http": proxy_cfg.get("http", "http://127.0.0.1:8080"),
                "https": proxy_cfg.get("https", "http://127.0.0.1:8080"),
            }
            # Disable SSL verification when proxying through Burp/ZAP
            self._session.verify = False
            console.print(
                f"  [yellow]🔀 Proxy: {proxy_cfg.get('http', 'http://127.0.0.1:8080')}[/yellow]"
            )
        else:
            self._session.verify = False

        # ── Rate limiter ──────────────────────────────────────────────
        scan_cfg = config.get("scan", {})
        rps = scan_cfg.get("requests_per_second", 10)
        jitter = scan_cfg.get("jitter", 0.05)
        self.rate_limiter = RateLimiter(rps, jitter)

        # ── Auth state ────────────────────────────────────────────────
        self._auth_type = "none"
        self._auth_check = None  # URL to verify still authenticated
        self._auth_marker = None  # String present only when authenticated

    # ── Form-based login ───────────────────────────────────────────────

    def login_form(
        self,
        target: str,
        login_path: str,
        credentials: Dict[str, str],
        auth_check_url: Optional[str] = None,
        auth_marker: Optional[str] = None,
    ) -> bool:
        """
        Login via HTML form submission.

        Args:
            target:        Base URL (e.g., http://example.com)
            login_path:    Login endpoint path (e.g., /login)
            credentials:   Dict of form fields (e.g., {"username": "admin", "password": "pass"})
            auth_check_url: URL to GET after login to verify success
            auth_marker:   String present in response only when authenticated
        """
        login_url = urljoin(target, login_path)
        console.print(f"  [cyan]→ Attempting form login: {login_url}[/cyan]")

        try:
            # Get the login page first to capture CSRF token
            resp = self._session.get(login_url, timeout=10)
            soup = BeautifulSoup(resp.text, "lxml")

            # Build form data including hidden fields (CSRF)
            form_data = {}
            form = soup.find("form")
            if form:
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    value = inp.get("value", "")
                    if name:
                        form_data[name] = value

            # Override with provided credentials
            form_data.update(credentials)

            # Determine action URL
            if form:
                action = form.get("action", login_path)
                post_url = urljoin(target, action)
            else:
                post_url = login_url

            # Submit login
            self.rate_limiter.wait()
            resp = self._session.post(
                post_url,
                data=form_data,
                timeout=10,
                allow_redirects=True,
            )

            # Verify authentication
            if auth_check_url and auth_marker:
                self._auth_check = urljoin(target, auth_check_url)
                self._auth_marker = auth_marker
                if self._verify_auth():
                    console.print(
                        "  [green]✅ Login successful (authenticated)[/green]"
                    )
                    self._auth_type = "form"
                    return True
                else:
                    console.print(
                        "  [red]❌ Login failed — auth marker not found[/red]"
                    )
                    return False
            else:
                # Heuristic: check that we're no longer on login page
                if login_path not in resp.url and resp.status_code < 400:
                    console.print(
                        "  [green]✅ Login likely successful (redirected away from login)[/green]"
                    )
                    self._auth_type = "form"
                    return True
                console.print(
                    "  [yellow]⚠  Login result uncertain — no auth marker provided[/yellow]"
                )
                self._auth_type = "form"
                return True  # Optimistic

        except Exception as e:
            console.print(f"  [red]Login error: {e}[/red]")
            return False

    # ── Bearer token / API key injection ──────────────────────────────

    def set_bearer_token(self, token: str) -> None:
        """Inject a Bearer token into all future requests."""
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._auth_type = "bearer"
        console.print(f"  [green]✅ Bearer token set: {token[:20]}...[/green]")

    def set_api_key(self, header_name: str, api_key: str) -> None:
        """Inject a custom API key header."""
        self._session.headers[header_name] = api_key
        self._auth_type = "apikey"
        console.print(
            f"  [green]✅ API key injected: {header_name}: {api_key[:10]}...[/green]"
        )

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set session cookies directly."""
        for k, v in cookies.items():
            self._session.cookies.set(k, v)
        self._auth_type = "cookie"
        console.print(f"  [green]✅ {len(cookies)} cookie(s) injected[/green]")

    # ── Verify auth still active ───────────────────────────────────────

    def _verify_auth(self) -> bool:
        if not self._auth_check or not self._auth_marker:
            return True
        try:
            self.rate_limiter.wait()
            resp = self._session.get(self._auth_check, timeout=10)
            return self._auth_marker in resp.text
        except Exception:
            return False

    # ── Get the underlying requests.Session ───────────────────────────

    def get_session(self) -> requests.Session:
        """Return the configured, authenticated requests.Session."""
        return self._session

    def get_rate_limiter(self) -> RateLimiter:
        """Return the rate limiter for use in scanners."""
        return self.rate_limiter

    @property
    def auth_type(self) -> str:
        return self._auth_type

    def status(self) -> Dict[str, Any]:
        return {
            "auth_type": self._auth_type,
            "proxy": bool(self._session.proxies),
            "cookies": len(self._session.cookies),
            "headers": dict(self._session.headers),
        }
