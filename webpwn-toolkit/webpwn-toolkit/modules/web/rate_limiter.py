#!/usr/bin/env python3
"""
Adaptive Rate Limiter
----------------------
Wraps a requests.Session to:
  • Detect 429 Too Many Requests responses
  • Apply exponential backoff (with jitter) per host
  • Respect Retry-After headers
  • Throttle concurrent requests globally
  • Record rate-limit events for the report
"""

import time
import threading
import random
from typing import Optional, Callable, Any
from rich.console import Console

console = Console()

# Global per-host backoff state  {host: backoff_seconds}
_host_backoff: dict = {}
_lock = threading.Lock()


class RateLimiter:
    """
    Drop-in wrapper around requests.Session that adds adaptive rate limiting.

    Usage:
        rl = RateLimiter(session, min_delay=0.1, max_backoff=120)
        resp = rl.get(url, **kwargs)
    """

    def __init__(
        self,
        session,
        min_delay: float = 0.05,  # seconds between requests (baseline)
        max_retries: int = 4,
        max_backoff: float = 60.0,  # max wait after 429
        jitter: float = 0.3,  # ±30% random jitter on backoff
    ):
        self._session = session
        self.min_delay = min_delay
        self.max_retries = max_retries
        self.max_backoff = max_backoff
        self.jitter = jitter
        self._last_req: dict = {}  # host → timestamp of last request

    # ── Internal helpers ──────────────────────────────────────────────

    def _host(self, url: str) -> str:
        from urllib.parse import urlparse

        return urlparse(url).netloc or url

    def _throttle(self, host: str) -> None:
        """Enforce min_delay + any active backoff for host."""
        with _lock:
            backoff = _host_backoff.get(host, 0)
            last = self._last_req.get(host, 0)
            now = time.time()
            delay = max(self.min_delay, backoff) - (now - last)
            if delay > 0:
                time.sleep(delay)
            self._last_req[host] = time.time()

    def _backoff(
        self, host: str, attempt: int, retry_after: Optional[float] = None
    ) -> None:
        """Set exponential backoff for host after a 429."""
        with _lock:
            current = _host_backoff.get(host, 1.0)
            if retry_after:
                wait = min(retry_after, self.max_backoff)
            else:
                wait = min(current * (2**attempt), self.max_backoff)
            # Apply jitter
            wait *= 1 + random.uniform(-self.jitter, self.jitter)
            _host_backoff[host] = wait
        console.print(
            f"  [yellow]⏳ Rate limited — backing off {wait:.1f}s "
            f"(attempt {attempt + 1}/{self.max_retries})[/yellow]"
        )
        time.sleep(wait)

    def _clear_backoff(self, host: str) -> None:
        with _lock:
            _host_backoff.pop(host, None)

    def _retry_after(self, resp) -> Optional[float]:
        """Parse Retry-After header (seconds or HTTP-date)."""
        ra = resp.headers.get("Retry-After", "")
        if ra.isdigit():
            return float(ra)
        try:
            from email.utils import parsedate_to_datetime

            dt = parsedate_to_datetime(ra)
            return max(
                0.0, (dt - __import__("datetime").datetime.utcnow()).total_seconds()
            )
        except Exception:
            return None

    # ── Public request method ─────────────────────────────────────────

    def _request(self, method: str, url: str, **kwargs) -> Any:
        host = self._host(url)
        for attempt in range(self.max_retries + 1):
            self._throttle(host)
            try:
                resp = getattr(self._session, method)(url, **kwargs)
                if resp.status_code == 429:
                    ra = self._retry_after(resp)
                    if attempt < self.max_retries:
                        self._backoff(host, attempt, ra)
                        continue
                    else:
                        console.print(
                            f"  [red]Rate limit persists after {self.max_retries} retries "
                            f"for {url}[/red]"
                        )
                else:
                    self._clear_backoff(host)
                return resp
            except Exception as e:
                if attempt == self.max_retries:
                    raise
                time.sleep(0.5 * (attempt + 1))
        return resp  # type: ignore

    def get(self, url: str, **kwargs):
        return self._request("get", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._request("post", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self._request("put", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self._request("delete", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self._request("options", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self._request("head", url, **kwargs)

    # Allow attribute passthrough to underlying session
    def __getattr__(self, name: str):
        return getattr(self._session, name)
