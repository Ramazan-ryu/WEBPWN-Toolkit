#!/usr/bin/env python3
"""
BaseScanner — Universal Base Class for all WebPwn modules
----------------------------------------------------------
Provides:
  • User-Agent rotation (real browser UAs)
  • Configurable rate limiting (token bucket)
  • Proxy support from config.yaml
  • Unified session creation
  • Safe GET/POST helpers with auto-retry
"""

import time
import random
import threading
import logging
import requests
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# ── Real-world User-Agent pool ───────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


class TokenBucketRateLimiter:
    """
    Thread-safe token bucket rate limiter.
    Ensures network requests do not exceed the specified rate.
    """

    def __init__(self, requests_per_second: float = 10.0) -> None:
        self.rate: float = requests_per_second
        self.tokens: float = requests_per_second
        self.max: float = requests_per_second
        self.last: float = time.monotonic()
        self._lock = threading.Lock()

    def wait(self) -> None:
        """Blocks the thread until a token is available."""
        with self._lock:
            now = time.monotonic()
            delta = now - self.last
            self.last = now
            self.tokens = min(self.max, self.tokens + delta * self.rate)
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1


def _load_proxy_config() -> Optional[Dict[str, str]]:
    """Load proxy settings from config.yaml if enabled."""
    try:
        import yaml

        cfg_path = Path(__file__).parent.parent.parent / "config.yaml"
        if cfg_path.exists():
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            proxy_cfg = cfg.get("proxy", {})
            if proxy_cfg.get("enabled", False):
                return {
                    "http": proxy_cfg.get("http", ""),
                    "https": proxy_cfg.get("https", ""),
                }
    except Exception as e:
        logger.debug("Failed to load proxy config: %s", e)
    return None


class BaseScanner(ABC):
    """
    Abstract Base Class for all WebPwn scanners.
    Provides session management, rate limiting, and UA rotation.
    """

    def __init__(
        self,
        target: str,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
        rate_limit: float = 10.0,
        rotate_ua: bool = True,
    ) -> None:
        """
        Initializes the base scanner.

        Args:
            target: The target URL to scan.
            session: Optional pre-configured requests session.
            timeout: Request timeout in seconds.
            rate_limit: Maximum requests per second.
            rotate_ua: Whether to rotate User-Agent headers per request.
        """
        self.target: str = target.rstrip("/")
        self.timeout: int = timeout
        self.rotate_ua: bool = rotate_ua
        self.results: List[Dict[str, Any]] = []

        self._rate_limiter = TokenBucketRateLimiter(rate_limit)

        self.session: requests.Session = (
            session if session is not None else requests.Session()
        )
        if session is None:
            self.session.verify = False

        proxies = _load_proxy_config()
        if proxies:
            self.session.proxies.update(proxies)
            self.session.verify = False

        self._rotate_user_agent()

    def _rotate_user_agent(self) -> None:
        """Rotates the User-Agent header randomly if enabled."""
        if self.rotate_ua:
            self.session.headers["User-Agent"] = random.choice(USER_AGENTS)

    def _request_safe(
        self, method: str, url: str, **kwargs: Any
    ) -> Optional[requests.Response]:
        """
        Executes a safe, rate-limited HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            kwargs: Additional arguments for requests.request

        Returns:
            Optional[requests.Response]: The HTTP response, or None if the request failed.
        """
        self._rate_limiter.wait()
        self._rotate_user_agent()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)

        try:
            return self.session.request(method.upper(), url, **kwargs)
        except requests.exceptions.Timeout:
            logger.debug("Timeout connecting to %s", url)
        except requests.exceptions.RequestException as e:
            logger.debug("Request failed for %s: %s", url, e)
        return None

    def _get(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        """Wrapper for safe GET request."""
        return self._request_safe("GET", url, **kwargs)

    def _post(
        self, url: str, data: Any = None, json: Any = None, **kwargs: Any
    ) -> Optional[requests.Response]:
        """Wrapper for safe POST request."""
        return self._request_safe("POST", url, data=data, json=json, **kwargs)

    @abstractmethod
    def run(self) -> List[Dict[str, Any]]:
        """
        Executes the scanner.
        Must be implemented by all subclasses.

        Returns:
            List of findings/vulnerabilities.
        """
        pass
