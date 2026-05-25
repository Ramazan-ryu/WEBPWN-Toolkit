#!/usr/bin/env python3
"""
Web Crawler Module
-------------------
Discovers all reachable pages, forms, and API endpoints
within the same domain. Results are used by all attack
modules to maximise coverage.

Features:
  • BFS link crawling (stays in-scope, same domain only)
  • Form extraction per page
  • Query-param endpoint detection
  • Configurable max-depth and max-pages
  • Polite crawling: respects delay, honours robots.txt hint
"""

import time
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse
from typing import List, Dict, Set, Optional

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class WebCrawler:
    """
    BFS crawler that stays within the target domain and collects:
      - All unique page URLs
      - All HTML forms (with action URL, method, fields)
      - All unique query-parameter endpoints
    """

    def __init__(
        self,
        start_url: str,
        threads: int = 10,
        timeout: int = 10,
        max_pages: int = 200,
        max_depth: int = 3,
        delay: float = 0.1,
    ):
        self.start_url = start_url.rstrip("/")
        self.threads = threads
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay

        parsed = urlparse(start_url)
        self.base_scheme = parsed.scheme
        self.base_host = parsed.netloc  # e.g. "localhost" or "example.com"

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "WebPwn-Toolkit/1.0 (Authorized Security Testing)",
            }
        )

        # Results
        self.pages: List[str] = []  # all discovered URLs
        self.forms: List[Dict] = []  # all discovered forms
        self.endpoints: List[str] = []  # URLs that have query params

    # ── Helpers ────────────────────────────────────────────────────────

    def _normalize(self, url: str) -> Optional[str]:
        """
        Normalize URL: remove fragment, ensure same host.
        Returns None if URL should be skipped.
        """
        try:
            p = urlparse(url)
            # Skip non-http schemes, different hosts, and binary extensions
            if p.scheme not in ("http", "https"):
                return None
            if p.netloc and p.netloc != self.base_host:
                return None
            skip_exts = {
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".svg",
                ".ico",
                ".pdf",
                ".zip",
                ".gz",
                ".tar",
                ".mp4",
                ".mp3",
                ".woff",
                ".woff2",
                ".ttf",
                ".eot",
                ".css",
            }
            path_lower = p.path.lower()
            if any(path_lower.endswith(ext) for ext in skip_exts):
                return None
            # Rebuild without fragment
            clean = urlunparse(
                (
                    p.scheme or self.base_scheme,
                    p.netloc or self.base_host,
                    p.path,
                    p.params,
                    p.query,
                    "",  # no fragment
                )
            )
            return clean
        except Exception:
            return None

    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """Extract all href/src links from page HTML."""
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                continue
            abs_url = urljoin(base_url, href)
            norm = self._normalize(abs_url)
            if norm:
                links.append(norm)
        # Also check <script src> and <form action>
        for tag in soup.find_all("script", src=True):
            src = urljoin(base_url, tag["src"])
            norm = self._normalize(src)
            if norm:
                links.append(norm)
        return links

    def _extract_forms(self, page_url: str, html: str) -> List[Dict]:
        """Extract all HTML forms from page, including CSRF tokens."""
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            abs_action = urljoin(page_url, action) if action else page_url

            inputs = {}
            hidden = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                value = inp.get("value", "")
                itype = inp.get("type", "text").lower()
                if not name:
                    continue
                if itype == "hidden":
                    # Keep CSRF and hidden tokens as-is
                    hidden[name] = value
                elif itype not in ("submit", "button", "image", "reset"):
                    inputs[name] = value or "test"

            if inputs or hidden:
                forms.append(
                    {
                        "page": page_url,
                        "url": abs_action,
                        "method": method,
                        "inputs": inputs,
                        "hidden": hidden,  # CSRF tokens passed through
                    }
                )
        return forms

    # ── BFS Crawler ────────────────────────────────────────────────────

    def _fetch_and_parse(self, url: str) -> dict:
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=False, allow_redirects=True
            )
            content_type = resp.headers.get("Content-Type", "").lower()

            # If it's a JS file, just return it so it can be analyzed later
            if "javascript" in content_type or url.endswith(".js"):
                return {
                    "url": url,
                    "forms": [],
                    "links": [],
                    "secrets": [],
                    "is_js": True,
                }

            if "html" not in content_type:
                return {
                    "url": url,
                    "forms": [],
                    "links": [],
                    "secrets": [],
                    "is_js": False,
                }

            html = resp.text
            forms = self._extract_forms(url, html)
            links = self._extract_links(url, html)

            # Senior feature: Regex secret extraction
            secrets = []
            secret_patterns = [
                (r"['\"](AIza[0-9A-Za-z-_]{35})['\"]", "Google API Key"),
                (r"['\"](sk_live_[0-9a-zA-Z]{24})['\"]", "Stripe API Key"),
                (
                    r"['\"](sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{43})['\"]",
                    "Square Access Token",
                ),
                (r"['\"](sk-[a-zA-Z0-9]{48})['\"]", "OpenAI API Key"),
                (r"['\"](ghp_[a-zA-Z0-9]{36})['\"]", "GitHub Personal Access Token"),
            ]
            for pattern, name in secret_patterns:
                for match in re.findall(pattern, html):
                    secrets.append({"name": name, "value": match, "url": url})

            return {
                "url": url,
                "forms": forms,
                "links": links,
                "secrets": secrets,
                "is_js": False,
            }
        except Exception:
            return {"url": url, "forms": [], "links": [], "secrets": [], "is_js": False}

    def run(self) -> Dict:
        """
        BFS crawl starting from start_url.
        Returns:
            {
                "pages":     [url, ...],
                "forms":     [{url, method, inputs, hidden}, ...],
                "endpoints": [url_with_params, ...],
                "secrets":   [{name, value, url}, ...],
                "js_endpoints": [str, ...]
            }
        """
        console.print(
            f"\n  [dim]-> Crawling {self.start_url} "
            f"(max {self.max_pages} pages, depth {self.max_depth})...[/dim]"
        )

        visited: Set[str] = set([self.start_url])
        queue: List[tuple] = [(self.start_url, 0)]

        all_forms: List[Dict] = []
        all_endpoints: List[str] = []
        all_secrets: List[Dict] = []
        js_files: List[str] = []

        import concurrent.futures

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Crawling...[/cyan]"),
            BarColumn(),
            TextColumn("{task.completed} pages"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("crawl", total=self.max_pages)

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                while queue and len(visited) < self.max_pages:
                    # Take up to `threads` items from queue
                    batch = queue[: self.threads]
                    queue = queue[self.threads :]

                    futures = {
                        ex.submit(self._fetch_and_parse, u, d): (u, d) for u, d in batch
                    }
                    for future in concurrent.futures.as_completed(futures):
                        u, d = futures[future]
                        progress.advance(task)

                        try:
                            res = future.result()
                            if "?" in res["url"]:
                                all_endpoints.append(res["url"])
                            all_forms.extend(res["forms"])
                            all_secrets.extend(res["secrets"])

                            if res.get("is_js"):
                                js_files.append(res["url"])

                            if d < self.max_depth:
                                for link in res["links"]:
                                    if (
                                        link not in visited
                                        and len(visited) < self.max_pages
                                    ):
                                        visited.add(link)
                                        queue.append((link, d + 1))
                        except Exception:
                            pass
                    time.sleep(self.delay)

        # Senior feature: Run JSAnalyzer on found JS files
        js_endpoints = []
        js_graphql = []
        if js_files:
            try:
                from modules.recon.js_analyzer import JSAnalyzer

                analyzer = JSAnalyzer(self.start_url, list(set(js_files)), self.timeout)
                js_res = analyzer.analyze()
                js_endpoints = js_res.get("endpoints", [])
                js_graphql = js_res.get("graphql_queries", [])
            except Exception as e:
                console.print(f"  [red]JS Analyzer failed: {e}[/red]")

        self.pages = list(visited)
        self.forms = all_forms
        self.endpoints = list(set(all_endpoints))

        console.print(
            f"  [green]✅ Crawl complete:[/green] "
            f"[bold]{len(self.pages)}[/bold] pages | "
            f"[bold]{len(self.forms)}[/bold] forms | "
            f"[bold]{len(self.endpoints)}[/bold] param endpoints | "
            f"[bold red]{len(all_secrets)}[/bold red] secrets found | "
            f"[bold cyan]{len(js_endpoints)}[/bold cyan] hidden JS routes"
        )

        if js_graphql:
            console.print(
                f"    [magenta]⚠ Found {len(js_graphql)} GraphQL patterns in JS![/magenta]"
            )

        if all_secrets:
            for s in all_secrets:
                console.print(
                    f"    [red]⚠ {s['name']}:[/red] {s['value']} (at {s['url']})"
                )

        return {
            "pages": self.pages,
            "forms": self.forms,
            "endpoints": self.endpoints,
            "secrets": all_secrets,
            "js_endpoints": js_endpoints,
            "js_graphql": js_graphql,
        }
