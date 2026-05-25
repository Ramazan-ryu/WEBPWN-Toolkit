#!/usr/bin/env python3
"""
Port Scanner Module
-------------------
• TCP connect scan (multi-threaded)
• Service banner grabbing
• Common port detection
"""

import socket
import concurrent.futures
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
)

console = Console()

# Well-known port -> service name mapping
SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP/TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker",
    2376: "Docker TLS",
    3000: "Dev Server",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS Alt",
    5000: "Flask/Dev",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7777: "Dev/Custom",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    27017: "MongoDB",
    27018: "MongoDB",
}

COMMON_PORTS = list(SERVICE_MAP.keys())


class PortScanner:
    """TCP connect scan with optional banner grabbing."""

    def __init__(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        threads: int = 100,
    ):
        self.host = host
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.threads = threads
        self.results: List[Dict] = []

    # ── Single port probe ──────────────────────────────────────────────

    def _probe(self, port: int) -> Optional[Dict]:
        try:
            with socket.create_connection(
                (self.host, port), timeout=self.timeout
            ) as sock:
                sock.settimeout(self.timeout)
                banner = ""
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(256).decode(errors="ignore").strip()
                    banner = banner.split("\n")[0][:120]
                except Exception:
                    pass

                service = SERVICE_MAP.get(port, self._guess_service(port))
                risk = self._risk_level(port)

                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    "risk": risk,
                }
        except Exception:
            return None

    @staticmethod
    def _guess_service(port: int) -> str:
        try:
            return socket.getservbyport(port)
        except Exception:
            return "unknown"

    @staticmethod
    def _risk_level(port: int) -> str:
        high_risk = {21, 23, 3389, 5900, 2375, 6379, 9200, 27017}
        medium_risk = {22, 80, 8080, 3306, 5432, 1433, 1521}
        if port in high_risk:
            return "high"
        if port in medium_risk:
            return "medium"
        return "low"

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        open_ports: List[Dict] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Scanning ports...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("scan", total=len(self.ports))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self._probe, p): p for p in self.ports}
                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result:
                        open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        self.results = open_ports

        console.print(f"  [green]✅ {len(open_ports)} open port(s) found[/green]")
        return open_ports
