#!/usr/bin/env python3
"""
Subdomain Enumeration Module
-----------------------------
• DNS brute-force (multi-threaded)
• Certificate Transparency (crt.sh)
"""

import dns.resolver
import requests
import concurrent.futures
import time
from pathlib import Path
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


class SubdomainEnumerator:
    """Enumerate subdomains via DNS brute-force and cert transparency."""

    DEFAULT_WORDLIST = Path(__file__).parents[2] / "wordlists" / "subdomains.txt"
    FALLBACK_SUBS = [
        "www",
        "mail",
        "ftp",
        "admin",
        "api",
        "dev",
        "test",
        "staging",
        "app",
        "portal",
        "vpn",
        "remote",
        "webmail",
        "secure",
        "shop",
        "blog",
        "support",
        "help",
        "docs",
        "status",
        "cdn",
        "static",
        "assets",
        "media",
        "images",
        "beta",
        "old",
        "new",
        "internal",
    ]

    def __init__(self, domain: str, wordlist: Optional[str] = None, threads: int = 50):
        self.domain = domain
        self.wordlist = wordlist or str(self.DEFAULT_WORDLIST)
        self.threads = threads
        self.results: List[Dict] = []

    # ── DNS resolution ─────────────────────────────────────────────────

    def _resolve(self, subdomain: str) -> Optional[Dict]:
        fqdn = f"{subdomain}.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]

            # grab CNAME if present
            cname = None
            try:
                cname_ans = resolver.resolve(fqdn, "CNAME")
                cname = str(cname_ans[0].target)
            except Exception:
                pass

            return {
                "subdomain": fqdn,
                "ips": ips,
                "cname": cname,
                "source": "dns_bruteforce",
                "status": "alive",
            }
        except Exception:
            return None

    # ── Advanced OSINT Collection ─────────────────────────────────────

    def _fetch_json(self, url: str) -> dict:
        try:
            resp = requests.get(
                url, timeout=10, headers={"User-Agent": "WebPwnToolkit/2.0 (OSINT)"}
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    def _fetch_text(self, url: str) -> str:
        try:
            resp = requests.get(
                url, timeout=10, headers={"User-Agent": "WebPwnToolkit/2.0 (OSINT)"}
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return ""

    def _osint_crtsh(self) -> List[str]:
        found = []
        data = self._fetch_json(f"https://crt.sh/?q=%.{self.domain}&output=json")
        if isinstance(data, list):
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(self.domain) and name != self.domain:
                        found.append(name.replace(f".{self.domain}", ""))
        return found

    def _osint_alienvault(self) -> List[str]:
        found = []
        data = self._fetch_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        )
        if isinstance(data, dict):
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname.endswith(self.domain) and hostname != self.domain:
                    found.append(hostname.replace(f".{self.domain}", "").strip(".*"))
        return found

    def _osint_hackertarget(self) -> List[str]:
        found = []
        text = self._fetch_text(
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        )
        for line in text.split("\n"):
            if "," in line:
                host = line.split(",")[0]
                if host.endswith(self.domain) and host != self.domain:
                    found.append(host.replace(f".{self.domain}", ""))
        return found

    def _osint_wayback(self) -> List[str]:
        found = []
        data = self._fetch_json(
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey&fl=original"
        )
        if isinstance(data, list) and len(data) > 1:
            for row in data[1:]:
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(row[0])
                    netloc = parsed.netloc.split(":")[0]
                    if netloc.endswith(self.domain) and netloc != self.domain:
                        found.append(netloc.replace(f".{self.domain}", ""))
                except Exception:
                    pass
        return found

    def _run_osint(self) -> List[str]:
        """Run multiple OSINT sources concurrently."""
        sources = [
            ("crt.sh", self._osint_crtsh),
            ("AlienVault", self._osint_alienvault),
            ("HackerTarget", self._osint_hackertarget),
            ("Wayback", self._osint_wayback),
        ]
        found = set()
        console.print(
            "  [dim]→ Querying advanced OSINT sources (crt.sh, AlienVault, HackerTarget, Wayback)...[/dim]"
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as ex:
            futures = {ex.submit(func): name for name, func in sources}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    res = future.result()
                    found.update(res)
                except Exception as e:
                    pass
        return list(found)

    # ── Subdomain Permutation ──────────────────────────────────────────

    def _apply_permutations(self, base_subs: List[str]) -> List[str]:
        """Generate altdns-style permutations."""
        console.print(
            "  [dim]→ Generating subdomain permutations (altdns logic)...[/dim]"
        )
        prefixes_suffixes = [
            "dev",
            "staging",
            "test",
            "api",
            "v1",
            "v2",
            "prod",
            "internal",
            "admin",
            "new",
            "old",
            "beta",
        ]
        permutations = set(base_subs)

        for sub in base_subs:
            parts = sub.split(".")
            if not parts:
                continue

            # Basic append/prepend for the first part
            first = parts[0]
            rest = ".".join(parts[1:])

            for word in prefixes_suffixes:
                # e.g. api-dev, dev-api
                new_first_post = f"{first}-{word}"
                new_first_pre = f"{word}-{first}"

                if rest:
                    permutations.add(f"{new_first_post}.{rest}")
                    permutations.add(f"{new_first_pre}.{rest}")
                else:
                    permutations.add(f"{new_first_post}")
                    permutations.add(f"{new_first_pre}")

                # Direct dot prefixes e.g. dev.api
                if rest:
                    permutations.add(f"{word}.{first}.{rest}")
                else:
                    permutations.add(f"{word}.{first}")

        return list(permutations)

    # ── Load wordlist ──────────────────────────────────────────────────

    def _load_words(self) -> List[str]:
        try:
            with open(self.wordlist, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(
                f"  [yellow]⚠  Wordlist not found, using built-in list[/yellow]"
            )
            return self.FALLBACK_SUBS

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        words = self._load_words()

        # Merge OSINT subdomains into wordlist
        osint_subs = self._run_osint()
        if osint_subs:
            console.print(
                f"  [dim]→ Found {len(osint_subs)} subdomains via OSINT[/dim]"
            )

        combined = list(set(words + osint_subs))

        # Apply permutations
        words = self._apply_permutations(combined)
        console.print(
            f"  [dim]→ {len(words)} unique candidates (incl. permutations) to probe via DNS[/dim]"
        )

        found: List[Dict] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Resolving subdomains...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("dns", total=len(words))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self._resolve, w): w for w in words}
                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result:
                        found.append(result)

        self.results = found
        console.print(f"  [green]✅ Found {len(found)} live subdomains[/green]")
        return found
