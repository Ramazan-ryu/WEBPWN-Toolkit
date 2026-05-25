#!/usr/bin/env python3
"""
GitHub Dorker & Source Code Leakage Scanner
-------------------------------------------
Searches GitHub repositories for leaked credentials and sensitive files
related to the target domain.
"""

import requests
import time
from typing import List, Dict
from rich.console import Console

console = Console()


class GitHubDorker:
    def __init__(self, target_domain: str, github_token: str = None):
        self.target = target_domain
        self.token = github_token
        self.results: List[Dict] = []
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebPwnToolkit/2.0 (GitHub Dorker)"
        self.session.headers["Accept"] = "application/vnd.github.v3+json"

        if self.token:
            self.session.headers["Authorization"] = f"token {self.token}"

        self.dorks = [
            f'"{self.target}" password',
            f'"{self.target}" API_KEY',
            f'"{self.target}" secret',
            f'"{self.target}" token',
            f'"{self.target}" AWS_ACCESS_KEY_ID',
            f'"{self.target}" DB_PASSWORD',
            f'"{self.target}" config.php',
            f'"{self.target}" FTP',
        ]

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ GitHub Dorker for '{self.target}'...[/bold yellow]"
        )
        if not self.token:
            console.print(
                "  [dim]⚠ Running unauthenticated. GitHub API limits searches to 10/minute.[/dim]"
            )

        for dork in self.dorks:
            try:
                url = (
                    f"https://api.github.com/search/code?q={requests.utils.quote(dork)}"
                )
                resp = self.session.get(url, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    total_count = data.get("total_count", 0)
                    if total_count > 0:
                        console.print(
                            f"    [red]⚠ Found {total_count} results for dork:[/red] {dork}"
                        )
                        self.results.append(
                            {
                                "type": "GitHub Leakage",
                                "severity": "high",
                                "evidence": f"Found {total_count} results for dork: {dork}",
                                "detail": f"Search URL: https://github.com/search?q={requests.utils.quote(dork)}&type=code",
                            }
                        )
                elif resp.status_code == 403:
                    console.print(
                        "  [yellow]⚠ GitHub API rate limit exceeded. Consider adding a token.[/yellow]"
                    )
                    break

                # Sleep to avoid rate limiting (Unauth: 10/min = 6s per request)
                time.sleep(6 if not self.token else 2)

            except Exception as e:
                console.print(f"  [red]GitHub API error: {e}[/red]")
                break

        console.print(f"  [green]✅ GitHub Dorker complete.[/green]")
        return self.results
