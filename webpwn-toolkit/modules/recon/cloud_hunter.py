#!/usr/bin/env python3
"""
Cloud Asset Hunter
-------------------
Generates permutations of a target's name and searches for exposed
Cloud storage buckets (AWS S3, Azure, GCP).
"""

import concurrent.futures
import requests
import urllib3
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

urllib3.disable_warnings()
console = Console()


class CloudHunter:
    def __init__(self, target_domain: str, threads: int = 20, timeout: int = 5):
        self.target = target_domain.split(".")[
            0
        ]  # Extract company name e.g., "example" from "example.com"
        self.threads = threads
        self.timeout = timeout

        self.suffixes = [
            "",
            "-dev",
            "-prod",
            "-staging",
            "-test",
            "-assets",
            "-media",
            "-public",
            "-private",
            "-backup",
            "-static",
            "-images",
            "dev",
            "prod",
            "staging",
            "test",
            "assets",
            "media",
            "public",
            "backup",
        ]

        self.results: List[Dict] = []
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebPwnToolkit/2.0 (Cloud Hunter)"

    def _check_s3(self, bucket_name: str) -> dict:
        url = f"http://{bucket_name}.s3.amazonaws.com"
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                return {
                    "type": "AWS S3",
                    "url": url,
                    "status": "Open",
                    "severity": "high",
                }
            elif resp.status_code == 403:
                return {
                    "type": "AWS S3",
                    "url": url,
                    "status": "Exists (Access Denied)",
                    "severity": "info",
                }
        except Exception:
            pass
        return None

    def _check_gcp(self, bucket_name: str) -> dict:
        url = f"https://storage.googleapis.com/{bucket_name}"
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                return {
                    "type": "GCP Bucket",
                    "url": url,
                    "status": "Open",
                    "severity": "high",
                }
            elif resp.status_code == 403:
                return {
                    "type": "GCP Bucket",
                    "url": url,
                    "status": "Exists (Access Denied)",
                    "severity": "info",
                }
        except Exception:
            pass
        return None

    def _check_azure(self, account_name: str) -> dict:
        url = f"https://{account_name}.blob.core.windows.net/"
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 400 and "InvalidQueryParameterValue" in resp.text:
                return {
                    "type": "Azure Blob",
                    "url": url,
                    "status": "Exists",
                    "severity": "info",
                }
            elif resp.status_code == 200:
                return {
                    "type": "Azure Blob",
                    "url": url,
                    "status": "Open",
                    "severity": "high",
                }
        except Exception:
            pass
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Cloud Asset Hunter for '{self.target}'...[/bold yellow]"
        )

        mutations = [f"{self.target}{s}" for s in self.suffixes]
        console.print(
            f"  [dim]→ Checking {len(mutations)} permutations across AWS, GCP, and Azure...[/dim]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Hunting Cloud Assets...[/cyan]"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("hunt", total=len(mutations) * 3)

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = []
                for m in mutations:
                    futures.append(ex.submit(self._check_s3, m))
                    futures.append(ex.submit(self._check_gcp, m))

                    # Azure storage account names must be 3-24 alphanumeric chars
                    clean_m = m.replace("-", "")
                    if 3 <= len(clean_m) <= 24:
                        futures.append(ex.submit(self._check_azure, clean_m))
                    else:
                        progress.advance(task)

                for future in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    res = future.result()
                    if res:
                        self.results.append(res)
                        color = "red" if res["status"] == "Open" else "cyan"
                        console.print(
                            f"    [{color}]⚠ {res['type']}:[/{color}] {res['url']} ({res['status']})"
                        )

        console.print(f"  [green]✅ Found {len(self.results)} cloud assets.[/green]")
        return self.results
