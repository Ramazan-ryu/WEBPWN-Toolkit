#!/usr/bin/env python3
"""
Cloud Misconfiguration Scanner
-------------------------------
Checks for common cloud misconfigurations associated with a domain:
  • S3 Bucket accessibility (AWS)
  • Azure Blob Storage accessibility
  • Google Cloud Storage accessibility
"""

import requests
import concurrent.futures
from urllib.parse import urlparse
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class CloudMisconfigScanner:
    def __init__(self, target: str, session=None, timeout: int = 10, threads: int = 10):
        self.target = target.rstrip("/")
        self.domain = urlparse(self.target).netloc.split(":")[0]
        # Common bucket naming conventions
        self.bucket_names = [
            self.domain,
            self.domain.replace(".", "-"),
            self.domain.replace(".", ""),
            self.domain.split(".")[0],
            f"{self.domain}-assets",
            f"{self.domain}-media",
            f"{self.domain}-static",
            f"{self.domain}-backup",
            f"{self.domain}-prod",
            f"{self.domain}-dev",
        ]
        self.timeout = timeout
        self.threads = threads
        self.session = session or requests.Session()
        self.session.verify = False
        self.results: List[Dict] = []

    def _check_bucket(self, url: str, provider: str) -> Optional[Dict]:
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                # Check if it looks like a directory listing or actual file
                if (
                    "ListBucketResult" in resp.text
                    or "<EnumerationResults" in resp.text
                    or "BlobList" in resp.text
                ):
                    return {
                        "url": url,
                        "type": f"Cloud Misconfiguration — Public {provider} Bucket/Container Listing",
                        "severity": "high",
                        "cvss": 7.5,
                        "detail": f"Publicly readable {provider} storage found. Directory listing is enabled.",
                        "evidence": f"Returned HTTP 200 with directory listing.",
                        "owasp": "A05:2021 – Security Misconfiguration",
                        "remediation": "Restrict access to the storage bucket/container. Disable public list access.",
                    }
            elif resp.status_code == 403:
                # Check if we can bypass with X-Forwarded-Host or similar (basic check)
                pass
        except Exception:
            pass
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Cloud Misconfig Scanner for {self.domain}[/bold yellow]"
        )

        urls_to_test = []
        for name in self.bucket_names:
            # AWS S3
            urls_to_test.append((f"http://{name}.s3.amazonaws.com/", "AWS S3"))
            urls_to_test.append((f"http://s3.amazonaws.com/{name}/", "AWS S3"))
            # Azure Blob
            urls_to_test.append(
                (
                    f"https://{name}.blob.core.windows.net/?restype=container&comp=list",
                    "Azure Blob",
                )
            )
            # GCP Storage
            urls_to_test.append(
                (f"https://storage.googleapis.com/{name}/", "GCP Storage")
            )

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Checking cloud storage...[/cyan]"),
            BarColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("cloud", total=len(urls_to_test))

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {
                    ex.submit(self._check_bucket, url, provider): url
                    for url, provider in urls_to_test
                }
                for future in concurrent.futures.as_completed(futures):
                    prog.advance(task)
                    res = future.result()
                    if res and res not in self.results:
                        self.results.append(res)
                        console.print(
                            f"  [bold red][!] {res['type']}[/bold red] - {res['url']}"
                        )

        color = "red" if self.results else "green"
        console.print(
            f"  [{color}]{len(self.results)} Cloud misconfig issue(s) found[/]"
        )
        return self.results
