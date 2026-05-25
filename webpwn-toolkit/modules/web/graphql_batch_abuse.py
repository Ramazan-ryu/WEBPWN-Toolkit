#!/usr/bin/env python3
"""
GraphQL Batching & Alias Abuse Tester — Senior Level
---------------------------------------------------------
Detects if GraphQL endpoints allow query batching (array of queries)
or alias batching (multiple aliases in one query) which can be used
to bypass rate limits, brute-force OTPs, or perform DoS.
"""

import json
import requests
from typing import List, Dict, Optional
from rich.console import Console

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object

console = Console()


class GraphQLBatchAbuseTester(BaseScanner if BaseScanner is not object else object):
    def __init__(self, target: str, session=None, timeout: int = 10):
        if BaseScanner is not object:
            super().__init__(target, session, timeout)
        else:
            self.target = target.rstrip("/")
            self.timeout = timeout
            self.session = session or requests.Session()
            self.session.verify = False
            self.results = []
        self.endpoints = [
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/graphql/console",
            "/graphiql",
        ]

    def _post_gql(self, url: str, json_data: dict) -> Optional[requests.Response]:
        if hasattr(self, "_post"):
            return self._post(url, json=json_data)
        try:
            return self.session.post(
                url, json=json_data, timeout=self.timeout, verify=False
            )
        except Exception:
            return None

    def _test_array_batching(self, url: str) -> Optional[Dict]:
        """Test if the server accepts an array of queries."""
        payload = [{"query": "query { __typename }"}, {"query": "query { __typename }"}]
        r = self._post_gql(url, payload)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list) and len(data) == 2 and "data" in data[0]:
                    return {
                        "url": url,
                        "type": "GraphQL — Array-Based Query Batching Enabled",
                        "severity": "medium",
                        "cvss": 5.3,
                        "detail": "GraphQL endpoint accepts arrays of queries. Attackers can bypass rate limits by sending 1000s of login/OTP attempts in a single HTTP request.",
                        "evidence": f"Response is an array of length {len(data)}.",
                        "owasp": "A04:2021 – Insecure Design",
                        "remediation": "Disable array-based query batching in your GraphQL engine if not needed.",
                    }
            except Exception:
                pass
        return None

    def _test_alias_batching(self, url: str) -> Optional[Dict]:
        """Test if the server allows multiple aliases to bypass rate limits."""
        payload = {"query": "query { q1: __typename, q2: __typename, q3: __typename }"}
        r = self._post_gql(url, payload)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "data" in data and "q1" in data["data"] and "q3" in data["data"]:
                    return {
                        "url": url,
                        "type": "GraphQL — Alias-Based Query Batching",
                        "severity": "medium",
                        "cvss": 4.3,
                        "detail": "GraphQL endpoint allows multiple aliases in a single query. This can be abused for brute-forcing (e.g. sending 100 'login' mutations with different aliases) or DoS.",
                        "evidence": "Server processed 3 aliases for __typename.",
                        "owasp": "A04:2021 – Insecure Design",
                        "remediation": "Implement query cost analysis and limit the number of aliases/operations per request.",
                    }
            except Exception:
                pass
        return None

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ GraphQL Batch Abuse Tester on {self.target}[/bold yellow]"
        )
        for path in self.endpoints:
            url = self.target + path
            # Quickly check if it's a GraphQL endpoint
            r = self._post_gql(url, {"query": "{__typename}"})
            if r and r.status_code in (200, 400) and "data" in r.text.lower():
                console.print(f"  [green]GraphQL endpoint found: {path}[/green]")
                res1 = self._test_array_batching(url)
                if res1:
                    self.results.append(res1)
                    console.print(f"  [bold red][!] {res1['type']}[/bold red]")

                res2 = self._test_alias_batching(url)
                if res2:
                    self.results.append(res2)
                    console.print(f"  [bold red][!] {res2['type']}[/bold red]")
                break  # Only test the first valid endpoint

        color = "red" if self.results else "green"
        console.print(
            f"  [{color}]{len(self.results)} GraphQL batching issue(s) found[/]"
        )
        return self.results
