#!/usr/bin/env python3
"""
API Schema Parser & Fuzzer (Swagger/OpenAPI)
---------------------------------------------
Automatically downloads swagger.json / openapi.yaml, parses all
endpoints, and generates thousands of test scenarios based on parameter types.
"""

import requests
import json
from typing import List, Dict
from rich.console import Console

console = Console()


class APISchemaFuzzer:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.results: List[Dict] = []
        self.schema = {}
        self.common_paths = [
            "/swagger.json",
            "/api-docs",
            "/v1/swagger.json",
            "/openapi.json",
            "/api/swagger.json",
            "/docs/api-docs.json",
        ]

    def _find_schema(self) -> bool:
        for path in self.common_paths:
            try:
                res = requests.get(
                    f"{self.target}{path}", timeout=self.timeout, verify=False
                )
                if res.status_code == 200 and (
                    "swagger" in res.text or "openapi" in res.text
                ):
                    self.schema = res.json()
                    console.print(
                        f"  [bold green]✅ API Schema found at {path}![/bold green]"
                    )
                    return True
            except Exception:
                pass
        return False

    def _fuzz_endpoints(self):
        paths = self.schema.get("paths", {})
        total_endpoints = sum(len(methods) for methods in paths.values())
        console.print(
            f"  [dim cyan][API] Parsing {total_endpoints} endpoints from schema...[/dim cyan]"
        )

        for path, methods in paths.items():
            for method, details in methods.items():
                params = details.get("parameters", [])
                for param in params:
                    p_name = param.get("name", "unknown")
                    p_type = param.get("schema", {}).get("type", "string")

                    # Generate Type Confusion / Massive payloads based on schema definition
                    if p_type == "integer":
                        # Send extremely large int or string to cause Type Confusion
                        payload = {p_name: "9999999999999999999999"}
                        try:
                            if method.lower() == "post":
                                r = requests.post(
                                    f"{self.target}{path}",
                                    json=payload,
                                    timeout=self.timeout,
                                    verify=False,
                                )
                            elif method.lower() == "get":
                                r = requests.get(
                                    f"{self.target}{path}",
                                    params=payload,
                                    timeout=self.timeout,
                                    verify=False,
                                )
                            else:
                                r = None

                            if r and r.status_code >= 500:
                                self.results.append(
                                    {
                                        "url": f"{self.target}{path}",
                                        "type": "API Type Confusion (Integer)",
                                        "severity": "medium",
                                        "detail": f"Parameter '{p_name}' expects integer. Sending extremely large string caused HTTP {r.status_code}.",
                                        "evidence": f"HTTP {r.status_code} error when fuzzing.",
                                        "owasp": "API4:2023 – Lack of Resources & Rate Limiting",
                                        "cvss": 5.3,
                                        "remediation": "Implement strict input validation and type checking.",
                                    }
                                )
                        except Exception:
                            pass
                    if param.get("required") == False:
                        # Mass Assignment Candidate - actually try to send it
                        try:
                            if method.lower() in ["post", "put"]:
                                # Try to send a generic object injection
                                payload = {
                                    p_name: "admin",
                                    "role": "admin",
                                    "isAdmin": True,
                                    "permissions": "all",
                                }
                                r = requests.request(
                                    method.upper(),
                                    f"{self.target}{path}",
                                    json=payload,
                                    timeout=self.timeout,
                                    verify=False,
                                )
                                if r and r.status_code in (200, 201):
                                    self.results.append(
                                        {
                                            "url": f"{self.target}{path}",
                                            "type": "Mass Assignment Candidate (Tested)",
                                            "severity": "high",
                                            "detail": f"Optional parameter '{p_name}' and extra fields were accepted by {method.upper()}.",
                                            "evidence": f"Request accepted with HTTP {r.status_code}",
                                            "owasp": "API3:2023 – Broken Object Property Level Authorization",
                                            "cvss": 7.1,
                                            "remediation": "Do not automatically bind incoming JSON data directly to internal database models.",
                                        }
                                    )
                        except Exception:
                            pass

    def run(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ API Schema Parser (Swagger/OpenAPI)...[/bold yellow]"
        )
        if self._find_schema():
            self._fuzz_endpoints()
        else:
            console.print("  [dim]No Swagger/OpenAPI schema found automatically.[/dim]")

        return self.results
