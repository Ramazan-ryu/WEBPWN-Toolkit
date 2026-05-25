#!/usr/bin/env python3
"""
CVE Lookup Module
------------------
Cross-references detected technologies with known CVEs via:
  • NIST NVD API (free, no key required for basic use)
  • Local CVE cache to avoid repeated requests
  • Severity mapping (CVSS v3 score → Critical/High/Medium/Low)
"""

import json
import time
import requests
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = Path(__file__).parents[2] / "sessions" / "cve_cache.json"
CACHE_TTL_SEC = 86400  # 24 hours


def _load_cache() -> Dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_cache(cache: Dict) -> None:
    CACHE_FILE.parent.mkdir(exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0:
        return "low"
    return "info"


class CVELookup:
    """
    Looks up CVEs for detected technologies using NIST NVD API.

    Usage:
        tech = {"cms": ["WordPress 6.1"], "server": ["Apache/2.4.50"]}
        cve_lookup = CVELookup(tech_findings=tech)
        results = cve_lookup.run()
    """

    def __init__(self, tech_findings: Dict[str, List[str]], timeout: int = 15):
        self.tech = tech_findings
        self.timeout = timeout
        self.cache = _load_cache()
        self.results: List[Dict] = []

    # ── Query NVD ─────────────────────────────────────────────────────

    def _query_nvd(self, keyword: str) -> List[Dict]:
        """Query NVD API for CVEs matching a keyword. Returns list of CVE dicts."""
        cache_key = keyword.lower().strip()
        now = time.time()

        # Cache hit
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if now - cached.get("ts", 0) < CACHE_TTL_SEC:
                return cached.get("cves", [])

        try:
            resp = requests.get(
                NVD_API_BASE,
                params={
                    "keywordSearch": keyword,
                    "resultsPerPage": 5,
                    "startIndex": 0,
                },
                timeout=self.timeout,
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            items = data.get("vulnerabilities", [])
            cves = []

            for item in items:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                desc_list = cve_data.get("descriptions", [])
                desc = next(
                    (d["value"] for d in desc_list if d.get("lang") == "en"),
                    "No description",
                )

                # CVSS score
                score = 0.0
                severity = "info"
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    severity = _cvss_to_severity(score)
                elif "cvssMetricV30" in metrics:
                    score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    severity = _cvss_to_severity(score)
                elif "cvssMetricV2" in metrics:
                    score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    severity = _cvss_to_severity(score)

                cves.append(
                    {
                        "cve_id": cve_id,
                        "score": score,
                        "severity": severity,
                        "desc": desc[:200],
                    }
                )

            # Cache result
            self.cache[cache_key] = {"ts": now, "cves": cves}
            _save_cache(self.cache)

            time.sleep(0.6)  # NVD rate limit: ~5 req/30s without API key
            return cves

        except Exception as e:
            console.print(f"  [dim]CVE lookup error for '{keyword}': {e}[/dim]")
            return []

    # ── Extract search terms from tech findings ────────────────────────

    def _build_keywords(self) -> List[str]:
        """Convert tech_findings dict into NVD search keywords."""
        # Values that are NOT real technology names — skip them
        SKIP_VALUES = {
            "none detected",
            "unknown",
            "-",
            "",
            "n/a",
            "none",
            "not detected",
            "not found",
            "none identified",
        }
        keywords = []
        for category, values in self.tech.items():
            if isinstance(values, list):
                for v in values:
                    clean = str(v).strip().lower()
                    if clean and clean not in SKIP_VALUES and len(clean) > 2:
                        keywords.append(str(v).strip())
            elif isinstance(values, str):
                clean = values.strip().lower()
                if clean and clean not in SKIP_VALUES and len(clean) > 2:
                    keywords.append(values.strip())
        return list(dict.fromkeys(keywords))  # deduplicate

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        keywords = self._build_keywords()
        if not keywords:
            console.print("  [dim]-> No technology data to look up CVEs for[/dim]")
            return []

        console.print(
            f"  [dim]-> Looking up CVEs for {len(keywords)} technology keyword(s)...[/dim]"
        )
        console.print("  [dim]-> Using NIST NVD API (free tier — may be slow)[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]CVE lookup...[/cyan]"),
            console=console,
        ) as progress:
            task = progress.add_task("cve", total=len(keywords))

            for keyword in keywords:
                progress.advance(task)
                cves = self._query_nvd(keyword)

                for cve in cves:
                    cve_id = cve["cve_id"]
                    desc = cve["desc"]

                    # ── Quality filters ─────────────────────────────────────────
                    # Skip REJECTED / reserved CVEs (no real vulnerability)
                    if any(
                        marker in desc
                        for marker in [
                            "DO NOT USE THIS CANDIDATE",
                            "Rejected reason",
                            "REJECT",
                            "** RESERVED **",
                            "** REJECT **",
                        ]
                    ):
                        console.print(f"  [dim]Skipped REJECTED CVE: {cve_id}[/dim]")
                        continue

                    # Skip CVEs with no CVSS score (no actionable data)
                    if cve["score"] == 0.0:
                        console.print(
                            f"  [dim]Skipped unscored CVE: {cve_id} (CVSS N/A)[/dim]"
                        )
                        continue

                    finding = {
                        "type": f"CVE: {cve_id}",
                        "technology": keyword,
                        "cve_id": cve_id,
                        "severity": cve["severity"],
                        "cvss": cve["score"],
                        "detail": (f"{cve_id} affects '{keyword}' — " f"{desc}"),
                        "evidence": f"Technology: {keyword} | CVE: {cve_id} | CVSS: {cve['score']}",
                        "owasp": "A06:2021 – Vulnerable and Outdated Components",
                        "remediation": (
                            f"Update '{keyword}' to the latest patched version. "
                            f"Check https://nvd.nist.gov/vuln/detail/{cve_id} for details."
                        ),
                    }
                    if finding not in self.results:
                        self.results.append(finding)
                        sev_color = {
                            "critical": "bold red",
                            "high": "red",
                            "medium": "yellow",
                            "low": "blue",
                        }.get(cve["severity"], "white")
                        console.print(
                            f"  [{sev_color}]  {cve_id} (CVSS {cve['score']}) "
                            f"— {keyword}[/]"
                        )

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' CVE(s) found!' if self.results else '✅ No known CVEs found'}"
            f"[/]"
        )
        return self.results
