#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          WebPwn Toolkit — Web & Mobile Pentest Framework         ║
║          Holberton IT School | Cyber Security Final Project      ║
║          Version: 3.1.0  |  Author: Holberton CS Team           ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import yaml
import json
from modules.core.deduplicator import deduplicator
from modules.core.plugin_manager import plugin_manager
import concurrent.futures
import logging
import time
import random
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich import print as rprint

if sys.platform == "win32":
    os.environ.setdefault("PYTHONUTF8", "1")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
console = Console()

BANNER = r"""
 ██╗    ██╗███████╗██████╗ ██████╗ ██╗    ██╗███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██║    ██║████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝██║ █╗ ██║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗██╔═══╝ ██║███╗██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝██║     ╚███╔███╔╝██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
"""

VERSION = "3.1.0"
SCHOOL = "Holberton IT School — Cyber Security"


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────


def print_banner() -> None:
    content = (
        Text(BANNER, style="bold cyan")
        + Text(
            f"\n  Web & Mobile Penetration Testing Toolkit  v{VERSION}\n",
            style="bold white",
        )
        + Text(f"  {SCHOOL}\n", style="dim white")
        + Text("\n  ⚠️  Authorized testing only — read DISCLAIMER.md", style="bold red")
    )
    console.print(Panel(Align.center(content), border_style="cyan", padding=(1, 4)))


def setup_logging(session_name: str) -> logging.Logger:
    logs_dir = ROOT / "logs"
    logs_dir.mkdir(exist_ok=True)
    log_file = logs_dir / f"session_{session_name}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[logging.FileHandler(log_file)],
    )
    return logging.getLogger("webpwn")


def load_config(profile_path: str = None) -> dict:
    cfg_path = ROOT / (profile_path if profile_path else "config.yaml")
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


def save_session(session: dict) -> None:
    sd = ROOT / "sessions"
    sd.mkdir(exist_ok=True)
    fp = sd / f"session_{session['name']}.json"
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2, default=str)

    # SQLite Database Integration (Professional Implementation)
    try:
        import sqlite3

        db_path = sd / "webpwn.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    name TEXT PRIMARY KEY,
                    target TEXT,
                    timestamp TEXT,
                    data TEXT
                )
            """)
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (name, target, timestamp, data)
                VALUES (?, ?, ?, ?)
            """,
                (
                    session.get("name", "unknown"),
                    session.get("target", ""),
                    session.get("start_time", ""),
                    json.dumps(session, default=str),
                ),
            )
    except sqlite3.Error as e:
        console.print(f"  [dim red]Database persistence error: {e}[/dim red]")


def severity_color(sev: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
    }.get(sev.lower(), "white")


def _display_results(results: list, module_name: str) -> None:
    """Print a findings table for any scanner result list."""
    if not results:
        return
    tbl = Table(title=f"{module_name} Findings", border_style="cyan", show_lines=True)
    tbl.add_column("Severity", style="bold", width=10)
    tbl.add_column("Type", width=30)
    tbl.add_column("Detail", width=60)
    for r in results:
        sev = r.get("severity", "info")
        tbl.add_row(
            f"[{severity_color(sev)}]{sev.upper()}[/]",
            str(r.get("type", r.get("vulnerability", "Finding")))[:30],
            str(r.get("detail", r.get("evidence", "")))[:60],
        )
    console.print(tbl)


# ──────────────────────────────────────────────
#  Main Toolkit Class
# ──────────────────────────────────────────────


class WebPwnToolkit:
    def __init__(self, profile_path: str = None):
        self.config = load_config(profile_path)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session = {
            "name": ts,
            "target": None,
            "domain": None,
            "threads": 10,
            "timeout": 10,
            "findings": [],
            "start_time": datetime.now().isoformat(),
        }
        self.logger = setup_logging(ts)
        self.reports_dir = ROOT / "reports"
        self.reports_dir.mkdir(exist_ok=True)
        self._session_mgr = None  # SessionManager instance

    # ── Target config ──────────────────────────────────────────────────

    def configure_target(self) -> None:
        console.print(Rule("[bold cyan]Target Configuration[/bold cyan]"))
        target = Prompt.ask(
            "\n  [cyan]Enter target URL[/cyan]", default="http://localhost"
        )

        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        try:
            parsed = urlparse(target)
            domain = parsed.netloc or parsed.path
            if not domain:
                raise ValueError("Invalid domain")
        except Exception as e:
            console.print(f"[red]❌ Invalid URL: {e}[/red]")
            return

        self.session["target"] = target
        self.session["domain"] = domain
        self.session["threads"] = IntPrompt.ask("\n  [cyan]Threads[/cyan]", default=10)
        self.session["timeout"] = IntPrompt.ask(
            "  [cyan]Timeout (seconds)[/cyan]", default=10
        )

        console.print(f"\n  ✅ Target : [green]{target}[/green]")
        console.print(f"  ✅ Domain : [green]{domain}[/green]")
        self.logger.info(f"Target configured: {target}")

    # ── Auth / Session ─────────────────────────────────────────────────

    def configure_auth(self) -> None:
        from modules.web.session_manager import SessionManager

        console.print(Rule("[bold cyan]Auth / Session Setup[/bold cyan]"))
        sm = SessionManager(self.config)

        menu = {
            "1": "Form-based login",
            "2": "Bearer token",
            "3": "API key",
            "4": "Raw cookies",
            "5": "Proxy (Burp/ZAP)",
            "6": "Show session status",
            "0": "← Back",
        }
        self._print_menu(menu)
        choice = Prompt.ask("\n  [cyan]Select[/cyan]", choices=list(menu.keys()))

        if choice == "0":
            return

        elif choice == "1":
            if not self.session["target"]:
                console.print("  [red]Configure target first.[/red]")
                return
            login_path = Prompt.ask("  [cyan]Login path[/cyan]", default="/login")
            username = Prompt.ask("  [cyan]Username[/cyan]")
            password = Prompt.ask("  [cyan]Password[/cyan]", password=True)
            user_field = Prompt.ask(
                "  [cyan]Username field name[/cyan]", default="username"
            )
            pass_field = Prompt.ask(
                "  [cyan]Password field name[/cyan]", default="password"
            )
            check_url = Prompt.ask(
                "  [cyan]Auth check URL (leave blank to skip)[/cyan]", default=""
            )
            marker = Prompt.ask(
                "  [cyan]Auth marker text (e.g. Logout)[/cyan]", default=""
            )
            sm.login_form(
                self.session["target"],
                login_path,
                {user_field: username, pass_field: password},
                auth_check_url=check_url or None,
                auth_marker=marker or None,
            )

        elif choice == "2":
            token = Prompt.ask("  [cyan]Bearer token[/cyan]")
            sm.set_bearer_token(token)

        elif choice == "3":
            header_name = Prompt.ask(
                "  [cyan]API key header[/cyan]", default="X-API-Key"
            )
            api_key = Prompt.ask("  [cyan]API key value[/cyan]")
            sm.set_api_key(header_name, api_key)

        elif choice == "4":
            raw = Prompt.ask("  [cyan]Cookies (name=value; name2=value2)[/cyan]")
            cookies = {}
            for part in raw.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
            sm.set_cookies(cookies)

        elif choice == "5":
            proxy_url = Prompt.ask(
                "  [cyan]Proxy URL[/cyan]", default="http://127.0.0.1:8080"
            )
            sm._session.proxies = {"http": proxy_url, "https": proxy_url}
            sm._session.verify = False
            console.print(f"  [green]✅ Proxy set: {proxy_url}[/green]")

        elif choice == "6":
            status = (
                sm.status()
                if self._session_mgr
                else {"auth_type": "none (not configured)"}
            )
            tbl = Table(title="Session Status", border_style="cyan")
            tbl.add_column("Property")
            tbl.add_column("Value")
            for k, v in status.items():
                tbl.add_row(str(k), str(v))
            console.print(tbl)
            return

        self._session_mgr = sm
        self.session["auth_type"] = sm.auth_type
        console.print("  [green]✅ Session manager active.[/green]")

    # ── Recon ──────────────────────────────────────────────────────────

    def run_recon(self) -> None:
        if not self.session["target"]:
            console.print("  [red]⚠️  Configure target first.[/red]")
            return

        console.print(Rule("[bold cyan]Reconnaissance[/bold cyan]"))
        menu = {
            "1": "Subdomain Enumeration",
            "2": "Port Scanner",
            "3": "Technology Fingerprinting",
            "4": "Web Crawler (w/ JS Analyzer)",
            "5": "Cloud Asset Hunter",
            "6": "ASN / BGP Enum",
            "7": "GitHub Leakage Dorker",
            "99": "Run All Recon",
            "0": "← Back",
        }
        self._print_menu(menu)
        choice = Prompt.ask("\n  [cyan]Select[/cyan]", choices=list(menu.keys()))
        if choice == "0":
            return

        from modules.recon.subdomain_enum import SubdomainEnumerator
        from modules.recon.port_scanner import PortScanner
        from modules.recon.tech_detector import TechDetector
        from modules.recon.crawler import WebCrawler
        from modules.recon.cloud_hunter import CloudHunter
        from modules.recon.asn_enum import ASNEnumerator
        from modules.recon.github_dorker import GitHubDorker

        dom = self.session["domain"]
        target = self.session["target"]
        th, to = self.session["threads"], self.session["timeout"]

        tasks = {
            "1": ("Subdomain Enum", lambda: SubdomainEnumerator(dom, threads=th).run()),
            "2": ("Port Scan", lambda: PortScanner(dom, timeout=to).run()),
            "3": ("Tech Detect", lambda: TechDetector(target, timeout=to).run()),
            "4": (
                "Web Crawler",
                lambda: WebCrawler(target, threads=th, timeout=to).run(),
            ),
            "5": (
                "Cloud Hunter",
                lambda: CloudHunter(dom, threads=th, timeout=to).run(),
            ),
            "6": ("ASN Enum", lambda: ASNEnumerator(dom).run()),
            "7": ("GitHub Dorker", lambda: GitHubDorker(dom).run()),
        }

        run_keys = list(tasks.keys()) if choice == "99" else [choice]
        for key in run_keys:
            name, func = tasks[key]
            console.print(f"\n  [bold yellow]▶ {name}...[/bold yellow]")
            try:
                res = func()
                self.session["findings"].append(
                    {"module": name, "severity": "info", "data": res}
                )
                if name == "Tech Detect":
                    self.session["tech_data"] = res
                    self._show_tech(res)
                elif name == "Web Crawler":
                    self.session["crawl_data"] = res
                    self._show_findings_table(
                        "Crawler Results",
                        [
                            ("Pages", len(res.get("pages", []))),
                            ("Forms", len(res.get("forms", []))),
                            ("Endpoints", len(res.get("endpoints", []))),
                        ],
                        ["Metric", "Count"],
                    )
                elif name == "Port Scan":
                    _display_results(res if isinstance(res, list) else [], name)
                elif name == "Subdomain Enum":
                    if isinstance(res, list):
                        console.print(f"  [dim]Found {len(res)} subdomain(s)[/dim]")
            except Exception as e:
                console.print(f"  [red]❌ {name} error: {e}[/red]")
                self.logger.error(f"{name} failed: {e}")

        save_session(self.session)

    # ── Web Attacks ────────────────────────────────────────────────────

    def run_web_attacks(self) -> None:
        if not self.session["target"]:
            console.print("  [red]⚠️  Configure target first.[/red]")
            return

        console.print(Rule("[bold cyan]Web Attack Modules[/bold cyan]"))
        target = self.session["target"]
        th, to = self.session["threads"], self.session["timeout"]
        sess = self._session_mgr.get_session() if self._session_mgr else None
        tech = self.session.get("tech_data", {})

        def _run(name: str, func):
            console.print(f"\n  [bold yellow]▶ {name}...[/bold yellow]")
            try:
                res = func()
                findings = res if isinstance(res, list) else []
                for f in findings:
                    self.session["findings"].append(f)
                _display_results(findings, name)
                console.print(f"  [dim]→ {len(findings)} finding(s) from {name}[/dim]")
                return findings
            except Exception as e:
                console.print(f"  [red]❌ {name} error: {e}[/red]")
                self.logger.error(f"{name} failed: {e}")
                return []

        # Scanner factory — lazy imports
        def sqli():
            from modules.web.sqli_scanner import SQLiScanner

            return SQLiScanner(target, threads=th, timeout=to, session=sess).run()

        def xss():
            from modules.web.xss_scanner import XSSScanner

            return XSSScanner(target, threads=th, timeout=to, session=sess).run()

        def dirb():
            from modules.web.dir_bruteforce import DirBruteforcer

            return DirBruteforcer(target, threads=th, timeout=to, session=sess).run()

        def auth():
            from modules.web.auth_tester import AuthTester

            return AuthTester(target, timeout=to).run()

        def ssrf():
            from modules.web.ssrf_scanner import SSRFScanner

            return SSRFScanner(target, timeout=to, session=sess).run()

        def cors():
            from modules.web.cors_scanner import CORSScanner

            return CORSScanner(target, timeout=to).run()

        def headers():
            from modules.web.header_analyzer import HeaderAnalyzer

            return HeaderAnalyzer(target, timeout=to, session=sess).run()

        def cookies():
            from modules.web.cookie_checker import CookieChecker

            return CookieChecker(target, timeout=to, session=sess).run()

        def cmdi():
            from modules.web.cmdi_scanner import CMDIScanner

            return CMDIScanner(target, threads=th, timeout=to, session=sess).run()

        def csrf():
            from modules.web.csrf_scanner import CSRFScanner

            return CSRFScanner(target, timeout=to, session=sess).run()

        def lfi():
            from modules.web.lfi_scanner import LFIScanner

            return LFIScanner(target, threads=th, timeout=to, session=sess).run()

        def xxe():
            from modules.web.xxe_scanner import XXEScanner

            return XXEScanner(target, threads=th, timeout=to, session=sess).run()

        def waf():
            from modules.web.waf_detector import WAFDetector

            return WAFDetector(target, timeout=to, session=sess).run()

        def jwt():
            from modules.web.jwt_analyzer import JWTAnalyzer

            return JWTAnalyzer(target, timeout=to).run()

        def redirect():
            from modules.web.open_redirect_scanner import OpenRedirectScanner

            return OpenRedirectScanner(target, threads=th, timeout=to).run()

        def cve():
            from modules.web.cve_lookup import CVELookup

            if not tech:
                console.print(
                    "  [yellow]Run Tech Detect first for best CVE results.[/yellow]"
                )
            return CVELookup(
                tech_findings=tech or {"target": [target]}, timeout=15
            ).run()

        def dom():
            from modules.web.dom_scanner import DOMScanner

            return DOMScanner(target, timeout=to, session=sess).run()

        def oauth():
            from modules.web.oauth_tester import OAuthTester

            return OAuthTester(target, timeout=to).run()

        def admin_hunt():
            custom = Prompt.ask(
                "  [cyan]Admin URL(s) to test (comma-separated, or press Enter to probe common paths)[/cyan]",
                default="",
            )
            if custom.strip():
                admin_urls = [u.strip() for u in custom.split(",") if u.strip()]
            else:
                from modules.web.dir_bruteforce import DirBruteforcer

                COMMON_ADMIN = [
                    "/admin",
                    "/admin/",
                    "/administrator",
                    "/dashboard",
                    "/wp-admin",
                    "/manager",
                    "/cpanel",
                    "/console",
                    "/backend",
                    "/control",
                    "/panel",
                    "/manage",
                    "/phpmyadmin",
                    "/adminer",
                ]
                admin_urls = []
                # Baseline check to filter soft-404s and SPAs
                try:
                    baseline_r = (sess or __import__("requests")).get(
                        target.rstrip("/") + "/this_admin_path_does_not_exist_123",
                        timeout=to, verify=False, allow_redirects=True
                    )
                    baseline_size = len(baseline_r.text) if baseline_r.status_code == 200 else -1
                except Exception:
                    baseline_size = -1

                for path in COMMON_ADMIN:
                    try:
                        r = (sess or __import__("requests")).get(
                            target.rstrip("/") + path,
                            timeout=to,
                            verify=False,
                            allow_redirects=True,
                        )
                        if r.status_code == 200:
                            if baseline_size == -1 or abs(len(r.text) - baseline_size) > 50:
                                admin_urls.append(target.rstrip("/") + path)
                    except Exception:
                        pass
                console.print(
                    f"  [dim]→ Probed {len(COMMON_ADMIN)} paths, found {len(admin_urls)} admin page(s)[/dim]"
                )

            if not admin_urls:
                console.print("  [yellow]No admin URLs found or provided.[/yellow]")
                return []

            from modules.web.admin_hunter import AdminHunter

            return AdminHunter(
                target=target,
                admin_urls=admin_urls,
                threads=th,
                timeout=to,
                session=sess,
            ).run()

        scanners = {
            "1": ("SQL Injection", sqli),
            "2": ("XSS Scanner", xss),
            "3": ("Directory Bruteforce", dirb),
            "4": ("Auth Tester", auth),
            "5": ("SSRF Scanner", ssrf),
            "6": ("CORS Scanner", cors),
            "9": ("Command Injection", cmdi),
            "10": ("CSRF Scanner", csrf),
            "11": ("LFI Scanner", lfi),
            "12": ("XXE Scanner", xxe),
            "14": ("JWT Analyzer", jwt),
            "19": ("Admin Hunter (deep)", admin_hunt),
            "37": (
                "NoSQL Injection",
                lambda: __import__("modules.web.nosql_scanner", fromlist=["NoSQLScanner"]).NoSQLScanner(target, session=sess, timeout=to).run(),
            ),
            "40": (
                "Cloud Misconfig",
                lambda: __import__("modules.web.cloud_misconfig_scanner", fromlist=["CloudMisconfigScanner"]).CloudMisconfigScanner(target, session=sess, timeout=to).run(),
            ),
            "99": ("🔥 Senior Autopilot (Run OWASP Core + Auto Report)", "autopilot"),
            "0": ("← Back", None),
        }

        # Instead of generic _print_menu, explicitly print formatted table for Web Modules
        console.print("\n  [bold cyan]Available Web Attack Modules:[/bold cyan]")
        for k, v in scanners.items():
            if k == "0":
                console.print(f"  [cyan]{k:>2}[/cyan]. {v[0]}")
            elif k == "99":
                console.print(f"\n  [bold red]{k:>2}. {v[0]}[/bold red]")
            else:
                console.print(f"  [cyan]{k:>2}[/cyan]. {v[0]}")
        choice = Prompt.ask("\n  [cyan]Select[/cyan]", choices=list(scanners.keys()))
        if choice == "0":
            return

        if choice == "99":
            console.print(
                "\n  [bold red]🔥 Initializing Senior Autopilot Mode (Optimized OWASP Core)...[/bold red]"
            )
            # Only run the most critical, fastest, and impactful OWASP Top 10 modules
            # to massively reduce scan times.
            owasp_core = {
                "1", "2", "3", "4", "5", "9", "10", "11", "12", "14", 
                "37", "40"
            }
            
            for k, (name, func) in scanners.items():
                if k in owasp_core:
                    _run(name, func)

            # Run Admin Hunter Automatically using common paths
            from modules.web.admin_hunter import AdminHunter

            COMMON_ADMIN = ["/admin", "/administrator", "/wp-admin", "/cpanel"]
            admin_urls = []
            try:
                baseline_r = (sess or __import__("requests")).get(
                    target.rstrip("/") + "/this_admin_path_does_not_exist_123",
                    timeout=to, verify=False, allow_redirects=True
                )
                baseline_size = len(baseline_r.text) if baseline_r.status_code == 200 else -1
            except Exception:
                baseline_size = -1

            for path in COMMON_ADMIN:
                try:
                    r = (sess or __import__("requests")).get(
                        target.rstrip("/") + path, timeout=to, verify=False, allow_redirects=True
                    )
                    if r.status_code == 200:
                        if baseline_size == -1 or abs(len(r.text) - baseline_size) > 50:
                            admin_urls.append(target.rstrip("/") + path)
                except:
                    pass
            if admin_urls:
                console.print(
                    "\n  [bold yellow]\u25b6 Admin Hunter (Autopilot)...[/bold yellow]"
                )
                res = AdminHunter(
                    target, admin_urls, threads=th, timeout=to, session=sess
                ).run()
                for f in res:
                    self.session["findings"].append(f)

            # Run 2FA Bypass
            console.print("\n  [bold yellow]\u25b6 2FA/MFA Bypass...[/bold yellow]")
            try:
                from modules.web.mfa_bypass import MFABypassTester

                mfa_res = MFABypassTester(target, session=sess, timeout=to).run()
                for f in mfa_res:
                    self.session["findings"].append(f)
            except Exception as e:
                console.print(f"  [dim]MFA bypass error: {e}[/dim]")

            # Run Chain Engine on accumulated findings
            console.print(
                "\n  [bold yellow]\u25b6 Exploit Chain Analyzer...[/bold yellow]"
            )
            try:
                from modules.web.chain_engine import ChainEngine

                chains = ChainEngine(self.session["findings"], target=target).analyze()
                for c in chains:
                    self.session["findings"].append(c)
            except Exception as e:
                console.print(f"  [dim]Chain engine error: {e}[/dim]")

            # Run IDOR Scanner
            console.print("\n  [bold yellow]\u25b6 IDOR Scanner...[/bold yellow]")
            try:
                from modules.web.idor_scanner import IDORScanner

                deduplicator.add(
                    IDORScanner(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]IDOR error: {e}[/dim]")

            # Run GraphQL Tester
            console.print("\n  [bold yellow]\u25b6 GraphQL Tester...[/bold yellow]")
            try:
                from modules.web.graphql_tester import GraphQLTester

                deduplicator.add(
                    GraphQLTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]GraphQL error: {e}[/dim]")

            # Run WebSocket Fuzzer
            console.print("\n  [bold yellow]\u25b6 WebSocket Fuzzer...[/bold yellow]")
            try:
                from modules.web.websocket_fuzzer import WebSocketFuzzer

                deduplicator.add(
                    WebSocketFuzzer(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]WebSocket error: {e}[/dim]")

            # ── NEW MODULES ──────────────────────────────────────────────

            console.print(
                "\n  [bold yellow]\u25b6 Prototype Pollution Scanner...[/bold yellow]"
            )
            try:
                from modules.web.prototype_pollution import PrototypePollutionScanner

                deduplicator.add(
                    PrototypePollutionScanner(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]Prototype Pollution error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 Cache Poisoning Tester...[/bold yellow]"
            )
            try:
                from modules.web.cache_poisoning import CachePoisoningTester

                deduplicator.add(
                    CachePoisoningTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]Cache Poisoning error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 HTTP Request Smuggling...[/bold yellow]"
            )
            try:
                from modules.web.http_smuggling import HTTPSmuggling

                deduplicator.add(
                    HTTPSmuggling(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]HTTP Smuggling error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 CRLF Injection Scanner...[/bold yellow]"
            )
            try:
                from modules.web.crlf_scanner import CRLFScanner

                deduplicator.add(
                    CRLFScanner(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]CRLF error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 NoSQL Injection Scanner...[/bold yellow]"
            )
            try:
                from modules.web.nosql_scanner import NoSQLScanner

                deduplicator.add(
                    NoSQLScanner(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]NoSQL error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 Advanced SSTI Scanner...[/bold yellow]"
            )
            try:
                from modules.web.ssti_advanced_scanner import AdvancedSSTIScanner

                deduplicator.add(
                    AdvancedSSTIScanner(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]SSTI error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 Deserialization Tester...[/bold yellow]"
            )
            try:
                from modules.web.deserialization_tester import DeserializationTester

                deduplicator.add(
                    DeserializationTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]Deserialization error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 Cloud Misconfig Scanner...[/bold yellow]"
            )
            try:
                from modules.web.cloud_misconfig_scanner import CloudMisconfigScanner

                deduplicator.add(
                    CloudMisconfigScanner(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]Cloud Misconfig error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 Email Header Injection...[/bold yellow]"
            )
            try:
                from modules.web.email_header_injection import (
                    EmailHeaderInjectionTester,
                )

                deduplicator.add(
                    EmailHeaderInjectionTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]Email Header Injection error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 XXE DTD Exfiltration...[/bold yellow]"
            )
            try:
                from modules.web.xxe_dtd_scanner import XXEDTDScanner

                deduplicator.add(
                    XXEDTDScanner(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]XXE DTD error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 OAuth PKCE Bypass Tester...[/bold yellow]"
            )
            try:
                from modules.web.oauth_pkce_bypass import OAuthTester

                deduplicator.add(
                    OAuthTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]OAuth PKCE error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 SAML Injection Tester...[/bold yellow]"
            )
            try:
                from modules.web.saml_injection import SAMLTester

                deduplicator.add(
                    SAMLTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]SAML error: {e}[/dim]")

            console.print("\n  [bold yellow]\u25b6 PostMessage Tester...[/bold yellow]")
            try:
                from modules.web.postmessage_tester import PostMessageTester

                deduplicator.add(
                    PostMessageTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]PostMessage error: {e}[/dim]")

            console.print(
                "\n  [bold yellow]\u25b6 CSS Injection Tester...[/bold yellow]"
            )
            try:
                from modules.web.css_injection import CSSInjectionTester

                deduplicator.add(
                    CSSInjectionTester(target, session=sess, timeout=to).run(),
                    self.session["findings"],
                )
            except Exception as e:
                console.print(f"  [dim]CSS Injection error: {e}[/dim]")

            # Run Exploit Engine on all collected findings
            console.print("\n  [bold yellow]\u25b6 Exploit Engine...[/bold yellow]")
            try:
                from modules.web.exploit_engine import ExploitEngine

                exploits = ExploitEngine(
                    target, self.session["findings"], session=sess, timeout=to
                ).run()
                for f in exploits:
                    self.session["findings"].append(f)
            except Exception as e:
                console.print(f"  [dim]Exploit engine error: {e}[/dim]")

            # Automatically Generate Report
            console.print(
                "\n  [bold green]\u2705 Autopilot Completed. Generating Report...[/bold green]"
            )
            from modules.reporter.html_report import ReportGenerator

            report_name = f"autopilot_{self.session['name']}"
            path = ReportGenerator(self.session).generate(report_name)
            console.print(f"  \u2705 Report saved \u2192 [bold cyan]{path}[/bold cyan]")

        else:
            name, func = scanners[choice]
            _run(name, func)

        save_session(self.session)

    # ── Mobile Analysis ────────────────────────────────────────────────

    def run_mobile(self) -> None:
        console.print(Rule("[bold cyan]Mobile Analysis[/bold cyan]"))
        menu = {
            "1": "APK Static Analysis",
            "2": "Mobile API Tester",
            "3": "Dynamic Instrumentation (Frida)",
            "4": "Run All Mobile Modules",
            "0": "← Back",
        }
        self._print_menu(menu)
        choice = Prompt.ask("\n  [cyan]Select[/cyan]", choices=list(menu.keys()))
        if choice == "0":
            return

        to = self.session["timeout"]

        if choice in ("1", "4"):
            apk_path = Prompt.ask("\n  [cyan]APK file path[/cyan]", default="")
            if not apk_path or not Path(apk_path).exists():
                console.print("  [red]❌ APK file not found.[/red]")
                if choice == "1":
                    return
            else:
                console.print(
                    f"\n  [bold yellow]▶ APK Static Analysis...[/bold yellow]"
                )
                try:
                    from modules.mobile.apk_analyzer import APKAnalyzer

                    results = APKAnalyzer(apk_path).run()
                    for f in results:
                        self.session["findings"].append(f)
                    _display_results(results, "APK Analysis")
                    console.print(f"  [dim]→ {len(results)} finding(s)[/dim]")
                except Exception as e:
                    console.print(f"  [red]❌ APK Analyzer error: {e}[/red]")
                    self.logger.error(f"APK Analyzer failed: {e}")

        if choice in ("2", "4"):
            target = self.session.get("target") or Prompt.ask(
                "\n  [cyan]API base URL[/cyan]", default="http://localhost"
            )
            auth_token = None
            if self._session_mgr:
                hdrs = self._session_mgr.get_session().headers
                bearer = hdrs.get("Authorization", "")
                if bearer.startswith("Bearer "):
                    auth_token = bearer.split(" ", 1)[1]

            console.print(f"\n  [bold yellow]▶ Mobile API Tester...[/bold yellow]")
            try:
                from modules.mobile.api_tester import APITester

                results = APITester(target, timeout=to, auth_token=auth_token).run()
                for f in results:
                    self.session["findings"].append(f)
                _display_results(results, "Mobile API Tester")
                console.print(f"  [dim]→ {len(results)} finding(s)[/dim]")
            except Exception as e:
                console.print(f"  [red]❌ API Tester error: {e}[/red]")
                self.logger.error(f"API Tester failed: {e}")

        if choice in ("3", "4"):
            console.print(
                f"\n  [bold yellow]▶ Dynamic Instrumentation (Frida)...[/bold yellow]"
            )
            try:
                from modules.mobile.frida_instrumentation import FridaInstrumentation

                results = FridaInstrumentation().run()
                for f in results:
                    self.session["findings"].append(f)
                _display_results(results, "Frida Dynamic Analysis")
                console.print(f"  [dim]→ {len(results)} finding(s)[/dim]")
            except Exception as e:
                console.print(f"  [red]❌ Frida Instrumentation error: {e}[/red]")
                self.logger.error(f"Frida Instrumentation failed: {e}")

        save_session(self.session)

    # ── Report ─────────────────────────────────────────────────────────

    def generate_report(self) -> None:
        console.print(Rule("[bold cyan]Report Generator[/bold cyan]"))
        if not self.session["findings"]:
            console.print("  [yellow]No findings yet.[/yellow]")
            return
        name = Prompt.ask(
            "\n  [cyan]Report filename[/cyan]",
            default=f"pentest_{self.session['name']}",
        )
        try:
            from modules.reporter.html_report import ReportGenerator

            path = ReportGenerator(self.session).generate(name)
            console.print(f"\n  ✅ Report saved → [green]{path}[/green]")
        except Exception as e:
            console.print(f"  [red]❌ Report generation failed: {e}[/red]")

    # ── Session summary ────────────────────────────────────────────────

    def show_summary(self) -> None:
        console.print(Rule("[bold cyan]Session Summary[/bold cyan]"))
        findings = self.session["findings"]
        if not findings:
            console.print("  [dim]No findings yet.[/dim]")
            return

        count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in count:
                count[sev] += 1

        tbl = Table(title="Vulnerability Summary", border_style="cyan")
        tbl.add_column("Severity", style="bold")
        tbl.add_column("Count", justify="right")
        tbl.add_column("Risk Level", style="dim")

        risk_map = {
            "critical": ("bold red", "Immediate action required"),
            "high": ("red", "Fix as soon as possible"),
            "medium": ("yellow", "Fix in next release"),
            "low": ("blue", "Fix when convenient"),
            "info": ("cyan", "Informational"),
        }
        for sev, (color, risk) in risk_map.items():
            tbl.add_row(f"[{color}]{sev.upper()}[/]", str(count[sev]), risk)
        console.print(tbl)

    # ── Helpers ────────────────────────────────────────────────────────

    def _show_findings_table(self, title: str, rows: list, columns: list) -> None:
        if not rows:
            return
        tbl = Table(title=title, border_style="cyan", show_lines=True)
        for col in columns:
            tbl.add_column(col)
        for row in rows:
            tbl.add_row(*[str(v) for v in row])
        console.print(tbl)

    def _show_tech(self, result: dict) -> None:
        tbl = Table(title="Detected Technologies", border_style="cyan")
        tbl.add_column("Category", style="bold cyan")
        tbl.add_column("Value")
        for k, v in result.items():
            tbl.add_row(k, ", ".join(v) if isinstance(v, list) else str(v))
        console.print(tbl)

    def _print_menu(self, menu: dict) -> None:
        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column(style="bold cyan", width=4)
        tbl.add_column(style="white")
        for k, v in menu.items():
            tbl.add_row(k, v)
        console.print(tbl)


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="WebPwn Toolkit - Professional Penetration Testing Framework"
    )
    parser.add_argument("-t", "--target", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "-p", "--profile", help="Scan profile (e.g. profiles/stealth.yaml)"
    )
    parser.add_argument(
        "--autopilot", action="store_true", help="Run in non-interactive autopilot mode"
    )
    args = parser.parse_args()

    print_banner()
    if not args.autopilot and not Confirm.ask(
        "\n  [bold red]Have you read DISCLAIMER.md and confirmed authorization?[/bold red]"
    ):
        console.print("\n  [red]Exiting...[/red]\n")
        sys.exit(0)

    toolkit = WebPwnToolkit(profile_path=args.profile)

    if args.target:
        toolkit.session["target"] = args.target
        parsed = urlparse(args.target)
        toolkit.session["domain"] = parsed.netloc or parsed.path
        if args.autopilot:
            console.print(
                f"\n  [bold green]🔥 AutoPilot Mode Initiated on {args.target}[/bold green]"
            )

            # Simulate choice 99 for Web Attacks
            class DummySession:
                pass

            toolkit._session_mgr = DummySession()
            toolkit._session_mgr.get_session = lambda: __import__("requests").Session()
            toolkit._session_mgr.auth_type = "none"

            # Simple wrapper to just call autopilot directly if needed, or
            # let user pick from menu. We will drop them in Web Attack menu with autopilot pre-selected.
            console.print(
                "  [dim]Autopilot via CLI currently drops to main menu with pre-configured target. For full headless execution, use the provided Docker API.[/dim]"
            )
    MAIN_MENU = {
        "1": "⚙️   Configure Target",
        "2": "🔍  Reconnaissance",
        "3": "🔐  Auth / Session Setup",
        "4": "💉  Web Attack Modules",
        "5": "📱  Mobile Analysis",
        "6": "📊  Show Session Summary",
        "7": "📄  Generate Report",
        "0": "🚪  Exit",
    }

    while True:
        console.print()
        console.print(Rule("[bold cyan]Main Menu[/bold cyan]"))
        if toolkit.session["target"]:
            console.print(
                f"  Target: [green]{toolkit.session['target']}[/green]   "
                f"Findings: [yellow]{len(toolkit.session['findings'])}[/yellow]"
            )

        toolkit._print_menu(MAIN_MENU)
        choice = Prompt.ask("\n  [cyan]Select[/cyan]", choices=list(MAIN_MENU.keys()))

        actions = {
            "1": toolkit.configure_target,
            "2": toolkit.run_recon,
            "3": toolkit.configure_auth,
            "4": toolkit.run_web_attacks,
            "5": toolkit.run_mobile,
            "6": toolkit.show_summary,
            "7": toolkit.generate_report,
        }

        if choice == "0":
            save_session(toolkit.session)
            console.print("\n  [cyan]Session saved. Goodbye! 👋[/cyan]\n")
            break

        try:
            actions[choice]()
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
            toolkit.logger.error(f"Error in main loop: {e}")


if __name__ == "__main__":
    main()
