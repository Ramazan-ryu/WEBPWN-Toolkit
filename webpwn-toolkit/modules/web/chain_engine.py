#!/usr/bin/env python3
"""
Vulnerability Chain Engine
---------------------------
Detects and constructs multi-stage attack chains by combining
individually discovered vulnerabilities into exploit chains.

Supported chains:
  XSS  → CSRF → Account Takeover
  SQLi → Credential Dump → Admin Login
  SSRF → Internal Pivot → Cloud Metadata
  LFI  → Source Code Read → Credential Extract
  CORS → XSS → Session Steal
  Open Redirect → Phishing → Credential Harvest
  XXE  → SSRF → Internal Port Scan
  IDOR → PII Exfiltration → Account Hijack
"""

import itertools
from typing import List, Dict, Tuple, Optional
from rich.console import Console
from rich.table import Table

console = Console()

# ── Chain definitions ─────────────────────────────────────────────────────────
# Each chain: (name, step1_keywords, step2_keywords, severity, cvss, description, remediation)

CHAINS: List[Tuple] = [
    (
        "XSS → CSRF → Account Takeover",
        ["xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss"],
        ["csrf", "missing csrf", "no csrf token", "cross-site request"],
        "critical",
        9.8,
        (
            "XSS allows attacker to steal CSRF tokens from victim's browser DOM, "
            "then forge authenticated state-changing requests (password reset, email change) "
            "without victim's knowledge — leading to full account takeover."
        ),
        (
            "Implement strict CSP (Content-Security-Policy). "
            "Use SameSite=Strict cookies. "
            "Enforce CSRF tokens even when XSS is patched (defense in depth)."
        ),
        "XSS → Steal CSRF Token → Forge Request → Change Email/Password → Account Takeover",
    ),
    (
        "SQLi → Credential Dump → Admin Takeover",
        ["sqli", "sql injection", "error-based sqli", "time-based blind sqli"],
        ["admin", "login", "authentication", "user enumeration", "default credentials"],
        "critical",
        10.0,
        (
            "SQL injection allows dumping the users/credentials table. "
            "Cracked or plaintext credentials can be used to log in as admin, "
            "achieving full application compromise."
        ),
        (
            "Use parameterized queries. "
            "Hash passwords with bcrypt/argon2. "
            "Enforce MFA on admin accounts."
        ),
        "SQLi → UNION SELECT users,passwords → Crack Hash → Login as Admin → Full Compromise",
    ),
    (
        "SSRF → Cloud Metadata → Credential Theft",
        ["ssrf", "server-side request forgery"],
        ["aws", "gcp", "azure", "cloud", "metadata", "169.254.169.254"],
        "critical",
        10.0,
        (
            "SSRF allows the attacker to query cloud metadata endpoints (169.254.169.254). "
            "This exposes IAM role credentials (access key + secret) "
            "enabling full cloud account compromise."
        ),
        (
            "Block 169.254.169.254 at network level. "
            "Use IMDSv2 (AWS). "
            "Validate and whitelist all server-side URL inputs."
        ),
        "SSRF → 169.254.169.254 → IAM Key → aws s3 ls → Full Cloud Compromise",
    ),
    (
        "LFI → Config Read → Credential Extraction",
        ["lfi", "local file inclusion", "path traversal", "directory traversal"],
        ["config", "database", "credentials", "db_password", ".env", "wp-config"],
        "critical",
        9.1,
        (
            "Local File Inclusion allows reading configuration files containing "
            "database credentials, API keys, and encryption secrets. "
            "These can be used to directly access the database or external services."
        ),
        (
            "Move config files outside web root. "
            "Use secrets managers (Vault, AWS SSM). "
            "Restrict file path inputs — whitelist allowed files."
        ),
        "LFI → /app/.env → DB_PASSWORD → Database Access → Full Data Breach",
    ),
    (
        "CORS Misconfiguration → XSS → Session Theft",
        ["cors", "cross-origin", "access-control-allow-origin: *"],
        ["xss", "cross-site scripting", "session", "cookie"],
        "high",
        8.8,
        (
            "Permissive CORS allows malicious origins to make authenticated API requests. "
            "Combined with XSS, attacker can send victim's session cookies "
            "to a controlled server via cross-origin fetch."
        ),
        (
            "Restrict CORS to trusted origins. "
            "Do not use wildcard (*) with credentials. "
            "Set HttpOnly + Secure + SameSite on cookies."
        ),
        "CORS * → XSS on trusted subdomain → fetch(attacker.com, cookies) → Session Steal",
    ),
    (
        "Open Redirect → Phishing → OAuth Token Steal",
        ["open redirect", "unvalidated redirect", "url redirect"],
        ["oauth", "login", "authentication", "token", "sso"],
        "high",
        7.4,
        (
            "An open redirect on the login page can be used to redirect OAuth "
            "authorization codes to an attacker-controlled server. "
            "The victim's session tokens are silently stolen."
        ),
        (
            "Whitelist all redirect URLs. "
            "Never use user-supplied URLs in redirect_uri without strict validation. "
            "Implement state parameter in OAuth flows."
        ),
        "Open Redirect → Craft malicious login URL → Victim clicks → OAuth code stolen",
    ),
    (
        "XXE → SSRF → Internal Port Scan",
        ["xxe", "xml external entity", "xml injection"],
        ["ssrf", "server-side request", "internal", "port"],
        "high",
        8.6,
        (
            "XXE allows injecting external entity references that cause the "
            "server to make HTTP requests to internal services. "
            "This enables port scanning, service fingerprinting, and cloud metadata access."
        ),
        (
            "Disable XML external entity processing (XXE). "
            "Use safe XML parsers (defusedxml). "
            "Implement egress filtering for server HTTP requests."
        ),
        "XXE ENTITY → http://169.254.169.254 → Internal Services → Lateral Movement",
    ),
    (
        "IDOR → PII Exfiltration → Mass Account Hijack",
        ["idor", "insecure direct object", "broken access control", "object reference"],
        ["pii", "email", "password", "personal", "user data", "account"],
        "critical",
        9.1,
        (
            "Insecure Direct Object References allow attackers to enumerate "
            "user IDs and access other users' data (emails, addresses, payment info). "
            "At scale, this enables mass PII exfiltration and account takeover."
        ),
        (
            "Implement authorization checks on every resource access. "
            "Use UUID instead of sequential IDs. "
            "Log and alert on anomalous data access patterns."
        ),
        "IDOR /api/user/1 → iterate IDs → dump all emails → credential stuffing → mass takeover",
    ),
    (
        "Subdomain Takeover → Cookie Scope Hijack",
        ["subdomain takeover", "dangling cname", "unclaimed subdomain"],
        ["cookie", "session", "authentication", "same-site"],
        "high",
        8.2,
        (
            "A taken-over subdomain (e.g. staging.example.com) is on the same "
            "cookie domain as the main application. Attacker can set/read cookies "
            "from the parent domain, hijacking authenticated sessions."
        ),
        (
            "Monitor DNS records for dangling CNAMEs. "
            "Use __Host- cookie prefix to restrict scope. "
            "Implement SameSite=Strict cookies."
        ),
        "Takeover staging.example.com → Set domain=.example.com cookie → Read main app sessions",
    ),
    (
        "JWT None Algorithm → Admin Privilege Escalation",
        ["jwt", "json web token", "token"],
        ["admin", "privilege", "role", "authorization", "access control"],
        "critical",
        9.8,
        (
            "JWT with 'alg:none' or weak HS256 secret allows forging tokens "
            "with arbitrary claims (e.g. role:admin). "
            "This bypasses all role-based access controls."
        ),
        (
            "Enforce RS256/ES256 algorithms. "
            "Reject 'none' algorithm. "
            "Validate all JWT claims server-side. "
            "Use short expiration times."
        ),
        "JWT alg:none → Forge {role:admin} → Access admin panel → Full privilege escalation",
    ),
]


class ChainEngine:
    """
    Analyzes a list of findings and constructs multi-stage attack chains.
    """

    def __init__(self, findings: List[Dict], target: str = ""):
        self.findings = findings
        self.target = target
        self.chains: List[Dict] = []

    # ── Match finding to keywords ─────────────────────────────────────────────

    def _matches(self, finding: Dict, keywords: List[str]) -> bool:
        text = " ".join(
            [
                str(finding.get("type", "")),
                str(finding.get("detail", "")),
                str(finding.get("module", "")),
                str(finding.get("owasp", "")),
                str(finding.get("evidence", "")),
            ]
        ).lower()
        return any(kw.lower() in text for kw in keywords)

    # ── Main analysis ─────────────────────────────────────────────────────────

    def analyze(self) -> List[Dict]:
        console.print(
            f"\n  [bold yellow]▶ Chain Engine — analyzing {len(self.findings)} findings "
            f"for exploit chains...[/bold yellow]"
        )

        for chain_name, kw1, kw2, severity, cvss, desc, remediation, steps in CHAINS:
            # Find step-1 findings
            step1_findings = [f for f in self.findings if self._matches(f, kw1)]
            # Find step-2 findings
            step2_findings = [f for f in self.findings if self._matches(f, kw2)]

            if step1_findings and step2_findings:
                step1 = step1_findings[0]
                step2 = step2_findings[0]

                chain = {
                    "type": f"CHAIN: {chain_name}",
                    "severity": severity,
                    "cvss": cvss,
                    "url": step1.get("url", step2.get("url", self.target)),
                    "module": "Chain Engine",
                    "detail": desc,
                    "evidence": (
                        f"Step 1: [{step1.get('type','?')}] at {step1.get('url','?')}\n"
                        f"Step 2: [{step2.get('type','?')}] at {step2.get('url','?')}"
                    ),
                    "owasp": "A01:2021 – Broken Access Control (Chained)",
                    "remediation": remediation,
                    "attack_steps": steps,
                    "chain_components": [
                        step1.get("type", "?"),
                        step2.get("type", "?"),
                    ],
                }
                self.chains.append(chain)
                console.print(
                    f"  [bold red][CHAIN][/bold red] {chain_name} "
                    f"[dim]({severity.upper()} / CVSS {cvss})[/dim]"
                )

        if not self.chains:
            console.print(
                "  [dim]No exploit chains detected from current findings.[/dim]"
            )
        else:
            # Print summary table
            tbl = Table(
                title="Exploit Chain Summary", border_style="red", show_lines=True
            )
            tbl.add_column("Chain", style="bold red")
            tbl.add_column("Severity", style="bold")
            tbl.add_column("CVSS", justify="right")
            tbl.add_column("Attack Path", style="dim")
            for c in self.chains:
                name = c["type"].replace("CHAIN: ", "")
                sev = c["severity"].upper()
                score = str(c["cvss"])
                steps = c.get("attack_steps", "")[:80]
                tbl.add_row(name, sev, score, steps)
            console.print(tbl)

        return self.chains
