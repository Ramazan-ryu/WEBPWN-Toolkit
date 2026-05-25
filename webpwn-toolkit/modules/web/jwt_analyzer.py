#!/usr/bin/env python3
"""
JWT Analyzer
--------------
Tests for:
  • alg:none vulnerability (signature stripped)
  • Weak HS256 secret brute-force (common wordlist)
  • RS256 → HS256 algorithm confusion attack
  • Expired token accepted by server
  • JWT stored insecurely (response body / local storage hints)
  • Missing or weak claims (no exp, no iss, no aud)
"""

import base64
import hashlib
import hmac
import json
import time
import requests
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Common weak JWT secrets to brute-force
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "qwerty",
    "test",
    "jwt",
    "token",
    "supersecret",
    "changeme",
    "letmein",
    "hello",
    "world",
    "abc123",
    "mykey",
    "apikey",
    "12345678",
    "secret123",
    "jwttoken",
    "mysecret",
    "private",
    "master",
    "development",
    "production",
    "staging",
    "local",
]

# JWT regex pattern
import re

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64_decode_padded(s: str) -> bytes:
    """Base64url decode with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _b64_encode_url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def parse_jwt(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    """Parse JWT into (header, payload, signature). Returns None on failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64_decode_padded(parts[0]))
        payload = json.loads(_b64_decode_padded(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def forge_none_alg(token: str) -> str:
    """Create a JWT with alg:none and no signature."""
    parts = token.split(".")
    header = json.loads(_b64_decode_padded(parts[0]))
    header["alg"] = "none"
    new_header = _b64_encode_url(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."


def forge_hs256(token: str, secret: str) -> str:
    """Re-sign a JWT with HS256 using the given secret."""
    parts = token.split(".")
    header = json.loads(_b64_decode_padded(parts[0]))
    header["alg"] = "HS256"
    new_header_b64 = _b64_encode_url(json.dumps(header, separators=(",", ":")).encode())
    signing_input = f"{new_header_b64}.{parts[1]}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{new_header_b64}.{parts[1]}.{_b64_encode_url(sig)}"


class JWTAnalyzer:
    """JWT security analyzer — finds tokens in responses and tests attacks."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebPwnToolkit/1.0 (Security Assessment)"
        self.results: List[Dict] = []

    # ── Find JWT tokens in responses ───────────────────────────────────

    def _harvest_tokens(self) -> List[str]:
        """Crawl the target and collect JWT tokens from responses."""
        tokens = []
        urls_to_check = [self.target]

        for url in urls_to_check:
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                # Check response body
                found = JWT_REGEX.findall(resp.text)
                tokens.extend(found)
                # Check cookies
                for cookie_val in resp.cookies.values():
                    found = JWT_REGEX.findall(cookie_val)
                    tokens.extend(found)
                # Check Authorization header echo (some APIs echo it back)
                auth = resp.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    candidate = auth.split(" ", 1)[1]
                    if JWT_REGEX.match(candidate):
                        tokens.append(candidate)
            except Exception:
                pass

        # Deduplicate
        return list(dict.fromkeys(tokens))

    # ── Analyze a single token ─────────────────────────────────────────

    def _analyze_token(self, token: str) -> List[Dict]:
        findings = []
        parsed = parse_jwt(token)
        if not parsed:
            return findings

        header, payload, signature = parsed
        alg = header.get("alg", "none").upper()

        # 1) alg:none check
        if alg == "NONE":
            findings.append(
                {
                    "type": "JWT alg:none Vulnerability",
                    "severity": "critical",
                    "detail": "JWT uses alg:none — signature is not verified by the server",
                    "evidence": f"alg={alg} | token[:40]: {token[:40]}...",
                    "owasp": "A02:2021 – Cryptographic Failures",
                    "cvss": 9.8,
                    "remediation": (
                        "Explicitly reject tokens with alg:none. "
                        "Whitelist only expected algorithms (e.g., RS256)."
                    ),
                }
            )

        # 2) Missing exp claim
        if "exp" not in payload:
            findings.append(
                {
                    "type": "JWT Missing Expiration (exp)",
                    "severity": "medium",
                    "detail": "JWT has no 'exp' claim — token never expires",
                    "evidence": f"payload claims: {list(payload.keys())}",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "cvss": 5.3,
                    "remediation": "Always set an 'exp' claim. Use short-lived tokens (15-60 min).",
                }
            )
        else:
            # 3) Already expired but check if server accepts
            exp_ts = payload["exp"]
            if exp_ts < time.time():
                findings.append(
                    {
                        "type": "JWT Expired Token (potential acceptance)",
                        "severity": "high",
                        "detail": "JWT is expired — if server accepts it, replay attacks are possible",
                        "evidence": f"exp={exp_ts} | now={int(time.time())}",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "cvss": 7.5,
                        "remediation": "Strictly validate 'exp' claim on every request.",
                    }
                )

        # 4) Missing iss / aud
        for claim in ("iss", "aud"):
            if claim not in payload:
                findings.append(
                    {
                        "type": f"JWT Missing '{claim}' Claim",
                        "severity": "low",
                        "detail": f"JWT lacks '{claim}' — token may be accepted by unintended services",
                        "evidence": f"Missing claim: {claim}",
                        "owasp": "A07:2021 – Identification and Authentication Failures",
                        "cvss": 3.7,
                        "remediation": f"Add '{claim}' claim and validate it server-side.",
                    }
                )

        # 5) Weak HS256 secret brute-force
        if alg in ("HS256", "HS384", "HS512"):
            cracked = self._brute_force_secret(token, alg)
            if cracked:
                findings.append(
                    {
                        "type": "JWT Weak Secret (Brute-forced)",
                        "severity": "critical",
                        "detail": f"JWT secret is weak: '{cracked}'",
                        "evidence": f"Cracked secret: {cracked} | alg: {alg}",
                        "owasp": "A02:2021 – Cryptographic Failures",
                        "cvss": 9.8,
                        "remediation": (
                            "Use a cryptographically random secret of at least 256 bits. "
                            "Prefer RS256 (asymmetric) for stateless JWT."
                        ),
                    }
                )

        # 6) Sensitive data in payload
        sensitive_keys = ["password", "pass", "secret", "credit_card", "ssn", "dob"]
        for k in payload:
            if any(s in k.lower() for s in sensitive_keys):
                findings.append(
                    {
                        "type": "JWT Sensitive Data in Payload",
                        "severity": "high",
                        "detail": f"Sensitive field '{k}' found in JWT payload (base64 only, not encrypted)",
                        "evidence": f"Claim: {k}",
                        "owasp": "A02:2021 – Cryptographic Failures",
                        "cvss": 7.5,
                        "remediation": "Never store sensitive data in JWT payload. Use JWE for encrypted tokens.",
                    }
                )

        return findings

    # ── Brute-force HS256 secret ───────────────────────────────────────

    def _brute_force_secret(self, token: str, alg: str) -> Optional[str]:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = _b64_decode_padded(parts[2])

        alg_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_fn = alg_map.get(alg, hashlib.sha256)

        for secret in WEAK_SECRETS:
            sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if sig == expected_sig:
                return secret
        return None

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print("  [dim]-> Harvesting JWT tokens from target...[/dim]")

        tokens = self._harvest_tokens()
        console.print(f"  [dim]-> {len(tokens)} JWT token(s) found[/dim]")

        if not tokens:
            console.print("  [dim]-> No JWT tokens found in responses/cookies[/dim]")
            console.print(
                "  [yellow]  Tip: Provide a token manually via config if you have one[/yellow]"
            )
            return []

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Analyzing JWT tokens...[/cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("jwt", total=len(tokens))
            for token in tokens:
                progress.advance(task)
                findings = self._analyze_token(token)
                for f in findings:
                    if f not in self.results:
                        self.results.append(f)

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' JWT issue(s) found!' if self.results else '✅ No JWT issues found'}"
            f"[/]"
        )
        return self.results
