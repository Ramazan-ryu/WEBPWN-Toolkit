#!/usr/bin/env python3
"""
APK Static Analyzer
--------------------
Analyzes Android APK files for:
  • Hardcoded secrets (API keys, passwords, tokens)
  • Dangerous permissions
  • Exported components (Activities, Services, Receivers)
  • Insecure configurations (debuggable, allowBackup)
  • Insecure network config
  • Embedded URLs / endpoints
"""

import re
import os
import string
import zipfile
import tempfile
import shutil
import requests
from pathlib import Path
from typing import List, Dict, Optional
from xml.etree import ElementTree as ET
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ── Signature patterns ─────────────────────────────────────────────────────────

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey).{0,10}['\"][A-Za-z0-9_\\-]{20,}['\"]",
    "Private Key Header": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Password in code": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    "Bearer Token": r"(?i)bearer\s+[A-Za-z0-9_\\-\\.]{20,}",
    "Basic Auth": r"(?i)basic\s+[A-Za-z0-9+/=]{10,}",
    "Stripe Key": r"sk_(test|live)_[0-9a-zA-Z]{24,}",
    "Twilio SID": r"AC[0-9a-fA-F]{32}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "IP Address (internal)": r"(?:10|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}",
    "URL with credentials": r"https?://[^:]+:[^@]+@[^/\s]+",
}

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": ("high", "Can read all SMS messages"),
    "android.permission.SEND_SMS": (
        "high",
        "Can send SMS (potential premium SMS fraud)",
    ),
    "android.permission.RECEIVE_SMS": ("medium", "Can intercept incoming SMS"),
    "android.permission.READ_CONTACTS": ("medium", "Access to all contacts"),
    "android.permission.READ_CALL_LOG": ("medium", "Access to call history"),
    "android.permission.RECORD_AUDIO": ("high", "Can record microphone"),
    "android.permission.ACCESS_FINE_LOCATION": (
        "medium",
        "Precise GPS location access",
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        "high",
        "Background location tracking",
    ),
    "android.permission.CAMERA": ("medium", "Camera access"),
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "Read all files on storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "Write files to storage"),
    "android.permission.PROCESS_OUTGOING_CALLS": (
        "high",
        "Can intercept outgoing calls",
    ),
    "android.permission.READ_PHONE_STATE": (
        "medium",
        "Access device ID and call state",
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("low", "Auto-start at device boot"),
    "android.permission.INSTALL_PACKAGES": (
        "critical",
        "Can install arbitrary packages",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "high",
        "Can prompt to install packages",
    ),
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": ("high", "Filesystem mount access"),
    "android.permission.CHANGE_WIFI_STATE": ("low", "Can change Wi-Fi settings"),
    "android.permission.BLUETOOTH_ADMIN": ("low", "Bluetooth admin access"),
    "android.permission.USE_BIOMETRIC": ("medium", "Biometric sensor access"),
}

INSECURE_NET_PATTERNS = [
    (r"http://", "Plain HTTP endpoint", "medium"),
    (r"allowCleartext\s*=\s*['\"]?true", "Cleartext traffic allowed", "high"),
    (
        r"cleartextTrafficPermitted\s*=\s*['\"]?true",
        "Cleartext traffic permitted globally",
        "high",
    ),
    (
        r"android:usesCleartextTraffic\s*=\s*['\"]?true",
        "Cleartext traffic flag set",
        "high",
    ),
    (r"SSLContext\.getInstance\(['\"]SSL['\"]", "Outdated SSL protocol used", "high"),
    (
        r"TrustAllX509TrustManager|ALLOW_ALL_HOSTNAME_VERIFIER",
        "SSL certificate validation disabled",
        "critical",
    ),
    (r"setHostnameVerifier\(ALLOW_ALL", "Hostname verification disabled", "critical"),
]


class APKAnalyzer:
    """Android APK static security analyzer."""

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.work_dir: Optional[Path] = None
        self.results: List[Dict] = []

    # ── Extract APK ────────────────────────────────────────────────────

    def _extract(self) -> bool:
        try:
            self.work_dir = Path(tempfile.mkdtemp(prefix="webpwn_apk_"))
            with zipfile.ZipFile(self.apk_path, "r") as z:
                z.extractall(self.work_dir)
            console.print(f"  [dim]-> Extracted to {self.work_dir}[/dim]")
            return True
        except Exception as e:
            console.print(f"  [red]APK extraction failed: {e}[/red]")
            return False

    def _cleanup(self) -> None:
        if self.work_dir and self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)

    # ── Manifest analysis ──────────────────────────────────────────────

    def _analyze_manifest(self) -> List[Dict]:
        findings = []
        manifest_path = self.work_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return findings

        try:
            raw = manifest_path.read_bytes()
            # Try parsing as text (works for decoded manifests)
            try:
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                ns = "http://schemas.android.com/apk/res/android"

                app = root.find("application")
                if app is not None:
                    # Debuggable
                    if app.get(f"{{{ns}}}debuggable", "false").lower() == "true":
                        findings.append(
                            {
                                "type": "Debuggable APK",
                                "severity": "high",
                                "detail": "android:debuggable=true — allows runtime debugging of the app",
                                "evidence": "AndroidManifest.xml: android:debuggable=true",
                                "owasp": "M7: Client Code Quality",
                                "cvss": 7.4,
                                "remediation": "Set android:debuggable=false in production builds.",
                            }
                        )

                    # allowBackup
                    if app.get(f"{{{ns}}}allowBackup", "true").lower() == "true":
                        findings.append(
                            {
                                "type": "Backup Allowed",
                                "severity": "medium",
                                "detail": "android:allowBackup=true — app data can be extracted via ADB backup",
                                "evidence": "AndroidManifest.xml: android:allowBackup=true",
                                "owasp": "M2: Insecure Data Storage",
                                "cvss": 5.5,
                                "remediation": "Set android:allowBackup=false to prevent data extraction.",
                            }
                        )

                    # Exported components
                    for tag in ("activity", "service", "receiver", "provider"):
                        for comp in root.iter(tag):
                            exported = comp.get(f"{{{ns}}}exported", None)
                            name = comp.get(f"{{{ns}}}name", "unknown")
                            intent = comp.find("intent-filter")
                            # Component is exported if explicitly true or has intent-filter
                            if exported == "true" or (
                                exported is None and intent is not None
                            ):
                                findings.append(
                                    {
                                        "type": f"Exported {tag.capitalize()}",
                                        "severity": "medium",
                                        "detail": f"{tag}: {name} is exported — accessible by other apps",
                                        "evidence": f"<{tag} android:name={name} android:exported=true>",
                                        "owasp": "M1: Improper Platform Usage",
                                        "cvss": 6.5,
                                        "remediation": (
                                            f"Set android:exported=false unless intentionally public. "
                                            f"Add permission checks to {name}."
                                        ),
                                    }
                                )

                # Permissions
                for perm in root.iter("uses-permission"):
                    perm_name = perm.get(f"{{{ns}}}name", "")
                    if perm_name in DANGEROUS_PERMISSIONS:
                        sev, desc = DANGEROUS_PERMISSIONS[perm_name]
                        findings.append(
                            {
                                "type": "Dangerous Permission",
                                "severity": sev,
                                "detail": f"{perm_name}: {desc}",
                                "evidence": f'<uses-permission android:name="{perm_name}"/>',
                                "owasp": "M1: Improper Platform Usage",
                                "cvss": {
                                    "critical": 9.0,
                                    "high": 7.5,
                                    "medium": 5.5,
                                    "low": 3.0,
                                }.get(sev, 5.0),
                                "remediation": f"Remove permission '{perm_name}' if not strictly needed.",
                            }
                        )

            except ET.ParseError:
                # Binary manifest — fall back to string search
                raw_str = str(raw)
                if "debuggable" in raw_str:
                    findings.append(
                        {
                            "type": "Possible Debuggable Flag",
                            "severity": "medium",
                            "detail": "Debuggable attribute detected in binary manifest",
                            "evidence": "Binary AndroidManifest.xml",
                            "owasp": "M7: Client Code Quality",
                            "cvss": 5.0,
                            "remediation": "Decompile with apktool and verify android:debuggable=false",
                        }
                    )

        except Exception as e:
            console.print(f"  [yellow]Manifest parse warning: {e}[/yellow]")

        return findings

    # ── Secret scanning & Advanced Static checks ───────────────────────

    def _extract_strings_from_binary(self, filepath: Path) -> str:
        """Extract printable ASCII strings from binary files (e.g., .dex, .so)."""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            # Find sequences of 4+ printable characters
            chars = r"A-Za-z0-9/\-:.,_=@"
            pattern = re.compile(b"[%s]{4,}" % chars.encode())
            strings = pattern.findall(data)
            return "\n".join(s.decode("ascii", errors="ignore") for s in strings)
        except Exception:
            return ""

    def _scan_secrets(self) -> List[Dict]:
        findings = []
        text_exts = {
            ".java",
            ".kt",
            ".xml",
            ".json",
            ".properties",
            ".yaml",
            ".yml",
            ".txt",
            ".smali",
            ".gradle",
            ".py",
            ".js",
        }
        bin_exts = {".dex"}

        file_count = 0
        firebase_urls = set()

        for fpath in self.work_dir.rglob("*"):
            if not fpath.is_file():
                continue

            content = ""
            if fpath.suffix.lower() in text_exts and fpath.stat().st_size <= 500_000:
                try:
                    content = fpath.read_text(errors="ignore")
                except Exception:
                    pass
            elif fpath.suffix.lower() in bin_exts:
                content = self._extract_strings_from_binary(fpath)

            if not content:
                continue

            # Check for Secrets
            for secret_type, pattern in SECRET_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    val = match.group(0)[:80]
                    if "firebaseio.com" in val.lower():
                        firebase_urls.add(val)

                    finding = {
                        "type": f"Hardcoded Secret: {secret_type}",
                        "severity": (
                            "critical"
                            if "key" in secret_type.lower()
                            or "private" in secret_type.lower()
                            or "password" in secret_type.lower()
                            else "high"
                        ),
                        "detail": f"{secret_type} found in {fpath.relative_to(self.work_dir)}",
                        "evidence": val,
                        "owasp": "M9: Reverse Engineering / M2: Insecure Data Storage",
                        "cvss": 9.0,
                        "remediation": (
                            "Never hardcode secrets in source code. "
                            "Use environment variables, secure key management (e.g., Android Keystore), "
                            "or remote config."
                        ),
                    }
                    if finding not in findings:
                        findings.append(finding)

            # Check for Insecure WebView configurations
            webview_patterns = [
                (
                    r"setJavaScriptEnabled\s*\(\s*true\s*\)",
                    "WebView JavaScript Enabled",
                    "medium",
                ),
                (
                    r"addJavascriptInterface\s*\(",
                    "WebView Javascript Interface Exposed",
                    "high",
                ),
                (
                    r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)",
                    "WebView Debugging Enabled",
                    "high",
                ),
            ]
            for pat, title, sev in webview_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    finding = {
                        "type": title,
                        "severity": sev,
                        "detail": f"{title} found in {fpath.relative_to(self.work_dir)}",
                        "evidence": "Pattern matched: " + pat,
                        "owasp": "M7: Client Code Quality",
                        "cvss": {"high": 7.4, "medium": 5.3}.get(sev, 5.0),
                        "remediation": "Disable JavaScript in WebView if not strictly required. Remove addJavascriptInterface if supporting OS < 4.2.",
                    }
                    if finding not in findings:
                        findings.append(finding)

            file_count += 1

        console.print(
            f"  [dim]-> Scanned {file_count} files (including .dex) for secrets and WebViews[/dim]"
        )

        # Active check: Are Firebase databases publicly readable?
        for f_url in firebase_urls:
            try:
                db_url = f_url.rstrip("/") + "/.json"
                r = requests.get(db_url, timeout=10, verify=False)
                if r.status_code == 200:
                    findings.append(
                        {
                            "type": "Publicly Readable Firebase DB",
                            "severity": "critical",
                            "detail": f"Firebase database {f_url} allows unauthenticated read access!",
                            "evidence": f"HTTP 200 on {db_url} | Data: {str(r.text)[:80]}",
                            "owasp": "M2: Insecure Data Storage",
                            "cvss": 9.8,
                            "remediation": 'Update Firebase security rules to require authentication (.read = "auth != null").',
                        }
                    )
            except Exception:
                pass

        return findings

    # ── Network config scan ────────────────────────────────────────────

    def _scan_network_config(self) -> List[Dict]:
        findings = []
        for fpath in self.work_dir.rglob("*.xml"):
            try:
                content = fpath.read_text(errors="ignore")
                for pattern, description, severity in INSECURE_NET_PATTERNS:
                    matches = re.findall(pattern, content, re.I)
                    if matches:
                        findings.append(
                            {
                                "type": "Insecure Network Configuration",
                                "severity": severity,
                                "detail": f"{description} in {fpath.name}",
                                "evidence": matches[0][:80],
                                "owasp": "M3: Insecure Communication",
                                "cvss": {
                                    "critical": 9.1,
                                    "high": 7.4,
                                    "medium": 5.3,
                                }.get(severity, 5.0),
                                "remediation": (
                                    "Use HTTPS for all network connections. "
                                    "Implement Certificate Pinning. "
                                    "Set cleartextTrafficPermitted=false."
                                ),
                            }
                        )
            except Exception:
                pass
        return findings

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        console.print(
            f"  [dim]-> APK: {self.apk_path.name} ({self.apk_path.stat().st_size // 1024} KB)[/dim]"
        )

        if not self._extract():
            return []

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Analyzing APK...[/cyan]"),
                console=console,
            ) as progress:
                progress.add_task("apk", total=None)

                self.results.extend(self._analyze_manifest())
                self.results.extend(self._scan_secrets())
                self.results.extend(self._scan_network_config())

        finally:
            self._cleanup()

        console.print(
            f"  [{'red' if self.results else 'green'}]"
            f"{'⚠ ' + str(len(self.results)) + ' APK finding(s)!' if self.results else '✅ No major issues found'}"
            f"[/]"
        )
        return self.results
