#!/usr/bin/env python3
"""
Technology Detector Module
---------------------------
• HTTP headers analysis
• HTML meta tag parsing
• CMS / framework fingerprinting
• JavaScript library detection
• Security header audit
"""

import re
import requests
from bs4 import BeautifulSoup
from typing import Dict, List
from rich.console import Console

console = Console()


# ── Signature databases ────────────────────────────────────────────────────────

CMS_SIGNATURES: Dict[str, List[str]] = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Joomla": ["joomla", "/components/com_", "Joomla!"],
    "Drupal": ["Drupal", "drupal.org", "/sites/default/files/"],
    "Magento": ["Mage.Cookies", "magento", "/skin/frontend/"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Ghost": ["ghost.io", "ghost-url"],
    "Wix": ["wix.com", "_wixCssIds"],
    "Squarespace": ["squarespace.com", "static.squarespace.com"],
    "OpenCart": ["route=common/home", "opencart"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrfSenior waretoken", "django"],
    "Rails": ["_rails_session", "ruby-on-rails"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js": ["__nuxt", "__NUXT__"],
    "React": ["react-root", "__reactFiber"],
    "Angular": ["ng-version", "angular.js"],
    "Vue.js": ["__vue__", "data-v-"],
}

JS_SIGNATURES: Dict[str, str] = {
    "jQuery": r"jquery[.-](\d+\.\d+\.?\d*)",
    "Bootstrap": r"bootstrap[.-](\d+\.\d+\.?\d*)",
    "React": r"react[.-](\d+\.\d+\.?\d*)",
    "Angular": r"angular[.-](\d+\.\d+\.?\d*)",
    "Vue.js": r"vue[.-](\d+\.\d+\.?\d*)",
    "Lodash": r"lodash[.-](\d+\.\d+\.?\d*)",
    "Moment.js": r"moment[.-](\d+\.\d+\.?\d*)",
    "Axios": r"axios[.-](\d+\.\d+\.?\d*)",
    "Font Awesome": r"font-awesome[.-](\d+\.\d+\.?\d*)",
    "Tailwind CSS": r"tailwindcss[.-](\d+\.\d+\.?\d*)",
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against MITM / protocol downgrade",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Content-Security-Policy": "Mitigates XSS & data injection",
    "X-XSS-Protection": "Old-browser XSS filter",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts browser feature access",
}

SERVER_SIGNATURES: Dict[str, str] = {
    "Apache": r"Apache/?([\d.]*)",
    "Nginx": r"nginx/?([\d.]*)",
    "IIS": r"Microsoft-IIS/?([\d.]*)",
    "Tomcat": r"Apache Tomcat/?([\d.]*)",
    "Caddy": r"Caddy",
    "Lighttpd": r"lighttpd/?([\d.]*)",
}


class TechDetector:
    """Fingerprint technologies used by a web target."""

    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout
        self.headers_map: Dict[str, str] = {}
        self.html: str = ""

    # ── HTTP fetch ─────────────────────────────────────────────────────

    def _fetch(self) -> bool:
        try:
            resp = requests.get(
                self.url,
                timeout=self.timeout,
                headers={"User-Agent": "WebPwnToolkit/1.0"},
                verify=False,
                allow_redirects=True,
            )
            self.headers_map = dict(resp.headers)
            self.html = resp.text
            self.status_code = resp.status_code
            return True
        except Exception as e:
            console.print(f"  [red]Fetch error: {e}[/red]")
            return False

    # ── Detection methods ──────────────────────────────────────────────

    def _detect_server(self) -> List[str]:
        server_header = self.headers_map.get("Server", "")
        x_powered = self.headers_map.get("X-Powered-By", "")
        found = []
        for name, pattern in SERVER_SIGNATURES.items():
            for val in (server_header, x_powered):
                m = re.search(pattern, val, re.I)
                if m:
                    ver = m.group(1) if m.lastindex else ""
                    found.append(f"{name} {ver}".strip())
        return list(set(found))

    def _detect_cms(self) -> List[str]:
        combined = self.html.lower() + " ".join(self.headers_map.values()).lower()
        found = []
        for cms, sigs in CMS_SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                found.append(cms)
        return found

    def _detect_js_libs(self) -> List[str]:
        found = []
        scripts = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', self.html, re.I)
        combined = " ".join(scripts) + self.html
        for lib, pattern in JS_SIGNATURES.items():
            m = re.search(pattern, combined, re.I)
            if m:
                ver = m.group(1) if m.lastindex else ""
                found.append(f"{lib} {ver}".strip())
        return list(set(found))

    def _audit_security_headers(self) -> Dict[str, str]:
        present = {}
        missing = {}
        for hdr, desc in SECURITY_HEADERS.items():
            if hdr in self.headers_map:
                present[hdr] = f"✅ {self.headers_map[hdr][:60]}"
            else:
                missing[hdr] = f"❌ MISSING — {desc}"
        return {**present, **missing}

    def _detect_cookies(self) -> List[str]:
        issues = []
        cookies = self.headers_map.get("Set-Cookie", "")
        if cookies:
            if "HttpOnly" not in cookies:
                issues.append("Cookie missing HttpOnly flag")
            if "Secure" not in cookies:
                issues.append("Cookie missing Secure flag")
            if "SameSite" not in cookies:
                issues.append("Cookie missing SameSite attribute")
        return issues

    def _detect_meta(self) -> Dict[str, str]:
        soup = BeautifulSoup(self.html, "lxml")
        meta = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name", tag.get("property", "")).lower()
            content = tag.get("content", "")
            if name and content:
                meta[name] = content[:120]
        return meta

    # ── Public run ─────────────────────────────────────────────────────

    def run(self) -> Dict:
        if not self._fetch():
            return {"error": "Could not reach target"}

        result = {
            "url": self.url,
            "status_code": self.status_code,
            "server": self._detect_server() or ["Not disclosed"],
            "cms_frameworks": self._detect_cms() or ["None detected"],
            "javascript_libs": self._detect_js_libs() or ["None detected"],
            "security_headers": self._audit_security_headers(),
            "cookie_issues": self._detect_cookies() or ["None detected"],
            "raw_headers": {
                k: v
                for k, v in self.headers_map.items()
                if k.lower() not in ("set-cookie",)
            },
        }

        missing_count = sum(
            1 for v in result["security_headers"].values() if "MISSING" in v
        )
        if missing_count > 0:
            console.print(
                f"  [yellow]⚠  {missing_count} security header(s) missing[/yellow]"
            )

        return result
