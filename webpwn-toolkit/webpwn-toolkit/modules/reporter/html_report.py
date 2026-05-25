#!/usr/bin/env python3
"""
HTML Report Generator
----------------------
Generates professional penetration testing reports:
  • Executive Summary
  • Vulnerability table with CVSS scores
  • Detailed findings per module
  • Remediation recommendations
  • Risk heat-map
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List
from jinja2 import Environment
from rich.console import Console

console = Console()

# Optional PDF support — uses reportlab (no system libs needed on Windows)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        HRFlowable,
    )

    _PDF_AVAILABLE = True
except ImportError:
    _PDF_AVAILABLE = False

REPORTS_DIR = Path(__file__).parents[2] / "reports"

# ── HTML Template ──────────────────────────────────────────────────────────────
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>WebPwn Report — {{ target }}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg:        #0d1117;
    --surface:   #161b22;
    --surface2:  #21262d;
    --border:    #30363d;
    --text:      #e6edf3;
    --muted:     #8b949e;
    --accent:    #58a6ff;
    --critical:  #ff4444;
    --high:      #ff8c00;
    --medium:    #f0c040;
    --low:       #58a6ff;
    --info:      #3fb950;
    --success:   #3fb950;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    font-size: 14px;
  }

  /* ── Header ── */
  .header {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1c2128 100%);
    border-bottom: 1px solid var(--border);
    padding: 40px 60px;
    position: relative;
    overflow: hidden;
  }
  .header::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at 20% 50%, rgba(88,166,255,0.08) 0%, transparent 60%);
  }
  .header-badge {
    display: inline-block;
    background: rgba(88,166,255,0.1);
    border: 1px solid rgba(88,166,255,0.3);
    color: var(--accent);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 16px;
  }
  .header h1 {
    font-size: 32px;
    font-weight: 700;
    background: linear-gradient(90deg, #e6edf3, #58a6ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 8px;
  }
  .header-meta {
    color: var(--muted);
    font-size: 13px;
    display: flex; gap: 24px; flex-wrap: wrap;
    margin-top: 16px;
  }
  .header-meta span { display: flex; align-items: center; gap: 6px; }

  /* ── Layout ── */
  .container { max-width: 1200px; margin: 0 auto; padding: 40px 60px; }

  /* ── Section ── */
  .section { margin-bottom: 40px; }
  .section-title {
    font-size: 20px; font-weight: 600;
    color: var(--text);
    border-left: 3px solid var(--accent);
    padding-left: 12px;
    margin-bottom: 20px;
  }

  /* ── Risk cards ── */
  .risk-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 32px;
  }
  .risk-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s;
  }
  .risk-card:hover { transform: translateY(-2px); }
  .risk-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 3px;
  }
  .risk-card.critical::before { background: var(--critical); }
  .risk-card.high::before     { background: var(--high); }
  .risk-card.medium::before   { background: var(--medium); }
  .risk-card.low::before      { background: var(--low); }
  .risk-card.info::before     { background: var(--info); }

  .risk-count {
    font-size: 36px; font-weight: 700; line-height: 1;
    margin-bottom: 6px;
  }
  .risk-card.critical .risk-count { color: var(--critical); }
  .risk-card.high .risk-count     { color: var(--high); }
  .risk-card.medium .risk-count   { color: var(--medium); }
  .risk-card.low .risk-count      { color: var(--low); }
  .risk-card.info .risk-count     { color: var(--info); }
  .risk-label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }

  /* ── Table ── */
  .table-wrap { overflow-x: auto; border-radius: 12px; border: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; }
  thead { background: var(--surface2); }
  th {
    padding: 12px 16px; text-align: left;
    font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--muted); font-weight: 600;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    font-size: 13px;
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(88,166,255,0.04); }

  /* ── Severity badge ── */
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .badge-critical { background: rgba(255,68,68,0.15);  color: #ff6b6b; border: 1px solid rgba(255,68,68,0.3); }
  .badge-high     { background: rgba(255,140,0,0.15);  color: #ffaa44; border: 1px solid rgba(255,140,0,0.3); }
  .badge-medium   { background: rgba(240,192,64,0.15); color: #f0c040; border: 1px solid rgba(240,192,64,0.3); }
  .badge-low      { background: rgba(88,166,255,0.15); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }
  .badge-info     { background: rgba(63,185,80,0.15);  color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }

  /* ── Finding card ── */
  .finding-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 16px;
    overflow: hidden;
  }
  .finding-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    cursor: pointer;
  }
  .finding-title { font-weight: 600; font-size: 14px; }
  .finding-body  { padding: 20px; }

  .detail-grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 8px 16px;
    font-size: 13px;
  }
  .detail-label { color: var(--muted); font-weight: 500; }
  .detail-value { color: var(--text); word-break: break-all; }

  .code-block {
    background: #0d1117;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #a5d6ff;
    word-break: break-all;
    margin-top: 4px;
  }

  .remediation-box {
    background: rgba(63,185,80,0.06);
    border: 1px solid rgba(63,185,80,0.2);
    border-radius: 8px;
    padding: 12px 16px;
    margin-top: 12px;
    font-size: 13px;
    color: #7ee787;
  }
  .remediation-box strong { display: block; margin-bottom: 4px; color: #3fb950; }

  /* ── CVSS bar ── */
  .cvss-bar-wrap { width: 100%; height: 6px; background: var(--border); border-radius: 3px; margin-top: 6px; }
  .cvss-bar { height: 100%; border-radius: 3px; transition: width 0.5s ease; }

  /* ── Footer ── */
  footer {
    text-align: center;
    padding: 32px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 40px;
  }

  /* ── Executive summary box ── */
  .exec-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 32px;
  }
  .exec-box p { color: var(--muted); margin-bottom: 12px; }
  .exec-box p:last-child { margin-bottom: 0; }

  .module-tag {
    display: inline-block;
    background: rgba(88,166,255,0.1);
    color: var(--accent);
    border: 1px solid rgba(88,166,255,0.2);
    padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-family: 'JetBrains Mono', monospace;
  }

  @media (max-width: 768px) {
    .container { padding: 20px; }
    .header    { padding: 24px 20px; }
    .risk-grid { grid-template-columns: repeat(3, 1fr); }
    .detail-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<!-- ── HEADER ── -->
<div class="header">
  <div class="header-badge">🔐 Penetration Test Report</div>
  <h1>WebPwn Security Assessment</h1>
  <div class="header-meta">
    <span>🎯 <strong>{{ target }}</strong></span>
    <span>📅 {{ date }}</span>
    <span>⏱ Session: {{ session_name }}</span>
    <span>🔧 WebPwn Toolkit v1.0</span>
    <span>🎓 Holberton IT School</span>
  </div>
</div>

<div class="container">

  <!-- ── EXECUTIVE SUMMARY ── -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="exec-box">
      <p>
        This report presents the results of an automated web and mobile security assessment
        conducted against <strong>{{ target }}</strong> using <strong>WebPwn Toolkit v1.0</strong>.
        The assessment covers OWASP Top 10 (2021) vulnerability categories including
        injection attacks, broken access control, security misconfigurations, and more.
      </p>
      <p>
        A total of <strong>{{ total_findings }}</strong> security findings were identified across
        <strong>{{ modules_tested }}</strong> test module(s). Of these,
        <strong style="color:var(--critical)">{{ severity_counts.critical }}</strong> are Critical,
        <strong style="color:var(--high)">{{ severity_counts.high }}</strong> are High,
        <strong style="color:var(--medium)">{{ severity_counts.medium }}</strong> are Medium,
        <strong style="color:var(--low)">{{ severity_counts.low }}</strong> are Low, and
        <strong style="color:var(--info)">{{ severity_counts.info }}</strong> are Informational.
      </p>
      <p>
        <strong>Risk Rating: </strong>
        {% if severity_counts.critical > 0 %}
          <span class="badge badge-critical">CRITICAL</span>
        {% elif severity_counts.high > 0 %}
          <span class="badge badge-high">HIGH</span>
        {% elif severity_counts.medium > 0 %}
          <span class="badge badge-medium">MEDIUM</span>
        {% else %}
          <span class="badge badge-low">LOW / ACCEPTABLE</span>
        {% endif %}
      </p>
    </div>
  </div>

  <!-- ── RISK OVERVIEW ── -->
  <div class="section">
    <div class="section-title">Risk Overview</div>
    <div class="risk-grid">
      {% for sev in ['critical','high','medium','low','info'] %}
      <div class="risk-card {{ sev }}">
        <div class="risk-count">{{ severity_counts[sev] }}</div>
        <div class="risk-label">{{ sev }}</div>
      </div>
      {% endfor %}
    </div>
  </div>

  <!-- ── FINDINGS TABLE ── -->
  <div class="section">
    <div class="section-title">Findings Summary ({{ total_findings }} total)</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Severity</th>
            <th>Type</th>
            <th>Location</th>
            <th>CVSS</th>
            <th>OWASP</th>
            <th>Module</th>
          </tr>
        </thead>
        <tbody>
          {% for idx, f in findings_flat %}
          <tr>
            <td>{{ idx }}</td>
            <td>
              <span class="badge badge-{{ f.severity }}">{{ f.severity|upper }}</span>
            </td>
            <td>{{ f.data.get('type', f.module) }}</td>
            <td style="max-width:220px; word-break:break-all; font-size:12px; font-family:'JetBrains Mono',monospace;">
              {{ f.data.get('url', f.data.get('location', '-'))[:60] }}
            </td>
            <td>
              {% set cvss = f.data.get('cvss', 0) %}
              {{ "%.1f"|format(cvss) }}
              <div class="cvss-bar-wrap">
                <div class="cvss-bar"
                     style="width:{{ (cvss/10*100)|int }}%;
                            background:{% if cvss >= 9 %}var(--critical)
                                       {% elif cvss >= 7 %}var(--high)
                                       {% elif cvss >= 4 %}var(--medium)
                                       {% else %}var(--low){% endif %};">
                </div>
              </div>
            </td>
            <td style="font-size:11px; color:var(--muted);">{{ f.data.get('owasp', '-') }}</td>
            <td><span class="module-tag">{{ f.module }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── DETAILED FINDINGS ── -->
  <div class="section">
    <div class="section-title">Detailed Findings</div>

    {% for idx, f in findings_flat %}
    <div class="finding-card">
      <div class="finding-header">
        <div>
          <span class="badge badge-{{ f.severity }}" style="margin-right:10px;">{{ f.severity|upper }}</span>
          <span class="finding-title">{{ f.data.get('type', f.module) }}</span>
        </div>
        <span style="font-size:12px; color:var(--muted);">#{{ idx }} | CVSS {{ "%.1f"|format(f.data.get('cvss',0)) }}</span>
      </div>
      <div class="finding-body">
        <div class="detail-grid">
          <span class="detail-label">Location</span>
          <span class="detail-value">
            <div class="code-block">{{ f.data.get('url', f.data.get('location', 'N/A')) }}</div>
          </span>

          <span class="detail-label">Description</span>
          <span class="detail-value">{{ f.data.get('detail', f.data.get('description', '-')) }}</span>

          <span class="detail-label">OWASP</span>
          <span class="detail-value" style="color:var(--accent);">{{ f.data.get('owasp', '-') }}</span>

          <span class="detail-label">Module</span>
          <span class="detail-value"><span class="module-tag">{{ f.module }}</span></span>
        </div>

        <!-- Clickable Technical Details -->
        <div style="margin-top: 15px;">
          
          {% if f.data.get('parameter') or f.data.get('payload') %}
          <details class="report-details" style="margin-bottom: 10px; cursor: pointer;">
            <summary style="font-weight: bold; color: var(--accent);">🔍 View Payload & Parameter</summary>
            <div style="padding: 10px; background: rgba(0,0,0,0.2); border-left: 3px solid var(--accent); margin-top: 8px;">
              {% if f.data.get('parameter') %}<strong>Parameter:</strong> <code>{{ f.data.get('parameter') }}</code><br><br>{% endif %}
              {% if f.data.get('payload') %}<strong>Payload:</strong> <div class="code-block" style="margin-top:5px;">{{ f.data.get('payload') }}</div>{% endif %}
            </div>
          </details>
          {% endif %}

          {% if f.data.get('evidence') %}
          <details class="report-details" style="margin-bottom: 10px; cursor: pointer;">
            <summary style="font-weight: bold; color: var(--accent);">📄 View Evidence / Response</summary>
            <div style="padding: 10px; background: rgba(0,0,0,0.2); border-left: 3px solid var(--high); margin-top: 8px;">
              <div class="code-block">{{ f.data.get('evidence') }}</div>
            </div>
          </details>
          {% endif %}

          <details class="report-details" open style="margin-bottom: 10px; cursor: pointer;">
            <summary style="font-weight: bold; color: var(--high);">⚠️ Senior Pentester Analysis (Impact)</summary>
            <div style="padding: 10px; background: rgba(255,140,0,0.1); border-left: 3px solid var(--high); margin-top: 8px; color: #ffaa44;">
              {{ f.data.get('senior_impact', 'N/A') }}
            </div>
          </details>

          <details class="report-details" open style="cursor: pointer;">
            <summary style="font-weight: bold; color: var(--low);">✅ Strategic Remediation</summary>
            <div class="remediation-box" style="margin-top: 8px;">
              {{ f.data.get('senior_remediation', f.data.get('remediation', 'N/A')) }}
            </div>
          </details>
          
        </div>
      </div>
    </div>
    {% endfor %}
  </div>

  <!-- ── METHODOLOGY ── -->
  <div class="section">
    <div class="section-title">Methodology</div>
    <div class="exec-box">
      <div class="detail-grid">
        <span class="detail-label">Framework</span>
        <span class="detail-value">OWASP Testing Guide v4.2 + OWASP Mobile Security Testing Guide</span>
        <span class="detail-label">Scope</span>
        <span class="detail-value">{{ target }}</span>
        <span class="detail-label">Test Type</span>
        <span class="detail-value">Black-box automated scanning</span>
        <span class="detail-label">Modules Run</span>
        <span class="detail-value">
          {% for mod in modules_run %}
          <span class="module-tag" style="margin-right:4px;">{{ mod }}</span>
          {% endfor %}
        </span>
        <span class="detail-label">Start Time</span>
        <span class="detail-value">{{ start_time }}</span>
        <span class="detail-label">Report Time</span>
        <span class="detail-value">{{ date }}</span>
      </div>
    </div>
  </div>

</div>

<footer>
  Generated by <strong>WebPwn Toolkit v1.0</strong> |
  Holberton IT School — Cyber Security Final Project |
  {{ date }} |
  <em>This report is confidential and for authorized use only.</em>
</footer>

</body>
</html>"""


class ReportGenerator:
    """Professional HTML penetration test report generator."""

    def __init__(self, session: Dict):
        self.session = session
        REPORTS_DIR.mkdir(exist_ok=True)

    def _count_severities(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.session.get("findings", []):
            # Handle nested list findings (Port Scan, Cloud Hunter, etc.)
            data = f.get("data", [])
            if isinstance(data, list) and data:
                for item in data:
                    if isinstance(item, dict):
                        sev = item.get("severity", f.get("severity", "info")).lower()
                        if sev in counts:
                            counts[sev] += 1
            else:
                sev = f.get("severity", "info").lower()
                if sev in counts:
                    counts[sev] += 1
        return counts

    def _get_modules_run(self) -> List[str]:
        """Return a clean list of module names that produced findings."""
        # Named module groups that appeared in the session
        named_mods = set()
        for f in self.session.get("findings", []):
            mod = f.get("module")
            if mod:
                # Only include if the module actually has data
                d = f.get("data")
                if d is None or (isinstance(d, list) and not d):
                    continue  # empty module group — skip
                named_mods.add(mod)
            else:
                # Flat finding — infer a high-level module label
                t = str(f.get("type", ""))
                if t.startswith("CVE"):
                    named_mods.add("CVE Scanner")
                elif "Missing Header" in t:
                    named_mods.add("Header Check")
                elif "Cookie" in t:
                    named_mods.add("Cookie Check")
                elif "WAF" in t:
                    named_mods.add("WAF Check")
                else:
                    named_mods.add("Path Scanner")
        return sorted(list(named_mods))

    # Known third-party tracker / CDN domains that are NOT security findings
    # These appear in page HTML as external resources and cause false positives.
    _THIRD_PARTY_NOISE = {
        "analytics.tiktok.com",
        "px.ads.linkedin.com",
        "www.google-analytics.com",
        "google-analytics.com",
        "www.googletagmanager.com",
        "googletagmanager.com",
        "c.ba.contentsquare.net",
        "t.contentsquare.net",
        "contentsquare.net",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "www.facebook.com",
        "connect.facebook.net",
        "static.hotjar.com",
        "script.hotjar.com",
        "www.youtube.com",
        "youtube.com",
        "snapchat.com",
        "twitter.com",
        "platform.twitter.com",
        "d.clarity.ms",
        "clarity.ms",
    }

    def _is_off_target(self, url: str) -> bool:
        """Returns True if the URL belongs to a known 3rd-party noise domain."""
        if not url or not url.startswith("http"):
            return False
        import re

        m = re.search(r"https?://([^/]+)", url)
        if not m:
            return False
        domain = m.group(1).lower().lstrip("www.")
        for noise in self._THIRD_PARTY_NOISE:
            if domain == noise or domain.endswith("." + noise):
                return True
        return False

    def _normalize_findings(self, findings: list) -> list:
        """
        Normalise the findings list so every entry is a simple dict-backed object
        that the Jinja2 template can access as f.severity, f.module, f.data.

        Handles three JSON shapes:
          1. Flat finding  — {"severity": .., "type": .., "url": .., ...}
          2. Module-group  — {"module": .., "severity": .., "data": {...}}
          3. List-group    — {"module": .., "severity": .., "data": [{...}, ...]}
        """

        # ── OWASP categories inferred from path/url keywords ──────────────────
        OWASP_RULES = [
            (
                [
                    "actuator",
                    "phpinfo",
                    "phpmyadmin",
                    "adminer",
                    "backup",
                    "config",
                    "secret",
                    "env",
                    ".git",
                    "server-status",
                    "admin",
                ],
                "A05:2021 – Security Misconfiguration",
            ),
            (["cve", "cve-"], "A06:2021 – Vulnerable and Outdated Components"),
            (["sqli", "sql injection", "injection"], "A03:2021 – Injection"),
            (["xss", "cross-site"], "A03:2021 – Injection"),
            (["ssrf"], "A10:2021 – SSRF"),
            (
                ["header", "csp", "hsts", "x-frame"],
                "A05:2021 – Security Misconfiguration",
            ),
            (
                ["cookie", "httponly", "samesite"],
                "A05:2021 – Security Misconfiguration",
            ),
            (
                ["s3", "gcp", "azure", "bucket", "blob"],
                "A05:2021 – Security Misconfiguration",
            ),
        ]

        def _infer_owasp(text: str) -> str:
            t = text.lower()
            for keywords, category in OWASP_RULES:
                if isinstance(keywords, list):
                    if any(k in t for k in keywords):
                        return category
                elif keywords in t:
                    return category
            return "A05:2021 – Security Misconfiguration"

        # ── Module name inference for flat/un-grouped findings ────────────────
        def _infer_module(d: dict) -> str:
            if d.get("module"):
                return d["module"]
            t = str(d.get("type", ""))
            if t.startswith("CVE"):
                return "CVE Scanner"
            if "Missing Header" in t:
                return "Header Check"
            if "Cookie" in t:
                return "Cookie Check"
            p = str(d.get("path", d.get("url", "")))
            if any(k in p.lower() for k in ["actuator", "phpmy", "adminer", "backup"]):
                return "AdminHunter"
            return t.split()[0] if t else "Scanner"

        # ── Friendly type label ───────────────────────────────────────────────
        def _infer_type(d: dict, module: str) -> str:
            t = d.get("type", "")
            if t and t != "unknown":
                return t
            # build from path / url
            path = d.get("path") or ""
            url = d.get("url", "")
            if path:
                return f"Exposed Path: /{path}"
            if url:
                return f"Cloud Asset: {url.split('//')[1][:40] if '//' in url else url[:40]}"
            return module

        SENIOR_MAPPING = {
            "CVE": {
                "impact": "Attackers can exploit this known vulnerability (CVE) to execute remote code, read sensitive server files, or hijack user sessions. This puts the entire infrastructure and customer data at critical risk.",
                "remediation": "Immediately apply the official vendor patch for the identified technology. If patching is not immediately possible, apply WAF virtual patching and restrict access to the vulnerable component.",
            },
            "WAF": {
                "impact": "Attackers can bypass the Web Application Firewall using encoded payloads (Hex, Base64, Unicode). This renders the WAF ineffective and exposes the backend to direct injection attacks.",
                "remediation": "Update WAF rulesets to decode and normalize all incoming traffic before signature analysis. Ensure strict input validation on the backend regardless of WAF presence.",
            },
            "Logic": {
                "impact": "Attackers can manipulate the application's state machine (e.g., negative quantities in cart) to steal services, purchase items for free, or cause financial loss to the business.",
                "remediation": "Never trust client-side data. Enforce strict server-side validation for all state transitions, quantities (>0), and prices. Implement robust state-machine logic in backend controllers.",
            },
            "Cookie": {
                "impact": "Missing secure cookie flags allow attackers to steal session tokens via Cross-Site Scripting (XSS) or Man-in-the-Senior (MitM) attacks, leading to complete account takeover.",
                "remediation": "Set 'HttpOnly', 'Secure', and 'SameSite=Strict' attributes on all sensitive cookies. Ensure the application enforces HTTPS strictly.",
            },
            "Header": {
                "impact": "Missing security headers expose users to MIME-sniffing, Clickjacking, and Cross-Site Scripting. It weakens the client-side security posture significantly.",
                "remediation": "Configure the web server to emit standard security headers: Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options: nosniff, and Strict-Transport-Security (HSTS).",
            },
            "actuator": {
                "impact": "Spring Boot Actuator endpoints are publicly accessible. Attackers can leak environment variables, heap dumps, active beans, request mappings, and potentially trigger remote shutdown or restart.",
                "remediation": "Restrict Actuator endpoints behind authentication. In application.properties set: management.endpoints.web.exposure.include=health and add Spring Security to protect /actuator/**.",
            },
            "backup": {
                "impact": "Accessible backup files can expose full database dumps, source code, credentials, and configuration secrets. This is a critical data exposure risk.",
                "remediation": "Remove all backup files from the web root. Store backups in a secure, non-public storage location with access controls.",
            },
            "Cloud": {
                "impact": "Publicly accessible cloud storage buckets (S3/GCP/Azure) can expose sensitive files, customer data, or application assets to unauthorized access or modification.",
                "remediation": "Set bucket/blob ACL to private. Enable bucket versioning and logging. Use signed URLs for authorized access only.",
            },
            "Port": {
                "impact": "Exposed network services increase the attack surface. SSH, HTTP, and non-standard ports can be exploited for brute-force, service fingerprinting, and lateral movement.",
                "remediation": "Restrict port access via firewall rules. Only expose necessary services. Harden SSH with key-based auth and disable root login.",
            },
        }

        class _F:
            __slots__ = ("severity", "module", "data")

            def __init__(self, d: dict):
                self.severity = str(d.get("severity", "info")).lower()
                self.module = _infer_module(d)

                # Build flat data dict
                self.data: dict = {}
                self.data.update(d)
                # Merge dict-type data sub-field
                if isinstance(d.get("data"), dict):
                    self.data.update(d["data"])

                # Fix type field
                self.data["type"] = _infer_type(d, self.module)

                # Fix module field in data
                self.data["module"] = self.module

                # CVE findings: set Location to NVD link so it's never empty/N/A
                cve_id = self.data.get("cve_id", "")
                if cve_id:
                    self.data["url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    tech = self.data.get("technology", "")
                    if tech:
                        self.data["detail"] = (
                            self.data.get("detail")
                            or f"{cve_id} affects {tech} — see NVD for full advisory."
                        )

                # Infer OWASP if missing
                if not self.data.get("owasp"):
                    lookup = (
                        self.data["type"]
                        + " "
                        + str(self.data.get("url", ""))
                        + " "
                        + str(self.data.get("path", ""))
                    )
                    self.data["owasp"] = _infer_owasp(lookup)

                # Auto-generate detail if missing
                if not self.data.get("detail"):
                    if "port" in self.data:
                        self.data["detail"] = (
                            f"Port {self.data.get('port')} is {self.data.get('state', 'open')} "
                            f"({self.data.get('service', 'unknown service')}) — "
                            f"Banner: {self.data.get('banner', 'N/A')}"
                        )
                    elif "subdomain" in self.data:
                        self.data["detail"] = (
                            f"Subdomain discovered: {self.data.get('subdomain')}"
                        )
                    elif "server" in self.data:
                        svr = self.data.get("server", "")
                        svr_str = ", ".join(svr) if isinstance(svr, list) else str(svr)
                        self.data["detail"] = f"Technology detected: {svr_str}"
                    elif "status" in self.data:
                        self.data["detail"] = (
                            f"{self.data.get('type', 'Cloud Asset')} status: "
                            f"{self.data.get('status')} — {self.data.get('url', '')}"
                        )
                    elif "status_code" in self.data:
                        self.data["detail"] = (
                            f"HTTP {self.data.get('status_code')} on /{self.data.get('path', '')} "
                            f"(size: {self.data.get('size', '?')} bytes)"
                        )

                # Last resort: if no url set yet, use session target (so Location is never N/A)
                if not self.data.get("url"):
                    tgt = self.data.get("_session_target", "")
                    dom = self.data.get("_session_domain", "")
                    port = self.data.get("port")
                    if port and dom:
                        # Port Scan: show host:port
                        self.data["url"] = f"{dom}:{port}"
                    elif tgt:
                        self.data["url"] = tgt

                # Assign Senior Impact & Remediation
                t_str = str(self.data.get("type", "")).lower()
                p_str = str(self.data.get("path", "")).lower()
                u_str = str(self.data.get("url", "")).lower()
                combo = f"{t_str} {p_str} {u_str} {self.module.lower()}"

                matched = False
                for k, v in SENIOR_MAPPING.items():
                    if k.lower() in combo:
                        self.data["senior_impact"] = v["impact"]
                        self.data["senior_remediation"] = v["remediation"]
                        matched = True
                        break

                if not matched:
                    if self.severity in ["high", "critical"]:
                        self.data["senior_impact"] = (
                            "High risk of system compromise. Attackers could potentially gain "
                            "unauthorized access, escalate privileges, or extract sensitive data."
                        )
                    else:
                        self.data["senior_impact"] = (
                            "Could aid attackers in reconnaissance or be chained with other "
                            "vulnerabilities to compromise the application."
                        )
                    self.data["senior_remediation"] = self.data.get(
                        "remediation",
                        "Follow security best practices and ensure all inputs are sanitized and dependencies updated.",
                    )

        # ── Expand / flatten all findings into a flat list ───────────────────
        session_target = self.session.get("target", "")
        session_domain = self.session.get("domain", "")
        result = []
        for entry in findings:
            data_field = entry.get("data")
            module_name = entry.get("module", "")

            if isinstance(data_field, list):
                if not data_field:
                    # Genuinely empty module group (e.g. Subdomain Enum with no subdomains)
                    continue
                # Expand each list item as a separate finding
                for item in data_field:
                    if not isinstance(item, dict):
                        continue
                    # ── False Positive Filter: skip off-target 3rd-party URLs ──
                    item_url = item.get("url", "")
                    if self._is_off_target(item_url):
                        console.print(
                            f"  [dim yellow][FP-FILTER] Skipped off-target finding: {item_url[:80]}[/dim yellow]"
                        )
                        continue

                    item_sev = str(
                        item.get("severity", entry.get("severity", "info"))
                    ).lower()
                    merged = {
                        "module": module_name,
                        "severity": item_sev,
                        "_session_target": session_target,
                        "_session_domain": session_domain,
                    }
                    merged.update(item)
                    result.append(_F(merged))

            elif (
                data_field is None
                and not entry.get("url")
                and not entry.get("path")
                and not entry.get("type")
            ):
                # Truly empty entry with nothing useful — skip
                continue

            else:
                # Flat finding (no data wrapper) OR module with dict data
                flat = {
                    "_session_target": session_target,
                    "_session_domain": session_domain,
                }
                flat.update(entry)
                # ── False Positive Filter for flat findings too ──
                if self._is_off_target(flat.get("url", "")):
                    console.print(
                        f"  [dim yellow][FP-FILTER] Skipped off-target: {flat.get('url','')[:80]}[/dim yellow]"
                    )
                    continue
                result.append(_F(flat))

        dedup_result = []
        seen_sig = set()
        for f_obj in result:
            # Create a signature based on type, url, and detail (or description) to deduplicate findings
            sig = (
                str(f_obj.data.get("type", "")),
                str(f_obj.data.get("url", "")),
                str(f_obj.data.get("detail", f_obj.data.get("description", ""))),
            )
            if sig not in seen_sig:
                seen_sig.add(sig)
                dedup_result.append(f_obj)

        return dedup_result

    def generate(self, report_name: str) -> str:
        raw_findings = self.session.get("findings", [])
        findings = self._normalize_findings(raw_findings)

        # Sort findings by severity (critical -> high -> medium -> low -> info)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity, 5))

        sev_counts = self._count_severities()
        modules_run = self._get_modules_run()
        findings_flat = list(enumerate(findings, start=1))

        context = {
            "target": self.session.get("target", "Unknown"),
            "session_name": self.session.get("name", "N/A"),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "start_time": self.session.get("start_time", "N/A"),
            "total_findings": len(findings),
            "modules_tested": len(modules_run),
            "modules_run": modules_run,
            "severity_counts": sev_counts,
            "findings_flat": findings_flat,
        }

        # Render with autoescape=True to prevent XSS payloads from executing
        env = Environment(autoescape=True)
        template = env.from_string(REPORT_TEMPLATE)
        html = template.render(**context)
        out_path = REPORTS_DIR / f"{report_name}.html"

        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        # PDF export using reportlab (Windows-compatible)
        if _PDF_AVAILABLE:
            try:
                pdf_path = REPORTS_DIR / f"{report_name}.pdf"
                self._generate_pdf(pdf_path, findings)
                console.print(f"  [dim]-> PDF report: {pdf_path}[/dim]")
            except Exception as pdf_err:
                console.print(f"  [yellow]PDF generation failed: {pdf_err}[/yellow]")
        else:
            console.print(
                "  [dim]PDF export unavailable — install reportlab: "
                "pip install reportlab[/dim]"
            )

        return str(out_path)

    def _generate_pdf(self, pdf_path: Path, findings: list) -> None:
        """Generate a detailed, Senior Pentester level PDF report matching admiu standard."""
        SEV_COLORS = {
            "critical": colors.HexColor("#d73a4a"),
            "high": colors.HexColor("#ff8c00"),
            "medium": colors.HexColor("#f0c040"),
            "low": colors.HexColor("#0366d6"),
            "info": colors.HexColor("#28a745"),
        }

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=A4,
            rightMargin=1.5 * cm,
            leftMargin=1.5 * cm,
            topMargin=1.5 * cm,
            bottomMargin=1.5 * cm,
        )
        styles = getSampleStyleSheet()
        story = []

        # Styles
        title_style = ParagraphStyle(
            "Title",
            parent=styles["Title"],
            fontSize=24,
            spaceAfter=8,
            textColor=colors.HexColor("#1a1a2e"),
        )
        h1_style = ParagraphStyle(
            "H1",
            parent=styles["Heading1"],
            fontSize=16,
            spaceBefore=18,
            spaceAfter=10,
            textColor=colors.HexColor("#24292e"),
        )
        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=13,
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.HexColor("#24292e"),
        )
        body_style = ParagraphStyle(
            "Body", parent=styles["Normal"], fontSize=10, spaceAfter=6, leading=14
        )
        impact_style = ParagraphStyle(
            "Impact",
            parent=body_style,
            textColor=colors.HexColor("#b35900"),
            leftIndent=10,
        )
        remediation_style = ParagraphStyle(
            "Rem",
            parent=body_style,
            textColor=colors.HexColor("#005cc5"),
            leftIndent=10,
        )

        target = self.session.get("target", "Unknown")
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        sev_counts = self._count_severities()

        story.append(Paragraph("WebPwn Advanced Pentest Report", title_style))
        story.append(Paragraph(f"<b>Target:</b> {target}", body_style))
        story.append(
            Paragraph(
                f"<b>Date:</b> {date_str} | Generated by WebPwn Senior Pentest Module",
                body_style,
            )
        )
        story.append(
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e1e4e8"))
        )
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Executive Summary", h1_style))
        story.append(
            Paragraph(
                f"This report presents the findings of an advanced automated security assessment against {target}. The assessment utilized senior-level heuristics to identify critical vulnerabilities across OWASP Top 10 categories. A total of {len(findings)} security findings were recorded.",
                body_style,
            )
        )

        # Risk Table
        risk_data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev_counts[sev] > 0:
                risk_data.append([sev.upper(), str(sev_counts[sev])])

        risk_tbl = Table(risk_data, colWidths=[5 * cm, 5 * cm])
        risk_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#24292e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e1e4e8")),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(risk_tbl)
        story.append(Spacer(1, 1 * cm))

        story.append(Paragraph("Detailed Security Findings", h1_style))

        for idx, f in enumerate(findings, start=1):
            sev = f.severity
            c = SEV_COLORS.get(sev, colors.grey)

            # Title
            story.append(
                Paragraph(
                    f"<b>#{idx} [{sev.upper()}] {f.data.get('type', f.module)}</b>",
                    ParagraphStyle("FT", parent=h2_style, textColor=c),
                )
            )

            # CVSS & Location
            loc = str(f.data.get("url", f.data.get("location", "N/A")))[:80]
            cvss = f.data.get("cvss", "N/A")
            cve = f.data.get("cve_id", "")

            details = f"<b>Location:</b> {loc}<br/><b>CVSS Score:</b> {cvss}"
            if cve:
                details += f" | <b>CVE:</b> {cve} (See NVD for details)"
            story.append(Paragraph(details, body_style))

            # Technical Details
            desc = (
                str(f.data.get("detail", f.data.get("description", "-")))[:300]
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            story.append(Paragraph(f"<b>Technical Details:</b> {desc}", body_style))

            # Senior Impact — use ASCII-safe text for ReportLab
            impact = (
                f.data.get("senior_impact", "N/A")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            story.append(
                Paragraph("<b>[!] Attacker Impact / Scenario:</b>", body_style)
            )
            story.append(Paragraph(impact, impact_style))

            # Remediation
            rem = (
                f.data.get("senior_remediation", f.data.get("remediation", "N/A"))
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            story.append(Paragraph("<b>[+] Strategic Remediation:</b>", body_style))
            story.append(Paragraph(rem, remediation_style))

            story.append(Spacer(1, 0.3 * cm))
            story.append(
                HRFlowable(
                    width="100%", thickness=0.5, color=colors.HexColor("#eaecef")
                )
            )
            story.append(Spacer(1, 0.3 * cm))

        doc.build(story)
