# WebPwn Toolkit — Professional Audit & Operational Handbook

Generated: May 25, 2026

## Executive Summary

This document is a detailed, operational-ready handbook for the WebPwn Toolkit. It contains: a concise technical audit of recent fixes, exact API contracts and example payloads, frontend integration notes, admin-hunter behavior and sample findings, recommended configuration snippets, runbooks for engineers and pentesters, and export instructions so you can produce polished PDF or slide decks for presentations.

> Note: The content is intentionally practical — copy-pasteable commands, JSON examples, and suggested tests are included so you can onboard others or present the toolkit to stakeholders.

---

## 1) Quick Setup (Developer)

Prerequisites:
- Python 3.10+ (this workspace used Python 3.14)
- pip
- Optional: `python -m pip install reportlab python-pptx pandoc` for report/slide exports

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the web server (local development):

```bash
# Windows
run.bat
# or
python web_server.py
```

Open the UI at http://localhost:5000 (or as printed by the server).

---

## 2) API Reference (Concrete Contract)

### GET /api/modules

Description: Returns the available modules for the UI. Web modules are returned as an ordered array so the UI preserves the backend order.

Sample response (v3 format):

```json
{
  "recon": {
    "1": "Subdomain Enumeration",
    "2": "Port Scanner",
    "3": "Technology Fingerprinting"
  },
  "web": [
    {"display":"1","key":"1","name":"SQL Injection"},
    {"display":"2","key":"2","name":"XSS Scanner"},
    {"display":"3","key":"3","name":"Directory Bruteforce"}
  ],
  "mobile": {
    "1": "APK Static Analysis",
    "2": "Mobile API Tester",
    "3": "Dynamic Instrumentation (Frida)"
  }
}
```

Notes:
- `web` is an array of objects: `display` (UI number), `key` (task key used by backend), and `name` (human label).
- The UI must use `key` when emitting scan requests; `display` is purely visual.


### POST /api/configure

Request body:
```json
{ "sid": "default", "target": "https://example.com", "threads": 10, "timeout": 10 }
```

Response:
```json
{ "ok": true, "target": "https://example.com", "domain": "example.com" }
```

Purpose: create or update an in-memory session that is used during scans.


### GET /api/session?sid=default

Response shape:

```json
{
  "target": "https://example.com",
  "domain": "example.com",
  "findings_count": 3,
  "findings": [ /* array of finding objects */ ]
}
```


### POST /api/generate_report

Input: `{"sid":"default"}`

Behavior: This triggers `modules.reporter.html_report.ReportGenerator(sess).generate(name)` and returns the report path. If there are no findings, the call returns 400.

---

## 3) Frontend Integration Notes (Actionable)

File: `webui/app.js`

Key points:
- `loadModules()` fetches `/api/modules` and calls `buildModuleList()` for each category.
- `buildModuleList()` accepts either an object or an array for `mods`.
- When `mods` is an array, each item MUST contain a `key` property used for `element.dataset.key`.
- `startScan()` gathers selected items with `getSelected(type)` and emits a socket event `start_scan` containing `module_type`, `selected`, and `session_sid`.

Recommended change to ensure robustness (already applied in repo): always prefer `key` over visual index when submitting a scan request.

Example scan flow (copy-paste):

```js
// In browser devtools console, trigger a web scan with the first two web modules
const selected = ['1','2'];
io_socket.emit('start_scan', { module_type: 'web', selected, session_sid: 'default' });
```

---

## 4) Admin Hunter — Behavior, Heuristics, and Example Findings

The `AdminHunter` module performs four phases: Access check, Login brute-force, Authenticated deep scan, and Passive checks.

Important operational principle introduced in recent fixes:
- Passive leak checks are SKIPPED if a page contains a login form. This avoids false positives for auth-gated login pages (e.g., OWASP Juice Shop admin login).
- If a page is *accessible* (HTTP 200) and does not contain a login form but contains dashboard indicators ("dashboard", "logout", etc.), it is flagged as an exposed admin dashboard (high severity).

Example finding produced by `AdminHunter` when default creds found:

```json
{
  "url": "https://target.example.com/admin/login",
  "type": "Admin Panel — Default Credentials",
  "severity": "critical",
  "detail": "Successfully logged into admin panel with admin:admin",
  "evidence": "Credentials: admin:admin | URL: https://target.example.com/admin/login",
  "owasp": "A07:2021 – Identification and Authentication Failures",
  "cvss": 9.8,
  "remediation": "Change default credentials and enable MFA."
}
```

Example passive info-leak finding (only when page accessible and no login form):

```json
{
  "url": "https://target.example.com/admin/debug",
  "type": "Admin Page Info Leak — Stack trace leak",
  "severity": "high",
  "detail": "Stack trace strings found in admin debug page response",
  "evidence": "Pattern matched: stack trace",
  "owasp": "A05:2021 – Security Misconfiguration",
  "cvss": 7.5
}
```

Operational notes for pentesters:
- Juice Shop and intentionally vulnerable apps often include an admin login page — do not treat login forms as immediate vulnerabilities.
- Focus on: exposed dashboards, default credentials, sensitive data in unauthenticated pages, and object-level authorization checks (IDOR) on admin APIs.

---

## 5) Runbooks and Example Commands (For Presentation/Demo)

1) Configure a target and run a quick recon + web scan (CLI-driven via UI):

```bash
# Configure session
curl -X POST -H "Content-Type: application/json" http://localhost:5000/api/configure -d '{"sid":"demo","target":"http://juice-shop:3000","threads":8,"timeout":8}'

# Start a web scan by calling socket.io or using the UI. For automated demo, run headless script that uses the HTTP API socket proxy.
```

2) Retrieve findings after the scan:

```bash
curl "http://localhost:5000/api/session?sid=demo"
```

3) Generate a PDF report server-side (if findings present):

```bash
curl -X POST -H "Content-Type: application/json" http://localhost:5000/api/generate_report -d '{"sid":"demo"}'
```

---

## 6) Reporting Format and Example Templates

Suggested finding JSON schema (canonical):

```json
{
  "url": "string",
  "type": "string",
  "severity": "info|low|medium|high|critical",
  "detail": "detailed human-readable description",
  "evidence": "short evidence snippet",
  "owasp": "OWASP mapping",
  "cvss": 0.0,
  "remediation": "human readable remediation steps"
}
```

Use this schema as the single source of truth for `modules/*` when adding new modules — keeps the reporter and UI simple and consistent.

---

## 7) Suggested Additions (Senior-level)

- Add `modules/reporter/generator.py` which accepts a session dict and can output both HTML/PDF and Markdown. Move current `ReportGenerator` into a testable API.
- Add unit tests:
  - `test_api_modules_ordering` — assert `GET /api/modules` returns web array matching `WEB_ATTACK_TASK_ORDER`.
  - `test_adminhunter_passive_skip` — with a mock response containing a login form, verify passive checks are not emitted.
- CI: run `pytest` on PRs and create a release pipeline that produces a PDF artifact.

---

## 8) Exporting Options: MD → PDF / Slides

Option A — Use existing `reportlab` script (server-side): we already used `reportlab` to produce a basic PDF.

Option B — Convert Markdown to PDF/Slides using `pandoc`:

```bash
# Requires pandoc installed
pandoc reports/complete_toolkit_presentation.md -o reports/complete_toolkit_presentation.pdf --pdf-engine=xelatex
```

Option C — Generate PPTX slides (recommended for presentations): install `python-pptx` and create a generator that maps sections to slides.

---

## 9) Appendix: Example Session & Findings (sample files)
- `reports/sample_findings.json` — sample findings JSON (see repo)
- `sessions/session_demo.json` — example session capture (optional)

---

## 10) Next Steps I can take now (choose or let me proceed):
- Produce a PDF version of this document (I can run `pandoc` or use ReportLab).
- Generate a slide deck (`.pptx`) where each major section becomes 1–2 slides.
- Add automated unit tests for the critical behaviors described above.


---

Prepared by: internal audit script — can be iterated into a formal report generator.

