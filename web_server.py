#!/usr/bin/env python3
import os
os.environ.setdefault("PYTHONUTF8", "1")
"""
WebPwn Web Server — Flask + SocketIO Backend
Real-time streaming of scan results to browser UI
"""

import sys, os, json, threading, queue, logging, time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

app = Flask(__name__, static_folder="webui", static_url_path="")
app.config["SECRET_KEY"] = "webpwn-secret-2024"
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.WARNING)

# ── Global session state ────────────────────────────────────────────────────
SESSIONS: dict = {}          # sid -> session dict
ACTIVE_SCANS: dict = {}      # sid -> threading.Event (cancel flag)

RECON_TASKS = {
    "1": "Subdomain Enumeration",
    "2": "Port Scanner",
    "3": "Technology Fingerprinting",
    "4": "Web Crawler",
    "5": "Cloud Asset Hunter",
    "6": "ASN / BGP Enum",
    "7": "GitHub Leakage Dorker",
}

WEB_ATTACK_TASKS = {
    "1":  "SQL Injection",
    "2":  "XSS Scanner",
    "3":  "Directory Bruteforce",
    "4":  "Auth Tester",
    "5":  "SSRF Scanner",
    "6":  "CORS Scanner",
    "7":  "Header Analyzer",
    "8":  "Cookie Check",
    "9":  "Command Injection",
    "10": "CSRF Scanner",
    "11": "LFI Scanner",
    "12": "XXE Scanner",
    "13": "WAF Detector",
    "14": "JWT Analyzer",
    "15": "Open Redirect",
    "16": "CVE Lookup",
    "17": "DOM XSS Scanner",
    "18": "OAuth Tester",
    "19": "Admin Hunter",
    "20": "SSTI Scanner",
    "21": "Host Header Injection",
    "22": "Subdomain Takeover",
    "24": "OOB Tester",
    "26": "Business Logic",
    "27": "Exploit Engine",
    "28": "2FA/MFA Bypass",
    "29": "Exploit Chain Analyzer",
    "37": "NoSQL Injection",
    "40": "Cloud Misconfig",
}

WEB_ATTACK_TASK_ORDER = [
    "1","2","3","4","5","6","7","8","9","10","11","12","13",
    "14","15","16","17","18","19","20","21","22",
    "24","26","27","28","29","37","40",
]

MOBILE_TASKS = {
    "1": "APK Static Analysis",
    "2": "Mobile API Tester",
    "3": "Dynamic Instrumentation (Frida)",
}

# ── Helper ──────────────────────────────────────────────────────────────────

def emit_log(sid, msg, level="info", module="System"):
    socketio.emit("log", {
        "time": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "module": module,
        "msg": msg,
    }, room=sid)

def emit_finding(sid, finding):
    socketio.emit("finding", finding, room=sid)

def emit_progress(sid, current, total, module):
    socketio.emit("progress", {"current": current, "total": total, "module": module}, room=sid)

def emit_done(sid, module, count):
    socketio.emit("scan_done", {"module": module, "count": count}, room=sid)

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("webui", "index.html")

@app.route("/api/modules")
def get_modules():
    return jsonify({
        "recon": RECON_TASKS,
        "web": [
            {
                "display": str(i + 1),
                "key": task_key,
                "name": WEB_ATTACK_TASKS[task_key],
            }
            for i, task_key in enumerate(WEB_ATTACK_TASK_ORDER)
        ],
        "mobile": MOBILE_TASKS,
    })

@app.route("/api/session", methods=["GET"])
def get_session():
    sid = request.args.get("sid", "default")
    sess = SESSIONS.get(sid, {})
    return jsonify({
        "target": sess.get("target"),
        "domain": sess.get("domain"),
        "findings_count": len(sess.get("findings", [])),
        "findings": sess.get("findings", []),
    })

@app.route("/api/configure", methods=["POST"])
def configure():
    data = request.json or {}
    sid = data.get("sid", "default")
    target = data.get("target", "").strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
    except Exception:
        return jsonify({"error": "Invalid URL"}), 400

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSIONS[sid] = {
        "name": ts,
        "target": target,
        "domain": domain,
        "threads": int(data.get("threads", 10)),
        "timeout": int(data.get("timeout", 10)),
        "findings": [],
        "start_time": datetime.now().isoformat(),
    }
    return jsonify({"ok": True, "target": target, "domain": domain})

@app.route("/api/reports")
def list_reports():
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)
    files = []
    for f in sorted(reports_dir.glob("*.html"), reverse=True):
        files.append({"name": f.name, "size": f.stat().st_size, "time": f.stat().st_mtime})
    return jsonify(files[:20])

@app.route("/api/reports/<name>")
def get_report(name):
    reports_dir = ROOT / "reports"
    return send_from_directory(str(reports_dir), name)

@app.route("/api/generate_report", methods=["POST"])
def generate_report_api():
    data = request.json or {}
    sid = data.get("sid", "default")
    sess = SESSIONS.get(sid)
    if not sess or not sess.get("findings"):
        return jsonify({"error": "No findings to report"}), 400
    try:
        from modules.reporter.html_report import ReportGenerator
        name = f"webui_{sess['name']}"
        path = ReportGenerator(sess).generate(name)
        return jsonify({"ok": True, "path": str(path), "name": Path(path).name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/cancel", methods=["POST"])
def cancel_scan():
    data = request.json or {}
    sid = data.get("sid", "default")
    if sid in ACTIVE_SCANS:
        ACTIVE_SCANS[sid].set()
        return jsonify({"ok": True, "msg": "Scan cancelled"})
    return jsonify({"ok": False, "msg": "No active scan"})

# ── Scan runner (threaded) ───────────────────────────────────────────────────

def run_scan_thread(sid, module_type, selected_keys):
    """Run selected module keys sequentially in a background thread."""
    sess = SESSIONS.get(sid)
    if not sess:
        socketio.emit("error", {"msg": "Session not configured"}, room=sid)
        return

    cancel_evt = threading.Event()
    ACTIVE_SCANS[sid] = cancel_evt

    target = sess["target"]
    domain = sess["domain"]
    th = sess["threads"]
    to = sess["timeout"]
    total = len(selected_keys)

    # Build task map
    if module_type == "recon":
        task_map = _build_recon_tasks(target, domain, th, to)
        label_map = RECON_TASKS
    elif module_type == "web":
        task_map = _build_web_tasks(target, th, to, sess)
        label_map = WEB_ATTACK_TASKS
    elif module_type == "mobile":
        task_map = _build_mobile_tasks(target, to, sess)
        label_map = MOBILE_TASKS
    else:
        socketio.emit("error", {"msg": "Unknown module type"}, room=sid)
        return

    for i, key in enumerate(selected_keys, 1):
        if cancel_evt.is_set():
            emit_log(sid, "⛔ Scan cancelled by user", "warning", "System")
            break

        name = label_map.get(key, f"Task {key}")
        emit_progress(sid, i, total, name)
        emit_log(sid, f"▶ Starting: {name}", "info", name)

        func = task_map.get(key)
        if func is None:
            emit_log(sid, f"Module {key} not available", "warning", name)
            continue

        try:
            results = func()
            if isinstance(results, list):
                for r in results:
                    sess["findings"].append(r)
                    emit_finding(sid, r)
                emit_done(sid, name, len(results))
                emit_log(sid, f"✅ {name} → {len(results)} finding(s)", "success", name)
            elif isinstance(results, dict):
                sess["findings"].append({"module": name, "severity": "info", "data": results})
                emit_log(sid, f"✅ {name} completed", "success", name)
                emit_done(sid, name, 1)
            else:
                emit_done(sid, name, 0)
                emit_log(sid, f"✅ {name} completed (no findings)", "success", name)
        except Exception as e:
            emit_log(sid, f"❌ {name} error: {e}", "error", name)

    # Save session
    try:
        _save_sess(sess)
    except Exception:
        pass

    ACTIVE_SCANS.pop(sid, None)
    socketio.emit("all_done", {
        "total_findings": len(sess.get("findings", [])),
    }, room=sid)

def _save_sess(sess):
    sd = ROOT / "sessions"
    sd.mkdir(exist_ok=True)
    fp = sd / f"session_{sess['name']}.json"
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(sess, f, indent=2, default=str)

# ── Task builders ────────────────────────────────────────────────────────────

def _build_recon_tasks(target, domain, th, to):
    def _sub():
        from modules.recon.subdomain_enum import SubdomainEnumerator
        return SubdomainEnumerator(domain, threads=th).run()

    def _port():
        from modules.recon.port_scanner import PortScanner
        return PortScanner(domain, timeout=to).run()

    def _tech():
        from modules.recon.tech_detector import TechDetector
        return TechDetector(target, timeout=to).run()

    def _crawl():
        from modules.recon.crawler import WebCrawler
        return WebCrawler(target, threads=th, timeout=to).run()

    def _cloud():
        from modules.recon.cloud_hunter import CloudHunter
        return CloudHunter(domain, threads=th, timeout=to).run()

    def _asn():
        from modules.recon.asn_enum import ASNEnumerator
        return ASNEnumerator(domain).run()

    def _gh():
        from modules.recon.github_dorker import GitHubDorker
        return GitHubDorker(domain).run()

    return {
        "1": _sub, "2": _port, "3": _tech, "4": _crawl,
        "5": _cloud, "6": _asn, "7": _gh,
    }


def _build_web_tasks(target, th, to, sess):
    s = sess  # closure
    def _sess():
        sm = s.get("_session_mgr")
        return sm.get_session() if sm else None

    tasks = {}

    def _make(mod, cls, **kw):
        def fn():
            m = __import__(mod, fromlist=[cls])
            return getattr(m, cls)(target, **kw).run()
        return fn

    import importlib

    tasks["1"]  = _make("modules.web.sqli_scanner",     "SQLiScanner",     threads=th, timeout=to)
    tasks["2"]  = _make("modules.web.xss_scanner",      "XSSScanner",      threads=th, timeout=to)
    tasks["3"]  = _make("modules.web.dir_bruteforce",   "DirBruteforcer",  threads=th, timeout=to)
    tasks["4"]  = _make("modules.web.auth_tester",      "AuthTester",      timeout=to)
    tasks["5"]  = _make("modules.web.ssrf_scanner",     "SSRFScanner",     timeout=to)
    tasks["6"]  = _make("modules.web.cors_scanner",     "CORSScanner",     timeout=to)
    tasks["7"]  = _make("modules.web.header_analyzer",  "HeaderAnalyzer",  timeout=to)
    tasks["9"]  = _make("modules.web.cmdi_scanner",     "CMDIScanner",     threads=th, timeout=to)
    tasks["10"] = _make("modules.web.csrf_scanner",     "CSRFScanner",     timeout=to)
    tasks["11"] = _make("modules.web.lfi_scanner",      "LFIScanner",      threads=th, timeout=to)
    tasks["12"] = _make("modules.web.xxe_scanner",      "XXEScanner",      threads=th, timeout=to)
    tasks["14"] = _make("modules.web.jwt_analyzer",     "JWTAnalyzer",     timeout=to)
    tasks["37"] = _make("modules.web.nosql_scanner",    "NoSQLScanner",    timeout=to)
    tasks["40"] = _make("modules.web.cloud_misconfig_scanner", "CloudMisconfigScanner", timeout=to)

    def _cve():
        from modules.web.cve_lookup import CVELookup
        return CVELookup(tech_findings={"target": [target]}, timeout=15).run()
    tasks["16"] = _cve

    def _admin():
        from modules.web.admin_hunter import AdminHunter
        import requests
        from bs4 import BeautifulSoup
        
        PATHS = ["/admin","/administrator","/dashboard","/wp-admin","/manager","/cpanel"]
        found = []
        for p in PATHS:
            try:
                r = requests.get(target.rstrip("/")+p, timeout=to, verify=False)
                if r.status_code != 200:
                    continue
                
                # Check if this is a login-protected page (false positive filter)
                try:
                    soup = BeautifulSoup(r.text, "lxml")
                    lower_text = r.text.lower()
                    
                    # Look for login form indicators
                    has_password_field = soup.find("input", {"type": "password"}) is not None
                    has_login_text = any(x in lower_text for x in ["login", "sign in", "password", "authenticate"])
                    has_form = soup.find("form") is not None
                    
                    # If this looks like a login page, skip it
                    if (has_password_field and has_form) or (has_login_text and has_form):
                        continue
                except Exception:
                    pass
                
                found.append(target.rstrip("/")+p)
            except Exception:
                pass
        
        if not found:
            return []
        return AdminHunter(target=target, admin_urls=found, threads=th, timeout=to).run()
    tasks["19"] = _admin

    def _oob():
        from modules.web.oob_tester import OOBTester
        return OOBTester(target).inject_payloads()
    tasks["24"] = _oob

    def _biz():
        from modules.web.business_logic_tester import BusinessLogicTester
        return BusinessLogicTester(target, timeout=to).run()
    tasks["26"] = _biz

    def _exploit():
        from modules.web.exploit_engine import ExploitEngine
        return ExploitEngine(target, sess.get("findings", []), timeout=to).run()
    tasks["27"] = _exploit

    def _mfa():
        from modules.web.mfa_bypass import MFABypassTester
        return MFABypassTester(target, timeout=to).run()
    tasks["28"] = _mfa

    def _chain():
        from modules.web.chain_engine import ChainEngine
        return ChainEngine(sess.get("findings", []), target=target).analyze()
    tasks["29"] = _chain

    return tasks


def _build_mobile_tasks(target, to, sess):
    def _apk():
        apk = sess.get("apk_path", "")
        if not apk or not Path(apk).exists():
            return [{"severity": "info", "type": "APK", "detail": "No APK path configured"}]
        from modules.mobile.apk_analyzer import APKAnalyzer
        return APKAnalyzer(apk).run()

    def _api():
        from modules.mobile.api_tester import APITester
        return APITester(target, timeout=to).run()

    def _frida():
        from modules.mobile.frida_instrumentation import FridaInstrumentation
        return FridaInstrumentation().run()

    return {"1": _apk, "2": _api, "3": _frida}


# ── SocketIO events ──────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    sid = request.sid
    SESSIONS.setdefault(sid, {})
    emit("connected", {"sid": sid})

@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    if sid in ACTIVE_SCANS:
        ACTIVE_SCANS[sid].set()
        ACTIVE_SCANS.pop(sid, None)

@socketio.on("start_scan")
def on_start_scan(data):
    sid = request.sid
    module_type = data.get("module_type", "recon")
    selected = data.get("selected", [])

    if not selected:
        emit("error", {"msg": "No modules selected"})
        return

    # Copy session from browser-provided sid to socket sid if different
    browser_sid = data.get("session_sid", sid)
    if browser_sid != sid and browser_sid in SESSIONS:
        SESSIONS[sid] = SESSIONS[browser_sid]

    if not SESSIONS.get(sid, {}).get("target"):
        emit("error", {"msg": "Configure target first"})
        return

    if sid in ACTIVE_SCANS and not ACTIVE_SCANS[sid].is_set():
        emit("error", {"msg": "Scan already running"})
        return

    t = threading.Thread(
        target=run_scan_thread,
        args=(sid, module_type, selected),
        daemon=True,
    )
    t.start()
    emit("scan_started", {"module_type": module_type, "selected": selected})

@socketio.on("cancel_scan")
def on_cancel(data):
    sid = request.sid
    if sid in ACTIVE_SCANS:
        ACTIVE_SCANS[sid].set()
        emit("log", {"time": datetime.now().strftime("%H:%M:%S"),
                     "level": "warning", "module": "System", "msg": "⛔ Cancelling..."})

# ── Entry ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"\n  WebPwn Web UI — http://{host}:{port}\n")
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
