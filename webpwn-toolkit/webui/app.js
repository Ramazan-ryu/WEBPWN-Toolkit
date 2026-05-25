/* WebPwn Web UI — app.js */
'use strict';

// ── State ────────────────────────────────────────────────────────────────────
const S = {
  sid: null,
  apiSid: 'default',
  target: null,
  findings: [],
  modules: { recon: {}, web: {}, mobile: {} },
  running: {},
};

// ── Utilities ────────────────────────────────────────────────────────────────
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const ts  = () => new Date().toTimeString().slice(0,8);
const $   = id => document.getElementById(id);
const now = () => new Date().toTimeString().slice(0,8);

// ── Socket ───────────────────────────────────────────────────────────────────
const io_socket = io({ transports: ['websocket','polling'] });

io_socket.on('connect', () => {
  S.sid = io_socket.id;
  setConn(true);
});
io_socket.on('disconnect', () => setConn(false));
io_socket.on('connected', d => { S.sid = d.sid; });

io_socket.on('log', entry => {
  writeLog('log-global', entry);
  const page = document.querySelector('.page.active');
  if (page) {
    const lid = page.id.replace('page-','') + '-log';
    if ($(lid)) writeLog(lid, entry);
  }
});

io_socket.on('finding', f => {
  S.findings.push(f);
  refreshStats();
});

io_socket.on('progress', d => {
  const type = activePage();
  setProgress(type, d.current, d.total, d.module);
});

io_socket.on('scan_started', d => {
  setScan(d.module_type, true);
  writeLog('log-global', { time: now(), level:'info', module:'System', msg:`Started ${d.selected.length} module(s)` });
});

io_socket.on('scan_done', d => {
  writeLog('log-global', { time: now(), level:'success', module: d.module, msg:`${d.count} finding(s)` });
});

io_socket.on('all_done', d => {
  const type = activePage();
  setScan(type, false);
  writeLog('log-global', { time: now(), level:'success', module:'System', msg:`Scan complete — ${d.total_findings} total finding(s)` });
  syncFindings();
});

io_socket.on('error', d => {
  setStatus('config-status', d.msg, 'err');
  writeLog('log-global', { time: now(), level:'error', module:'System', msg: d.msg });
});

// ── Navigation ───────────────────────────────────────────────────────────────
const PAGE_TITLES = {
  dashboard:'Dashboard', target:'Target Config',
  recon:'Reconnaissance', web:'Web Attacks',
  mobile:'Mobile Analysis', findings:'Findings', reports:'Reports',
};

document.querySelectorAll('[data-page]').forEach(el => {
  el.addEventListener('click', e => { e.preventDefault(); goTo(el.dataset.page); });
});

function goTo(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
  const p = $('page-'+page);
  if (p) p.classList.add('active');
  const n = document.querySelector(`.nav-link[data-page="${page}"]`);
  if (n) n.classList.add('active');
  $('topbar-title').textContent = PAGE_TITLES[page] || page;
  if (page === 'findings') renderFindings();
  if (page === 'reports')  loadReports();
}

// ── Load Modules ─────────────────────────────────────────────────────────────
async function loadModules() {
  const res = await fetch('/api/modules').catch(() => null);
  if (!res) return;
  const data = await res.json();
  S.modules = data;
  buildModuleList('recon-modules', data.recon, 'recon');
  buildModuleList('web-modules',   data.web,   'web');
  buildModuleList('mobile-modules',data.mobile,'mobile');
}

function buildModuleList(cid, mods, type) {
  const c = $(cid);
  if (!c) return;
  c.innerHTML = '';
  const entries = Array.isArray(mods)
    ? mods.map(item => [item.key, item])
    : Object.entries(mods);

  entries.forEach(([key, value]) => {
    const display = value && value.display ? value.display : key;
    const name = value && value.name ? value.name : value;
    const taskKey = value && value.key ? value.key : key;
    const el = document.createElement('div');
    el.className = 'mod-item';
    el.dataset.key = taskKey;
    el.innerHTML = `
      <div class="mod-cb"></div>
      <span class="mod-num">${display}</span>
      <span class="mod-name">${esc(name)}</span>
    `;
    el.addEventListener('click', () => toggleMod(el, type));
    c.appendChild(el);
  });
  updateSelCount(type);
}

function toggleMod(el, type) {
  el.classList.toggle('sel');
  updateSelCount(type);
}

function selectAll(type) {
  document.querySelectorAll(`#${type}-modules .mod-item`).forEach(el => el.classList.add('sel'));
  updateSelCount(type);
}
function selectNone(type) {
  document.querySelectorAll(`#${type}-modules .mod-item`).forEach(el => el.classList.remove('sel'));
  updateSelCount(type);
}
function getSelected(type) {
  return [...document.querySelectorAll(`#${type}-modules .mod-item.sel`)].map(el => el.dataset.key);
}
function updateSelCount(type) {
  const n = getSelected(type).length;
  const el = $(`${type}-sel-count`);
  if (el) el.textContent = `${n} selected`;
}

// Select All / None buttons
['recon','web','mobile'].forEach(t => {
  $(`${t}-all`)  && ($(`${t}-all`).onclick  = () => selectAll(t));
  $(`${t}-none`) && ($(`${t}-none`).onclick = () => selectNone(t));
  $(`${t}-clear-log`) && ($(`${t}-clear-log`).onclick = () => clearLog(`${t}-log`));
});

// Web search filter
const wsearch = $('web-search');
if (wsearch) wsearch.addEventListener('input', e => {
  const q = e.target.value.toLowerCase();
  document.querySelectorAll('#web-modules .mod-item').forEach(el => {
    el.style.display = el.querySelector('.mod-name').textContent.toLowerCase().includes(q) ? '' : 'none';
  });
});

// Clear global log
$('clear-global-log') && ($('clear-global-log').onclick = () => clearLog('log-global'));

// ── Target Config ─────────────────────────────────────────────────────────────
$('configure-btn').addEventListener('click', async () => {
  const target  = $('inp-target').value.trim();
  const threads = $('inp-threads').value;
  const timeout = $('inp-timeout').value;
  if (!target) { setStatus('config-status','Enter a target URL','err'); return; }

  const res = await fetch('/api/configure', {
    method: 'POST',
    headers: { 'Content-Type':'application/json' },
    body: JSON.stringify({ sid: S.apiSid, target, threads, timeout }),
  }).catch(() => null);

  if (!res) { setStatus('config-status','Server unreachable','err'); return; }
  const data = await res.json();
  if (data.ok) {
    S.target = data.target;
    setStatus('config-status', `Saved — ${data.target}`, 'ok');
    $('stat-target').textContent = data.target;
    $('topbar-target-text').textContent = data.domain;
    $('target-preview').textContent = data.target;
    writeLog('log-global', { time: now(), level:'success', module:'Config', msg:`Target set: ${data.target}` });
  } else {
    setStatus('config-status', data.error || 'Failed', 'err');
  }
});

// ── Run Scan ──────────────────────────────────────────────────────────────────
function startScan(type) {
  if (!S.target) { alert('Configure a target first (Target Config).'); goTo('target'); return; }
  const selected = getSelected(type);
  if (!selected.length) { alert('Select at least one module.'); return; }
  clearLog(type+'-log');
  io_socket.emit('start_scan', {
    module_type: type,
    selected,
    session_sid: S.apiSid,
  });
}
function cancelScan(type) {
  io_socket.emit('cancel_scan', {});
  setScan(type, false);
}

$('recon-run').onclick    = () => startScan('recon');
$('recon-cancel').onclick = () => cancelScan('recon');
$('web-run').onclick      = () => startScan('web');
$('web-cancel').onclick   = () => cancelScan('web');
$('mobile-run').onclick   = () => {
  const apk = $('apk-path').value.trim();
  if (apk) fetch('/api/configure',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ sid: S.apiSid, apk_path: apk }) });
  startScan('mobile');
};
$('mobile-cancel').onclick = () => cancelScan('mobile');

// ── Progress ──────────────────────────────────────────────────────────────────
function setProgress(type, cur, tot, mod) {
  const wrap  = $(`${type}-prog-wrap`);
  const label = $(`${type}-prog-label`);
  const pct   = $(`${type}-prog-pct`);
  const fill  = $(`${type}-prog-fill`);
  if (!wrap) return;
  wrap.classList.remove('hidden');
  wrap.classList.add('running');
  const p = tot > 0 ? Math.round(cur/tot*100) : 0;
  fill.style.width = p + '%';
  label.textContent = mod || '—';
  pct.textContent   = `${cur}/${tot} (${p}%)`;
}

function setScan(type, running) {
  S.running[type] = running;
  const run    = $(`${type}-run`);
  const cancel = $(`${type}-cancel`);
  if (run)    run.classList.toggle('hidden', running);
  if (cancel) cancel.classList.toggle('hidden', !running);
  const wrap = $(`${type}-prog-wrap`);
  if (!running && wrap) {
    wrap.classList.remove('running');
    setTimeout(() => { if (wrap) wrap.classList.add('hidden'); }, 3000);
  }
}

// ── Log ───────────────────────────────────────────────────────────────────────
function writeLog(cid, entry) {
  const c = $(cid);
  if (!c) return;
  // Remove welcome message
  const w = c.querySelector('.term-welcome');
  if (w) w.remove();
  const row = document.createElement('div');
  row.className = 'log-row';
  row.innerHTML = `
    <span class="log-t">${esc(entry.time || now())}</span>
    <span class="log-m">${esc((entry.module||'').slice(0,14))}</span>
    <span class="log-${entry.level||'info'}">${esc(entry.msg||'')}</span>
  `;
  c.appendChild(row);
  c.scrollTop = c.scrollHeight;
}
function clearLog(cid) {
  const c = $(cid);
  if (c) c.innerHTML = '';
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function syncFindings() {
  const res = await fetch(`/api/session?sid=${S.apiSid}`).catch(() => null);
  if (!res) return;
  const data = await res.json();
  S.findings = data.findings || [];
  refreshStats();
}

function refreshStats() {
  const c = { critical:0, high:0, medium:0, low:0, info:0 };
  S.findings.forEach(f => {
    const s = (f.severity||'info').toLowerCase();
    c[s] != null ? c[s]++ : c.info++;
  });
  const tot = S.findings.length;
  $('stat-critical').textContent = c.critical;
  $('stat-high').textContent     = c.high;
  $('stat-medium').textContent   = c.medium;
  $('stat-low').textContent      = c.low + c.info;
  $('stat-total').textContent    = tot;
  $('topbar-findings').textContent = tot;
  $('findings-badge').textContent  = tot;

  // Bars
  const max = Math.max(tot, 1);
  $('bar-critical') && ($('bar-critical').style.width = (c.critical/max*100)+'%');
  $('bar-high')     && ($('bar-high').style.width     = (c.high/max*100)+'%');
  $('bar-medium')   && ($('bar-medium').style.width   = (c.medium/max*100)+'%');
  $('bar-low')      && ($('bar-low').style.width      = ((c.low+c.info)/max*100)+'%');
}

function renderFindings() {
  syncFindings().then(() => {
    const tbody = $('findings-tbody');
    const empty = $('findings-empty');
    const filt  = $('filter-sev').value;
    let rows = S.findings;
    if (filt) rows = rows.filter(f => (f.severity||'info').toLowerCase() === filt);
    tbody.innerHTML = '';
    if (!rows.length) { empty.classList.remove('hidden'); return; }
    empty.classList.add('hidden');
    rows.forEach(f => {
      const sev    = (f.severity||'info').toLowerCase();
      const mod    = esc((f.module||'').slice(0,24));
      const type   = esc((f.type||f.vulnerability||'Finding').slice(0,50));
      const detail = esc((f.detail||f.evidence||f.url||'').slice(0,180));
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="sev sev-${sev}">${sev.toUpperCase()}</span></td>
        <td style="font-family:var(--mono);font-size:.72rem;color:#6366f1">${mod}</td>
        <td>${type}</td>
        <td style="font-size:.75rem">${detail}</td>
      `;
      tbody.appendChild(tr);
    });
  });
}

$('filter-sev')       && ($('filter-sev').onchange      = renderFindings);
$('findings-refresh') && ($('findings-refresh').onclick  = renderFindings);

// ── Reports ───────────────────────────────────────────────────────────────────
async function loadReports() {
  const c = $('reports-list');
  c.innerHTML = '<p style="padding:16px;color:var(--text-3);font-size:.78rem">Loading…</p>';
  const res = await fetch('/api/reports').catch(() => null);
  if (!res) { c.innerHTML = '<p style="padding:16px;color:var(--red);font-size:.78rem">Error.</p>'; return; }
  const data = await res.json();
  if (!data.length) { c.innerHTML = '<p style="padding:16px;color:var(--text-3);font-size:.78rem">No reports yet.</p>'; return; }
  c.innerHTML = data.map(r => `
    <div class="report-row">
      <div>
        <div class="report-name">${esc(r.name)}</div>
        <div class="report-meta">${(r.size/1024).toFixed(1)} KB &nbsp;·&nbsp; ${new Date(r.time*1000).toLocaleString()}</div>
      </div>
      <a class="report-link" href="/api/reports/${encodeURIComponent(r.name)}" target="_blank">Open</a>
    </div>
  `).join('');
}

$('refresh-reports') && ($('refresh-reports').onclick = loadReports);

$('gen-report-btn').addEventListener('click', async () => {
  setStatus('report-status', 'Generating…', '');
  const res = await fetch('/api/generate_report', {
    method: 'POST',
    headers: { 'Content-Type':'application/json' },
    body: JSON.stringify({ sid: S.apiSid }),
  }).catch(() => null);
  if (!res) { setStatus('report-status','Server error','err'); return; }
  const data = await res.json();
  if (data.ok) { setStatus('report-status', `Saved: ${data.name}`, 'ok'); loadReports(); }
  else          { setStatus('report-status', data.error||'Failed','err'); }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function setConn(ok) {
  const dot = $('conn-dot');
  const txt = $('conn-text');
  if (!dot) return;
  dot.className = 'conn-dot ' + (ok ? 'on' : 'off');
  if (txt) txt.textContent = ok ? 'Connected' : 'Disconnected';
}

function setStatus(id, msg, type) {
  const el = $(id);
  if (!el) return;
  el.textContent  = msg;
  el.className    = 'form-status ' + type;
}

function activePage() {
  const p = document.querySelector('.page.active');
  return p ? p.id.replace('page-','') : 'web';
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadModules();
syncFindings();
setInterval(syncFindings, 15000);
