// RedactShield — Main Application
// State management, UI rendering, event handling, orchestration

import { detectSensitiveInfo, assessReidentificationRisk } from './detection.js';
import { processFile } from './processing.js';
import { MODES, redactText, exportPDF, exportImage, exportTokenKey } from './redaction.js';
import { runAudit } from './audit.js';

// ======================== STATE ========================
const S = {
  view: 'upload', // upload | processing | review | exporting | audit
  file: null,
  doc: null,          // { type, pages, fullText, qrCodes, ocrOk }
  dets: [],           // detections
  risk: null,         // re-identification risk
  mode: 'blackout',   // global mode
  itemMode: {},       // per-detection overrides
  page: 0,            // current page index
  msg: '',            // processing message
  audit: null,        // audit results
  blob: null,         // exported blob
  tokenMap: null,
  canary: '',
};

const CAT = {
  identity:         { bg: 'rgba(255,71,87,0.15)',  border: '#ff4757', label: 'Identity' },
  financial:        { bg: 'rgba(255,165,2,0.15)',   border: '#ffa502', label: 'Financial' },
  contact:          { bg: 'rgba(0,212,255,0.15)',   border: '#00d4ff', label: 'Contact' },
  quasi_identifier: { bg: 'rgba(139,92,246,0.15)',  border: '#8b5cf6', label: 'Quasi-ID' },
};
const SEV = {
  critical: '#ff4757', high: '#ffa502', medium: '#f1c40f', low: '#8b5cf6',
};

// ======================== INIT ========================
function init() {
  render();
}

function go(updates) {
  Object.assign(S, updates);
  render();
}

// ======================== RENDER ========================
function render() {
  const app = document.getElementById('app');
  switch (S.view) {
    case 'upload':     app.innerHTML = headerHTML() + uploadHTML(); break;
    case 'processing': app.innerHTML = headerHTML() + processingHTML(); break;
    case 'review':     app.innerHTML = headerHTML() + reviewHTML(); break;
    case 'exporting':  app.innerHTML = headerHTML() + exportingHTML(); break;
    case 'audit':      app.innerHTML = headerHTML() + auditHTML(); break;
  }
  postRender();
}

// -------------------- HEADER --------------------
function headerHTML() {
  return `<header class="hdr">
    <div class="hdr-l"><span class="logo-icon">\u{1F6E1}</span><span class="logo-txt">RedactShield</span></div>
    <div class="hdr-r">
      <span class="pill pill-g"><span class="dot dot-g"></span>Zero Upload</span>
      <span class="pill pill-b"><span class="dot dot-b"></span>Client-Side Only</span>
    </div>
  </header>`;
}

// -------------------- UPLOAD --------------------
function uploadHTML() {
  return `<div class="upload-view">
    <div class="hero"><h1>Detect &amp; Redact Sensitive Information</h1>
      <p class="sub">Everything runs in your browser. Nothing ever leaves your machine.</p></div>
    <div class="drop" id="dropZone">
      <svg class="drop-icon" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="4" y="8" width="40" height="32" rx="4" stroke="currentColor" stroke-width="2"/>
        <path d="M24 18v12M18 24l6-6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
      </svg>
      <h2>Drop your document here</h2>
      <p>PDF, PNG, JPG, or TXT — processed entirely in your browser</p>
      <label class="btn btn-p" for="fileIn">Browse Files</label>
      <input type="file" id="fileIn" accept=".pdf,.png,.jpg,.jpeg,.txt,.csv,.json,.xml,.md,.log" hidden>
      <div class="demo-or"><span>or</span></div>
      <button class="btn btn-s" data-a="loadDemo">\u{1F4C4} Load Demo Document</button>
    </div>
    <div class="feat-grid">
      <div class="feat"><div class="feat-i">\u{1F50D}</div><h3>Smart Detection</h3>
        <p>Verhoeff checksum for Aadhaar, Luhn for cards, context-gated bank accounts — not dumb regex</p></div>
      <div class="feat"><div class="feat-i">\u{1F512}</div><h3>True Redaction</h3>
        <p>Random-padded blackout, partial masking, encrypted tokenization — PDF text layer fully removed</p></div>
      <div class="feat"><div class="feat-i">⚔️</div><h3>Red-Team Self-Audit</h3>
        <p>Attacks its own output: hidden text extraction, OCR re-scan, QR scan, metadata &amp; hyperlink check</p></div>
      <div class="feat"><div class="feat-i">\u{1F4E1}</div><h3>Zero Network</h3>
        <p>Open DevTools → Network tab → zero requests. Your sensitive data never touches a server.</p></div>
    </div>
  </div>`;
}

// -------------------- PROCESSING --------------------
function processingHTML() {
  return `<div class="center-msg">
    <div class="spinner"></div>
    <h2>${S.msg || 'Processing…'}</h2>
    <p class="sub">All processing happens locally in your browser</p>
  </div>`;
}

// -------------------- REVIEW --------------------
function reviewHTML() {
  const pg = S.doc.pages[S.page];
  const grouped = groupBy(S.dets, 'category');
  const total = S.dets.length;
  const qrCount = (S.doc.qrCodes || []).length + (pg.qrCodes || []).length;

  return `<div class="review">
    <div class="viewer" id="viewer">
      ${S.doc.pages.length > 1 ? `<div class="pg-nav">
        <button class="btn btn-s" data-a="prevPage" ${S.page === 0 ? 'disabled' : ''}>&#9664; Prev</button>
        <span>Page ${S.page + 1} / ${S.doc.pages.length}</span>
        <button class="btn btn-s" data-a="nextPage" ${S.page >= S.doc.pages.length - 1 ? 'disabled' : ''}>Next &#9654;</button>
      </div>` : ''}
      <div class="canvas-wrap" id="canvasWrap"></div>
    </div>
    <div class="panel">
      <div class="panel-hdr">
        <h2>Detection Results</h2>
        <span class="count">${total} item${total !== 1 ? 's' : ''} found</span>
      </div>

      ${S.risk && S.risk.warning ? `<div class="alert alert-warn">
        <strong>⚠ Re-identification Risk (${S.risk.level.toUpperCase()})</strong>
        <p>${S.risk.warning}</p>
      </div>` : ''}

      ${qrCount ? `<div class="alert alert-danger">
        <strong>\u{1F4F1} ${qrCount} QR Code${qrCount > 1 ? 's' : ''} Detected</strong>
        <p>Aadhaar QR codes embed full demographic data. These will be blacked out on export.</p>
      </div>` : ''}

      ${S.doc.ocrOk === false ? `<div class="alert alert-info">
        <strong>OCR Unavailable</strong>
        <p>Tesseract.js is loading or failed. Text detection may be incomplete for images.</p>
      </div>` : ''}

      <div class="mode-bar">
        <label>Global Mode:</label>
        <select id="globalMode" data-a="setMode">
          ${['blackout','mask','token','ignore'].map(m =>
            `<option value="${m}" ${S.mode === m ? 'selected' : ''}>${modeLabel(m)}</option>`
          ).join('')}
        </select>
      </div>

      <div class="det-list">
        ${Object.entries(grouped).map(([cat, items]) => `
          <div class="det-group">
            <div class="det-group-hdr" style="border-color:${CAT[cat]?.border || '#666'}">
              <span class="cat-badge" style="background:${CAT[cat]?.bg || '#333'};color:${CAT[cat]?.border || '#ccc'}">${CAT[cat]?.label || cat}</span>
              <span class="det-cnt">${items.length}</span>
            </div>
            ${items.map(d => detCardHTML(d)).join('')}
          </div>
        `).join('')}
        ${total === 0 ? '<p class="empty">No sensitive information detected.</p>' : ''}
      </div>

      ${total > 0 ? `<div class="export-bar">
        <div class="canary-row">
          <label>Canary tag (optional):</label>
          <input id="canaryIn" type="text" placeholder="e.g. Shared-With-HR" value="${esc(S.canary)}">
        </div>
        <button class="btn btn-p btn-lg" data-a="export">Redact &amp; Export</button>
      </div>` : ''}
    </div>
  </div>`;
}

function detCardHTML(d) {
  const mode = S.itemMode[d.id] || S.mode;
  return `<div class="det-card" data-id="${d.id}">
    <div class="det-top">
      <span class="sev-dot" style="background:${SEV[d.severity] || '#888'}"></span>
      <span class="det-type">${d.label}</span>
      <span class="det-conf" title="Confidence">${Math.round(d.confidence * 100)}%</span>
    </div>
    <div class="det-val"><code>${esc(d.value)}</code></div>
    <select class="det-mode" data-a="itemMode" data-id="${d.id}">
      ${['blackout','mask','token','ignore'].map(m =>
        `<option value="${m}" ${mode === m ? 'selected' : ''}>${modeLabel(m)}</option>`
      ).join('')}
    </select>
  </div>`;
}

// -------------------- EXPORTING --------------------
function exportingHTML() {
  return `<div class="center-msg">
    <div class="spinner"></div>
    <h2>${S.msg || 'Applying redactions…'}</h2>
    <p class="sub">Flattening document, stripping metadata, running self-audit</p>
  </div>`;
}

// -------------------- AUDIT --------------------
function auditHTML() {
  const all = S.audit || [];
  const passed = all.filter(c => c.status === 'pass').length;
  const failed = all.filter(c => c.status === 'fail').length;

  return `<div class="audit-view">
    <div class="audit-hdr">
      <h2>⚔️ Red-Team Self-Audit</h2>
      <p class="sub">We attacked our own output. Here are the results:</p>
      <div class="audit-summary">
        <span class="pill pill-g">${passed} Passed</span>
        ${failed ? `<span class="pill pill-r">${failed} Failed</span>` : ''}
        <span class="pill pill-b">${all.length} Checks</span>
      </div>
    </div>
    <div class="audit-grid">
      ${all.map(c => `<div class="audit-card audit-${c.status}">
        <div class="audit-icon">${c.status === 'pass' ? '✅' : c.status === 'fail' ? '❌' : c.status === 'warn' ? '⚠️' : 'ℹ️'}</div>
        <div class="audit-body">
          <h3>${c.name}</h3>
          <p class="audit-desc">${c.desc}</p>
          <p class="audit-detail">${c.detail}</p>
        </div>
      </div>`).join('')}
    </div>
    <div class="audit-actions">
      <button class="btn btn-p btn-lg" data-a="download">⬇ Download Redacted Document</button>
      ${S.tokenMap && S.tokenMap.size ? `<button class="btn btn-s" data-a="downloadTokens">\u{1F511} Export Token Key</button>` : ''}
      <button class="btn btn-s" data-a="restart">\u{1F504} Process Another File</button>
    </div>
    <p class="footer-note">Everything above was processed 100% in your browser. Zero bytes sent to any server.</p>
  </div>`;
}

// ======================== POST-RENDER ========================
function postRender() {
  const app = document.getElementById('app');

  // ---------- Drop zone ----------
  const dz = app.querySelector('#dropZone');
  if (dz) {
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
    dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag-over'); handleFile(e.dataTransfer.files[0]); });
  }
  const fi = app.querySelector('#fileIn');
  if (fi) fi.addEventListener('change', () => { if (fi.files[0]) handleFile(fi.files[0]); });

  // ---------- Canvas ----------
  const wrap = app.querySelector('#canvasWrap');
  if (wrap && S.doc) {
    const pg = S.doc.pages[S.page];
    if (pg.canvas) {
      renderCanvas(wrap, pg);
    } else if (pg.text) {
      renderTextView(wrap, pg);
    }
  }

  // ---------- Delegated clicks ----------
  app.querySelectorAll('[data-a]').forEach(el => {
    const a = el.dataset.a;
    if (el.tagName === 'SELECT') {
      el.addEventListener('change', () => onAction(a, el));
    } else if (el.tagName === 'BUTTON' || el.tagName === 'LABEL') {
      el.addEventListener('click', () => onAction(a, el));
    }
  });
}

// ======================== CANVAS RENDERING ========================
function renderCanvas(wrap, pg) {
  const src = pg.canvas;
  const ratio = src.width / src.height;
  const maxW = wrap.clientWidth || 700;
  const maxH = window.innerHeight * 0.65;
  let w, h;
  if (maxW / maxH > ratio) { h = maxH; w = h * ratio; }
  else { w = maxW; h = w / ratio; }

  const c = document.createElement('canvas');
  c.width = w; c.height = h;
  c.className = 'doc-canvas';
  const ctx = c.getContext('2d');
  ctx.drawImage(src, 0, 0, w, h);

  const sx = w / src.width, sy = h / src.height;

  // Draw detection highlights
  for (const d of S.dets) {
    if (d.start < pg.gStart || d.start >= pg.gEnd) continue;
    const ls = d.start - pg.gStart, le = d.end - pg.gStart;
    const hits = (pg.tmap || []).filter(t => t.localStart < le && t.localEnd > ls);
    if (!hits.length) continue;

    const cat = CAT[d.category] || CAT.identity;
    ctx.save();
    ctx.fillStyle = cat.bg.replace('0.15', '0.35');
    ctx.strokeStyle = cat.border;
    ctx.lineWidth = 2;
    for (const t of hits) {
      const rx = t.x * sx, ry = t.y * sy, rw = t.w * sx, rh = t.h * sy;
      ctx.fillRect(rx, ry, rw, rh);
      ctx.strokeRect(rx, ry, rw, rh);
    }
    ctx.restore();
  }

  // Draw QR highlights
  if (pg.qrCodes) {
    for (const qr of pg.qrCodes) {
      if (!qr.loc) continue;
      const pts = [qr.loc.topLeftCorner, qr.loc.topRightCorner, qr.loc.bottomRightCorner, qr.loc.bottomLeftCorner];
      ctx.save();
      ctx.strokeStyle = '#ff4757';
      ctx.lineWidth = 3;
      ctx.setLineDash([6, 3]);
      ctx.beginPath();
      ctx.moveTo(pts[0].x * sx, pts[0].y * sy);
      for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x * sx, pts[i].y * sy);
      ctx.closePath();
      ctx.stroke();
      ctx.restore();
    }
  }

  wrap.appendChild(c);
}

function renderTextView(wrap, pg) {
  const text = pg.text;
  let html = '';
  let cursor = 0;
  const pageDets = [...S.dets].filter(d => d.start >= pg.gStart && d.start < pg.gEnd)
    .sort((a, b) => a.start - b.start);

  for (const d of pageDets) {
    const ls = d.start - pg.gStart;
    const le = d.end - pg.gStart;
    if (ls > cursor) html += esc(text.substring(cursor, ls));
    const cat = CAT[d.category] || CAT.identity;
    html += `<mark style="background:${cat.bg};border-bottom:2px solid ${cat.border};padding:1px 2px;border-radius:3px" title="${d.label} (${Math.round(d.confidence*100)}%)">${esc(text.substring(ls, le))}</mark>`;
    cursor = le;
  }
  if (cursor < text.length) html += esc(text.substring(cursor));

  const div = document.createElement('div');
  div.className = 'text-view';
  div.innerHTML = `<pre>${html}</pre>`;
  wrap.appendChild(div);
}

// ======================== ACTIONS ========================
function onAction(a, el) {
  switch (a) {
    case 'prevPage': go({ page: Math.max(0, S.page - 1) }); break;
    case 'nextPage': go({ page: Math.min(S.doc.pages.length - 1, S.page + 1) }); break;
    case 'setMode':  go({ mode: el.value }); break;
    case 'itemMode': {
      const id = el.dataset.id;
      S.itemMode[id] = el.value;
      break; // no full re-render needed
    }
    case 'export': doExport(); break;
    case 'download': downloadBlob(); break;
    case 'downloadTokens': doTokenExport(); break;
    case 'restart': location.reload(); break;
    case 'loadDemo': loadDemo(); break;
  }
}

// ======================== DEMO LOADER ========================
async function loadDemo() {
  try {
    const resp = await fetch('/samples/sample-sensitive.txt');
    const text = await resp.text();
    const file = new File([text], 'sample-sensitive.txt', { type: 'text/plain' });
    await handleFile(file);
  } catch (e) {
    alert('Could not load demo file: ' + e.message);
  }
}

// ======================== FILE HANDLING ========================
async function handleFile(file) {
  if (!file) return;
  go({ view: 'processing', file, msg: 'Reading file…' });

  try {
    const doc = await processFile(file, m => { S.msg = m; render(); });
    const dets = detectSensitiveInfo(doc.fullText);
    const risk = assessReidentificationRisk(doc.fullText, dets);

    // Also detect in QR code data
    if (doc.qrCodes) {
      for (const qr of doc.qrCodes) {
        const qrDets = detectSensitiveInfo(qr.data);
        for (const d of qrDets) {
          d.label += ' (from QR)';
          d.severity = 'critical';
          dets.push(d);
        }
      }
    }

    go({ view: 'review', doc, dets, risk, page: 0, itemMode: {} });
  } catch (e) {
    console.error(e);
    go({ view: 'upload', msg: '' });
    alert('Error processing file: ' + e.message);
  }
}

// ======================== EXPORT ========================
async function doExport() {
  const canaryIn = document.getElementById('canaryIn');
  const canary = canaryIn ? canaryIn.value.trim() : '';
  go({ view: 'exporting', msg: 'Applying redactions…', canary });

  try {
    let blob, tokenMap;

    if (S.doc.type === 'pdf') {
      S.msg = 'Building redacted PDF (image-only, zero text layer)…';
      render();
      const r = await exportPDF(S.doc.pages, S.dets, S.itemMode, S.mode, canary);
      blob = r.blob;
      tokenMap = r.tokenMap;
    } else if (S.doc.type === 'image') {
      S.msg = 'Redacting image…';
      render();
      const r = await exportImage(S.doc.pages[0], S.dets, S.itemMode, S.mode, canary);
      blob = r.blob;
      tokenMap = r.tokenMap;
    } else {
      S.msg = 'Redacting text…';
      render();
      const r = redactText(S.doc.fullText, S.dets, S.itemMode, S.mode);
      blob = new Blob([r.text], { type: 'text/plain' });
      tokenMap = r.tokenMap;
    }

    S.msg = 'Running red-team self-audit…';
    render();
    const audit = await runAudit(blob, S.doc.type, S.dets, m => { S.msg = m; render(); });

    go({ view: 'audit', blob, tokenMap, audit });
  } catch (e) {
    console.error(e);
    go({ view: 'review', msg: '' });
    alert('Export failed: ' + e.message);
  }
}

function downloadBlob() {
  if (!S.blob) return;
  const ext = S.doc.type === 'pdf' ? 'pdf' : S.doc.type === 'image' ? 'png' : 'txt';
  const name = S.file.name.replace(/\.[^.]+$/, '') + '_redacted.' + ext;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(S.blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function doTokenExport() {
  if (!S.tokenMap || !S.tokenMap.size) return;
  showPasswordModal(async (pw) => {
    const blob = await exportTokenKey(S.tokenMap, pw || '');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'redactshield_token_key' + (pw ? '.encrypted' : '') + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });
}

function showPasswordModal(onConfirm) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-box">
      <h3>🔐 Encrypt Token Key</h3>
      <p>Enter a password to encrypt the token key.<br>Leave blank for plaintext export.</p>
      <input type="password" id="modalPw" class="modal-input" placeholder="Password (optional)" autofocus>
      <div class="modal-btns">
        <button class="btn btn-s" id="modalCancel">Cancel</button>
        <button class="btn btn-p btn-s" id="modalOk">Export</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  const inp = overlay.querySelector('#modalPw');
  inp.focus();
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') overlay.querySelector('#modalOk').click(); });
  overlay.querySelector('#modalCancel').addEventListener('click', () => overlay.remove());
  overlay.querySelector('#modalOk').addEventListener('click', () => {
    const pw = inp.value;
    overlay.remove();
    onConfirm(pw);
  });
}

// ======================== HELPERS ========================
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function groupBy(arr, key) { const m = {}; for (const x of arr) { (m[x[key]] ??= []).push(x); } return m; }
function modeLabel(m) {
  return { blackout: '█ Hard Blackout', mask: '\u{1F3AD} Partial Mask', token: '\u{1F3F7} Token/Decoy', ignore: '\u{1F441} Leave As-Is' }[m] || m;
}

// ======================== START ========================
document.addEventListener('DOMContentLoaded', init);
