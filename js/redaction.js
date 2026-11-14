// RedactShield — Redaction Engine
// Four modes: hard blackout (random-padded), partial mask, format-preserving token, ignore
// Exports: flattened image-only PDFs (zero hidden text layer), stripped images, clean text

/* globals PDFLib */

export const MODES = { BLACKOUT: 'blackout', MASK: 'mask', TOKEN: 'token', IGNORE: 'ignore' };

// ==================== MASK HELPERS ====================
function maskValue(det) {
  const v = det.clean;
  switch (det.type) {
    case 'AADHAAR':     return 'XXXX-XXXX-' + v.slice(-4);
    case 'PAN':         return 'XXXXX' + v.slice(5, 9) + 'X';
    case 'CREDIT_CARD': return 'XXXX-XXXX-XXXX-' + v.slice(-4);
    case 'PHONE':       return 'XXXXX-' + v.slice(-5);
    case 'EMAIL': {
      const [u, d] = det.value.split('@');
      return u[0] + '***@' + d;
    }
    case 'BANK_ACCOUNT': return 'X'.repeat(Math.max(0, v.length - 4)) + v.slice(-4);
    case 'UPI': {
      const [u, h] = det.value.split('@');
      return u.slice(0, 2) + '***@' + h;
    }
    default:
      if (v.length <= 4) return '*'.repeat(v.length);
      return v.slice(0, 2) + '*'.repeat(v.length - 4) + v.slice(-2);
  }
}

// ==================== TEXT REDACTION ====================
export function redactText(text, dets, itemModes, globalMode) {
  const tokenMap = new Map();
  let tokenCounter = {};
  const sorted = [...dets].sort((a, b) => b.start - a.start);
  let out = text;

  for (const d of sorted) {
    const mode = itemModes[d.id] || globalMode || MODES.BLACKOUT;
    if (mode === MODES.IGNORE) continue;
    let rep;
    switch (mode) {
      case MODES.BLACKOUT:
        rep = '█'.repeat(d.value.length);
        break;
      case MODES.MASK:
        rep = maskValue(d);
        break;
      case MODES.TOKEN: {
        const cnt = (tokenCounter[d.type] || 0) + 1;
        tokenCounter[d.type] = cnt;
        const tok = `[${d.type}_${cnt}]`;
        tokenMap.set(tok, d.value);
        rep = tok;
        break;
      }
      default: rep = d.value;
    }
    out = out.substring(0, d.start) + rep + out.substring(d.end);
  }
  return { text: out, tokenMap };
}

// ==================== CANVAS REDACTION ====================
export function redactOnCanvas(canvas, tmap, dets, itemModes, globalMode, pageGStart) {
  const ctx = canvas.getContext('2d');
  const tokenMap = new Map();
  let tokenCounter = {};

  for (const d of dets) {
    const mode = itemModes[d.id] || globalMode || MODES.BLACKOUT;
    if (mode === MODES.IGNORE) continue;

    const localS = d.start - pageGStart;
    const localE = d.end - pageGStart;
    const hits = (tmap || []).filter(t => t.localStart < localE && t.localEnd > localS);
    if (!hits.length) continue;

    const minX = Math.min(...hits.map(t => t.x));
    const minY = Math.min(...hits.map(t => t.y));
    const maxX = Math.max(...hits.map(t => t.x + t.w));
    const maxY = Math.max(...hits.map(t => t.y + t.h));

    const padL = 3 + Math.random() * 8;
    const padR = 3 + Math.random() * 8;
    const padT = 2 + Math.random() * 4;
    const padB = 2 + Math.random() * 4;

    if (mode === MODES.BLACKOUT) {
      ctx.fillStyle = '#000';
      ctx.fillRect(minX - padL, minY - padT, (maxX - minX) + padL + padR, (maxY - minY) + padT + padB);
    } else if (mode === MODES.MASK) {
      ctx.fillStyle = '#fff';
      ctx.fillRect(minX - 2, minY - 2, (maxX - minX) + 4, (maxY - minY) + 4);
      ctx.fillStyle = '#111';
      const fs = Math.max(10, (maxY - minY) * 0.75);
      ctx.font = `bold ${fs}px monospace`;
      ctx.fillText(maskValue(d), minX, maxY - 2);
    } else if (mode === MODES.TOKEN) {
      const cnt = (tokenCounter[d.type] || 0) + 1;
      tokenCounter[d.type] = cnt;
      const tok = `[${d.type}_${cnt}]`;
      tokenMap.set(tok, d.value);
      ctx.fillStyle = '#fff';
      ctx.fillRect(minX - 2, minY - 2, (maxX - minX) + 4, (maxY - minY) + 4);
      ctx.fillStyle = '#0055cc';
      const fs = Math.max(10, (maxY - minY) * 0.65);
      ctx.font = `bold ${fs}px monospace`;
      ctx.fillText(tok, minX, maxY - 2);
    }
  }
  return tokenMap;
}

// ==================== QR REDACTION ====================
export function redactQR(canvas, qrCodes) {
  if (!qrCodes || !qrCodes.length) return;
  const ctx = canvas.getContext('2d');
  for (const qr of qrCodes) {
    const loc = qr.loc;
    if (!loc) continue;
    const pts = [loc.topLeftCorner, loc.topRightCorner, loc.bottomRightCorner, loc.bottomLeftCorner];
    const xs = pts.map(p => p.x), ys = pts.map(p => p.y);
    const pad = 10;
    ctx.fillStyle = '#000';
    ctx.fillRect(
      Math.min(...xs) - pad, Math.min(...ys) - pad,
      Math.max(...xs) - Math.min(...xs) + pad * 2,
      Math.max(...ys) - Math.min(...ys) + pad * 2
    );
  }
}

// ==================== EXPORT REDACTED PDF ====================
export async function exportPDF(pages, dets, itemModes, globalMode, canaryText) {
  const { PDFDocument, rgb } = PDFLib;
  const doc = await PDFDocument.create();
  doc.setTitle('');
  doc.setAuthor('');
  doc.setSubject('');
  doc.setKeywords([]);
  doc.setProducer('RedactShield');
  doc.setCreator('RedactShield — Zero Upload');

  const allTokens = new Map();

  for (const pg of pages) {
    const rc = cloneCanvas(pg.canvas);
    const pageDets = dets.filter(d => d.start >= pg.gStart && d.start < pg.gEnd);
    const tokens = redactOnCanvas(rc, pg.tmap, pageDets, itemModes, globalMode, pg.gStart);
    tokens.forEach((v, k) => allTokens.set(k, v));

    if (pg.qrCodes) redactQR(rc, pg.qrCodes);

    if (canaryText) {
      const ctx = rc.getContext('2d');
      ctx.fillStyle = 'rgba(200,200,200,0.08)';
      ctx.font = '9px sans-serif';
      ctx.fillText(canaryText, 10, rc.height - 6);
    }

    const blob = await canvasToBlob(rc, 'image/png');
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const img = await doc.embedPng(bytes);

    const w = pg.w / pg.scale * 72 / 96;
    const h = pg.h / pg.scale * 72 / 96;
    const p = doc.addPage([w, h]);
    p.drawImage(img, { x: 0, y: 0, width: w, height: h });
  }

  const pdfBytes = await doc.save();
  return { blob: new Blob([pdfBytes], { type: 'application/pdf' }), tokenMap: allTokens };
}

// ==================== EXPORT REDACTED IMAGE ====================
export async function exportImage(page, dets, itemModes, globalMode, canaryText) {
  const rc = cloneCanvas(page.canvas);
  const tokens = redactOnCanvas(rc, page.tmap, dets, itemModes, globalMode, page.gStart || 0);
  if (page.qrCodes) redactQR(rc, page.qrCodes);

  if (canaryText) {
    const ctx = rc.getContext('2d');
    ctx.fillStyle = 'rgba(200,200,200,0.08)';
    ctx.font = '9px sans-serif';
    ctx.fillText(canaryText, 10, rc.height - 6);
  }

  const blob = await canvasToBlob(rc, 'image/png');
  return { blob, tokenMap: tokens };
}

// ==================== TOKEN MAP EXPORT ====================
export async function exportTokenKey(tokenMap, password) {
  const obj = Object.fromEntries(tokenMap);
  const json = JSON.stringify(obj, null, 2);
  if (!password) return new Blob([json], { type: 'application/json' });

  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(json));

  return new Blob([JSON.stringify({
    v: 1, alg: 'AES-256-GCM', kdf: 'PBKDF2-SHA256-100k',
    salt: [...salt], iv: [...iv], data: [...new Uint8Array(ct)]
  })], { type: 'application/json' });
}

// ==================== HELPERS ====================
function cloneCanvas(src) {
  const c = document.createElement('canvas');
  c.width = src.width;
  c.height = src.height;
  c.getContext('2d').drawImage(src, 0, 0);
  return c;
}

function canvasToBlob(canvas, type) {
  return new Promise(r => canvas.toBlob(r, type));
}
