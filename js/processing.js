// RedactShield — Document Processing Engine
// PDF rendering, OCR (Tesseract.js), and QR detection (jsQR) — all in-browser

/* globals pdfjsLib, Tesseract, jsQR */

if (typeof pdfjsLib !== 'undefined') {
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
}

// ==================== PDF ====================
export async function processPDF(file, onMsg) {
  const buf = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({ data: buf }).promise;
  const pages = [];
  let fullText = '';
  let globalOff = 0;

  for (let i = 1; i <= pdf.numPages; i++) {
    if (onMsg) onMsg(`Rendering page ${i} / ${pdf.numPages}…`);
    const pg = await pdf.getPage(i);
    const scale = 2;
    const vp = pg.getViewport({ scale });
    const canvas = document.createElement('canvas');
    canvas.width = vp.width;
    canvas.height = vp.height;
    await pg.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise;

    const tc = await pg.getTextContent();
    let pageTxt = '';
    const tmap = [];
    let off = 0;

    for (const item of tc.items) {
      const tx = item.transform;
      tmap.push({
        str: item.str,
        x: tx[4] * scale,
        y: (vp.height / scale - tx[5]) * scale - (item.height || 12) * scale,
        w: item.width * scale,
        h: (item.height || 12) * scale,
        localStart: off,
        localEnd: off + item.str.length,
      });
      pageTxt += item.str;
      off += item.str.length;
      if (item.hasEOL) { pageTxt += '\n'; off++; }
    }

    const gStart = globalOff;
    const gEnd = globalOff + pageTxt.length;
    pages.push({ num: i, canvas, text: pageTxt, tmap, w: vp.width, h: vp.height, scale, gStart, gEnd });
    fullText += pageTxt + '\n';
    globalOff = fullText.length;
  }

  return { type: 'pdf', pages, fullText, pageCount: pdf.numPages };
}

// ==================== IMAGE (OCR) ====================
export async function processImage(file, onMsg) {
  const img = await loadImage(file);
  const canvas = document.createElement('canvas');
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);

  let text = '';
  let tmap = [];
  let ocrOk = true;

  if (typeof Tesseract !== 'undefined') {
    try {
      if (onMsg) onMsg('Starting OCR engine…');
      const worker = await Tesseract.createWorker('eng', 1, {
        logger(m) {
          if (m.status === 'recognizing text' && onMsg)
            onMsg(`OCR ${Math.round(m.progress * 100)}%`);
        },
      });
      const { data } = await worker.recognize(canvas);
      await worker.terminate();
      text = data.text || '';

      let off = 0;
      for (const w of (data.words || [])) {
        const b = w.bbox;
        tmap.push({
          str: w.text,
          x: b.x0, y: b.y0,
          w: b.x1 - b.x0,
          h: b.y1 - b.y0,
          localStart: off,
          localEnd: off + w.text.length,
        });
        off += w.text.length + 1;
      }
    } catch (e) {
      console.warn('OCR failed:', e);
      ocrOk = false;
    }
  } else {
    ocrOk = false;
  }

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const qrCodes = scanQR(imageData);

  return {
    type: 'image',
    pages: [{ num: 1, canvas, text, tmap, w: canvas.width, h: canvas.height, scale: 1, gStart: 0, gEnd: text.length, imageData, qrCodes }],
    fullText: text,
    qrCodes,
    ocrOk,
  };
}

// ==================== PLAIN TEXT ====================
export async function processText(file) {
  const text = await file.text();
  return {
    type: 'text',
    pages: [{ num: 1, text, tmap: null, w: 0, h: 0, gStart: 0, gEnd: text.length }],
    fullText: text,
  };
}

// ==================== QR DETECTION ====================
export function scanQR(imageData) {
  if (typeof jsQR === 'undefined') return [];
  const code = jsQR(imageData.data, imageData.width, imageData.height);
  if (!code) return [];
  return [{
    data: code.data,
    loc: code.location,
    warning: 'QR code detected — Aadhaar QR codes embed full name, DOB, gender, and address.',
  }];
}

// ==================== ROUTER ====================
export async function processFile(file, onMsg) {
  const ext = file.name.split('.').pop().toLowerCase();
  if (ext === 'pdf') return processPDF(file, onMsg);
  if (['png','jpg','jpeg','bmp','webp','tiff'].includes(ext)) return processImage(file, onMsg);
  if (['txt','csv','json','xml','html','log','md'].includes(ext)) return processText(file);
  throw new Error(`Unsupported format: .${ext}`);
}

// ==================== HELPERS ====================
function loadImage(file) {
  return new Promise((res, rej) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => { URL.revokeObjectURL(url); res(img); };
    img.onerror = () => { URL.revokeObjectURL(url); rej(new Error('Failed to load image')); };
    img.src = url;
  });
}
