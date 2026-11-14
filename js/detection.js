// RedactShield — Smart Sensitive Information Detection Engine
// Validates with Verhoeff (Aadhaar), Luhn (cards), structure checks (PAN), and context analysis

// ==================== VERHOEFF CHECKSUM ====================
const D = [
  [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],
  [2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
  [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
  [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
  [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]
];
const P = [
  [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],
  [5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
  [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
  [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
];
const INV = [0,4,3,2,1,5,6,7,8,9];

export function verhoeffValidate(num) {
  const digits = String(num).replace(/\D/g, '').split('').map(Number).reverse();
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = D[c][P[i % 8][digits[i]]];
  }
  return c === 0;
}

export function verhoeffGenerate(partialNum) {
  const digits = String(partialNum).replace(/\D/g, '').split('').map(Number).reverse();
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = D[c][P[(i + 1) % 8][digits[i]]];
  }
  return INV[c];
}

// ==================== LUHN CHECKSUM ====================
export function luhnValidate(num) {
  const digits = String(num).replace(/\D/g, '').split('').map(Number).reverse();
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits[i];
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

// ==================== PAN VALIDATION ====================
const PAN_ENTITIES = new Set('ABCFGHLJPT'.split(''));
export function validatePAN(pan) {
  if (!/^[A-Z]{5}\d{4}[A-Z]$/.test(pan)) return false;
  return PAN_ENTITIES.has(pan[3]);
}

// ==================== CONTEXT ANALYSIS ====================
function hasContext(text, index, length, words, window = 300) {
  const lo = Math.max(0, index - window);
  const hi = Math.min(text.length, index + length + window);
  const slice = text.substring(lo, hi).toLowerCase();
  return words.some(w => slice.includes(w));
}

// ==================== PATTERN DEFINITIONS ====================
const PATTERNS = [
  {
    type: 'AADHAAR', label: 'Aadhaar Number',
    category: 'identity', severity: 'critical',
    regex: /\b(\d{4}[\s-]?\d{4}[\s-]?\d{4})\b/g,
    validate(v) {
      const n = v.replace(/[\s-]/g, '');
      if (n.length !== 12 || /^[01]/.test(n)) return false;
      return verhoeffValidate(n);
    },
    ctx: ['aadhaar','uid','uidai','unique identification','enrollment','vid','aadhaar number'],
    ctxReq: false, base: 0.85,
  },
  {
    type: 'PAN', label: 'PAN Card',
    category: 'identity', severity: 'critical',
    regex: /\b([A-Z]{5}\d{4}[A-Z])\b/g,
    validate: validatePAN,
    ctx: ['pan','permanent account','income tax','pan card','pan number','tax id'],
    ctxReq: false, base: 0.80,
  },
  {
    type: 'CREDIT_CARD', label: 'Credit/Debit Card',
    category: 'financial', severity: 'critical',
    regex: /\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4})\b/g,
    validate(v) {
      const n = v.replace(/[\s-]/g, '');
      if (n.length < 13 || n.length > 19 || !/^[3-6]/.test(n)) return false;
      return luhnValidate(n);
    },
    ctx: ['card','credit','debit','visa','mastercard','rupay','cvv','expiry','valid thru'],
    ctxReq: false, base: 0.90,
  },
  {
    type: 'IFSC', label: 'IFSC Code',
    category: 'financial', severity: 'high',
    regex: /\b([A-Z]{4}0[A-Z0-9]{6})\b/g,
    validate: null,
    ctx: ['ifsc','bank','branch','neft','rtgs','imps','account','transfer'],
    ctxReq: false, base: 0.85,
  },
  {
    type: 'BANK_ACCOUNT', label: 'Bank Account Number',
    category: 'financial', severity: 'critical',
    regex: /\b(\d{9,18})\b/g,
    validate(v) {
      const n = v.replace(/\D/g, '');
      return n.length >= 9 && n.length <= 18;
    },
    ctx: ['account','a/c','acc no','bank account','savings','current account','ifsc','branch','bank','credited'],
    ctxReq: true, base: 0.70,
  },
  {
    type: 'UPI', label: 'UPI ID',
    category: 'financial', severity: 'high',
    regex: /\b([a-zA-Z0-9._-]+@[a-z]{2,})\b/g,
    validate(v) {
      const handles = ['okaxis','oksbi','okhdfcbank','ybl','paytm','apl','axisbank',
        'sbi','icici','hdfcbank','ibl','upi','kotak','indus','federal','rbl',
        'barodampay','pnb','idfcfirst','axl','okicici','fam','slice','jupiteraxis'];
      const h = v.split('@')[1];
      return h && handles.includes(h);
    },
    ctx: ['upi','pay','payment','gpay','phonepe','paytm','bhim'],
    ctxReq: false, base: 0.92,
  },
  {
    type: 'PHONE', label: 'Phone Number',
    category: 'contact', severity: 'high',
    regex: /(?:\+91[\s-]?|0)?([6-9]\d{4}[\s-]?\d{5})\b/g,
    validate(v) {
      const n = v.replace(/[\s+\-]/g, '').replace(/^91/, '').replace(/^0/, '');
      return n.length === 10 && /^[6-9]/.test(n);
    },
    ctx: ['phone','mobile','contact','call','whatsapp','tel','mob','number'],
    ctxReq: false, base: 0.75,
  },
  {
    type: 'EMAIL', label: 'Email Address',
    category: 'contact', severity: 'high',
    regex: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
    validate(v) {
      const upi = ['okaxis','oksbi','okhdfcbank','ybl','paytm','apl','axisbank','sbi','icici'];
      const dom = v.split('@')[1]?.toLowerCase();
      return !upi.includes(dom);
    },
    ctx: ['email','mail','e-mail','contact'],
    ctxReq: false, base: 0.90,
  },
  {
    type: 'PASSPORT', label: 'Passport Number',
    category: 'identity', severity: 'critical',
    regex: /\b([A-Z][0-9]{7})\b/g,
    validate: null,
    ctx: ['passport','travel document','immigration','visa','passport number'],
    ctxReq: true, base: 0.60,
  },
  {
    type: 'VOTER_ID', label: 'Voter ID (EPIC)',
    category: 'identity', severity: 'high',
    regex: /\b([A-Z]{3}\d{7})\b/g,
    validate: null,
    ctx: ['voter','epic','election','electoral','voter id','identity card'],
    ctxReq: true, base: 0.65,
  },
  {
    type: 'DL', label: 'Driving License',
    category: 'identity', severity: 'high',
    regex: /\b([A-Z]{2}[\s-]?\d{2}[\s-]?\d{4}[\s-]?\d{7})\b/g,
    validate: null,
    ctx: ['driving','license','licence','dl no','dl number','rto','motor vehicle'],
    ctxReq: true, base: 0.65,
  },
  {
    type: 'DOB', label: 'Date of Birth',
    category: 'quasi_identifier', severity: 'medium',
    regex: /\b(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})\b/g,
    validate(v) {
      const p = v.split(/[/.\-]/);
      if (p.length !== 3) return false;
      const d = +p[0], m = +p[1];
      return d >= 1 && d <= 31 && m >= 1 && m <= 12;
    },
    ctx: ['dob','date of birth','born','birthday','birth date','age','d.o.b'],
    ctxReq: true, base: 0.50,
  },
  {
    type: 'PINCODE', label: 'PIN Code',
    category: 'quasi_identifier', severity: 'low',
    regex: /\b(\d{6})\b/g,
    validate(v) { return +v >= 110000 && +v <= 999999 && v[0] !== '0'; },
    ctx: ['pin','pincode','zip','postal','address','area','pin code','locality'],
    ctxReq: true, base: 0.40,
  },
];

// ==================== MAIN DETECTION ====================
let _id = 0;

export function detectSensitiveInfo(text) {
  if (!text || !text.trim()) return [];
  const results = [];

  for (const pat of PATTERNS) {
    const re = new RegExp(pat.regex.source, pat.regex.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      const full = m[0];
      const val = m[1] || m[0];
      if (pat.validate && !pat.validate(val)) continue;
      const nearby = hasContext(text, m.index, full.length, pat.ctx);
      if (pat.ctxReq && !nearby) continue;

      let conf = pat.base;
      if (nearby) conf = Math.min(1, conf + 0.15);
      if (pat.validate) conf = Math.min(1, conf + 0.05);

      results.push({
        id: `d${++_id}`,
        type: pat.type,
        label: pat.label,
        value: full,
        clean: val.replace(/[\s-]/g, ''),
        start: m.index,
        end: m.index + full.length,
        confidence: conf,
        severity: pat.severity,
        category: pat.category,
      });
    }
  }
  return dedup(results);
}

function dedup(arr) {
  arr.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
  const out = [];
  for (const d of arr) {
    if (!out.some(e => d.start < e.end && d.end > e.start)) out.push(d);
  }
  return out;
}

// ==================== RE-IDENTIFICATION RISK ====================
const GENDER_RE = /\b(male|female|transgender|other)\b/gi;
const RELIGION_RE = /\b(hindu|muslim|christian|sikh|buddhist|jain|parsi)\b/gi;
const CASTE_RE = /\b(general|obc|sc|st|scheduled caste|scheduled tribe|other backward)\b/gi;

export function assessReidentificationRisk(text, detections) {
  const qi = new Set();
  for (const d of detections) {
    if (['DOB', 'PINCODE'].includes(d.type)) qi.add(d.type);
  }
  if (GENDER_RE.test(text)) qi.add('GENDER');
  if (RELIGION_RE.test(text)) qi.add('RELIGION');
  if (CASTE_RE.test(text)) qi.add('CASTE');

  const items = [...qi];
  const level = items.length >= 4 ? 'critical' : items.length >= 3 ? 'high' : items.length >= 2 ? 'medium' : 'low';
  return {
    identifiers: items,
    count: items.length,
    level,
    warning: items.length >= 3
      ? `${items.length} quasi-identifiers (${items.join(', ')}) together can uniquely re-identify a person even without direct IDs.`
      : null,
  };
}
