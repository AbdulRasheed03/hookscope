// Small helpers shared by the browser app and the Node CLI.

export function latin1(bytes) {
  let out = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return out;
}

export function toBytes(str) {
  const b = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) b[i] = str.charCodeAt(i) & 0xff;
  return b;
}

export function decodeText(bytes, charset = 'utf-8') {
  let cs = String(charset || 'utf-8').toLowerCase().trim().replace(/^"|"$/g, '');
  if (cs === 'us-ascii' || cs === 'ascii' || cs === '') cs = 'utf-8';
  try {
    return new TextDecoder(cs).decode(bytes);
  } catch {
    try {
      return new TextDecoder('utf-8').decode(bytes);
    } catch {
      return latin1(bytes);
    }
  }
}

export function b64ToBytes(str) {
  let clean = String(str).replace(/[^A-Za-z0-9+/]/g, '');
  if (clean.length % 4 === 1) clean = clean.slice(0, -1);
  while (clean.length % 4) clean += '=';
  try {
    return toBytes(atob(clean));
  } catch {
    return new Uint8Array(0);
  }
}

export async function digest(alg, bytes) {
  const h = await crypto.subtle.digest(alg, bytes);
  return Array.from(new Uint8Array(h), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function indexOfBytes(hay, needle, from = 0) {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

export function utf16le(str) {
  const b = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) b[i * 2] = str.charCodeAt(i);
  return b;
}

// Split on a separator while ignoring separators inside quotes or angle brackets.
export function splitOutside(str, sep) {
  const out = [];
  let cur = '';
  let q = false;
  let angle = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === '\\' && q) { cur += c + (str[i + 1] || ''); i++; continue; }
    if (c === '"') q = !q;
    else if (!q && c === '<') angle++;
    else if (!q && c === '>') angle = Math.max(0, angle - 1);
    if (c === sep && !q && angle === 0) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

export function isIPv4(s) {
  return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s);
}

export function isIP(s) {
  if (!s) return false;
  if (isIPv4(s)) return true;
  return /^[0-9a-f:]+$/i.test(s) && s.includes(':') && s.split(':').length > 2;
}

export function isPrivateIP(ip) {
  if (isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
}

export function defang(value) {
  return String(value)
    .replace(/^http/i, 'hxxp')
    .replace(/^ftp/i, 'fxp')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}

export function uniq(arr) {
  return [...new Set(arr.filter(Boolean))];
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

export function wordRegex(phrase) {
  const esc = phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp('(^|[^\\p{L}\\p{N}])' + esc + '(?=$|[^\\p{L}\\p{N}])', 'iu');
}
