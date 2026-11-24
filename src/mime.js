// A small, dependency free MIME parser (RFC 5322 / 2045 / 2047 / 2231).
// Works on a "binary string" where every char is one byte, so attachments survive intact.

import { latin1, toBytes, decodeText, b64ToBytes, splitOutside } from './util.js';

const MAX_DEPTH = 20;

export function splitHeaderBody(raw) {
  const m = /\r?\n\r?\n/.exec(raw);
  if (!m) return { head: raw, body: '' };
  return { head: raw.slice(0, m.index), body: raw.slice(m.index + m[0].length) };
}

export function decodeEncodedWords(s) {
  const EW = /=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g;
  // Whitespace between two encoded words is not part of the text (RFC 2047 section 6.2).
  s = s.replace(/(=\?[^?\s]+\?[BbQq]\?[^?]*\?=)\s+(?==\?[^?\s]+\?[BbQq]\?[^?]*\?=)/g, '$1');
  return s.replace(EW, (_m, cs, enc, txt) => {
    const charset = cs.split('*')[0];
    let bytes;
    if (enc.toUpperCase() === 'B') bytes = b64ToBytes(txt);
    else {
      bytes = toBytes(
        txt.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_x, h) => String.fromCharCode(parseInt(h, 16)))
      );
    }
    return decodeText(bytes, charset);
  });
}

export function decodeHeaderValue(raw) {
  // Raw 8 bit header bytes are most often UTF-8 (RFC 6532).
  const asUtf8 = /[\x80-\xff]/.test(raw) ? decodeText(toBytes(raw), 'utf-8') : raw;
  return decodeEncodedWords(asUtf8);
}

export function parseHeaderBlock(head) {
  const lines = head.split(/\r?\n/);
  const out = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line)) {
      if (out.length) out[out.length - 1].raw += ' ' + line.trim();
      continue;
    }
    const i = line.indexOf(':');
    if (i > 0) out.push({ name: line.slice(0, i).trim(), raw: line.slice(i + 1).trim() });
  }
  return out.map((h) => ({ name: h.name, key: h.name.toLowerCase(), raw: h.raw, value: decodeHeaderValue(h.raw) }));
}

function pctBytes(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) {
      out.push(parseInt(s.substr(i + 1, 2), 16));
      i += 2;
    } else out.push(s.charCodeAt(i) & 0xff);
  }
  return out;
}

// Parses "type/sub; a=b; c*=utf-8''x" style header values.
export function parseStructured(rawValue) {
  const parts = splitOutside(rawValue || '', ';');
  const main = (parts.shift() || '').trim().toLowerCase();
  const plain = {};
  const extended = {};
  for (const p of parts) {
    const i = p.indexOf('=');
    if (i < 0) continue;
    const k = p.slice(0, i).trim().toLowerCase();
    let v = p.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) v = v.slice(1, -1).replace(/\\(.)/g, '$1');
    if (!k.includes('*')) { plain[k] = decodeHeaderValue(v); continue; }
    const seg = k.split('*');
    const name = seg[0];
    const idx = /^\d+$/.test(seg[1]) ? Number(seg[1]) : 0;
    (extended[name] ||= []).push({ idx, enc: k.endsWith('*'), v });
  }
  const params = { ...plain };
  for (const [name, chunks] of Object.entries(extended)) {
    chunks.sort((a, b) => a.idx - b.idx);
    let charset = 'utf-8';
    const bytes = [];
    chunks.forEach((c, n) => {
      let v = c.v;
      if (c.enc) {
        if (n === 0) {
          const m = /^([^']*)'[^']*'(.*)$/.exec(v);
          if (m) { charset = m[1] || 'utf-8'; v = m[2]; }
        }
        bytes.push(...pctBytes(v));
      } else {
        bytes.push(...toBytes(v));
      }
    });
    params[name] = decodeText(Uint8Array.from(bytes), charset);
  }
  return { value: main, params };
}

export function qpDecode(str) {
  const s = str.replace(/=\r?\n/g, '');
  const out = new Uint8Array(s.length);
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 61 && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) {
      out[n++] = parseInt(s.substr(i + 1, 2), 16);
      i += 2;
    } else out[n++] = c & 0xff;
  }
  return out.subarray(0, n);
}

export function decodeTransfer(body, cte) {
  if (cte === 'base64') return b64ToBytes(body);
  if (cte === 'quoted-printable') return qpDecode(body);
  return toBytes(body);
}

export function splitMultipart(body, boundary) {
  const delim = '--' + boundary;
  const lines = body.split(/\r?\n/);
  const parts = [];
  let cur = null;
  for (const line of lines) {
    if (line.startsWith(delim)) {
      const rest = line.slice(delim.length);
      if (rest.startsWith('--')) {
        if (cur) parts.push(cur);
        cur = null;
        break;
      }
      if (/^\s*$/.test(rest)) {
        if (cur) parts.push(cur);
        cur = [];
        continue;
      }
    }
    if (cur) cur.push(line);
  }
  if (cur) parts.push(cur);
  return parts.map((p) => p.join('\r\n'));
}

export function parseEntity(raw, depth = 0) {
  const { head, body } = splitHeaderBody(raw);
  const headers = parseHeaderBlock(head);
  const get = (k) => headers.find((h) => h.key === k);
  const ctH = get('content-type');
  const ct = ctH ? parseStructured(ctH.raw) : { value: 'text/plain', params: {} };
  if (!ct.value.includes('/')) ct.value = 'text/plain';
  const cdH = get('content-disposition');
  const cd = cdH ? parseStructured(cdH.raw) : { value: '', params: {} };
  const cte = (get('content-transfer-encoding')?.raw || '7bit').trim().toLowerCase();

  const node = {
    headers,
    contentType: ct.value,
    params: ct.params,
    disposition: cd.value,
    filename: cd.params.filename || ct.params.name || '',
    contentId: (get('content-id')?.raw || '').replace(/[<>]/g, ''),
    transferEncoding: cte,
    children: [],
    bytes: null,
    text: null,
  };

  if (node.contentType.startsWith('multipart/') && ct.params.boundary && depth < MAX_DEPTH) {
    node.children = splitMultipart(body, ct.params.boundary).map((p) => parseEntity(p, depth + 1));
  } else {
    node.bytes = decodeTransfer(body, cte);
    if (node.contentType.startsWith('text/')) node.text = decodeText(node.bytes, ct.params.charset || 'utf-8');
  }
  return node;
}

export function parseEmail(bytes) {
  let raw = latin1(bytes);
  raw = raw.replace(/^\xEF\xBB\xBF/, '');
  if (/^From [^\r\n]*\r?\n/.test(raw)) raw = raw.replace(/^From [^\r\n]*\r?\n/, ''); // mbox separator
  raw = raw.replace(/^\s+/, '');
  return parseEntity(raw);
}

export function leaves(node, out = []) {
  if (!node.children.length) out.push(node);
  else node.children.forEach((c) => leaves(c, out));
  return out;
}

export function parseAddress(s) {
  s = String(s || '').trim();
  let name = '';
  let address = '';
  const m = /^(.*?)<\s*([^<>]*?)\s*>\s*$/.exec(s);
  if (m) {
    name = m[1].trim().replace(/^"([\s\S]*)"$/, '$1').replace(/\\(.)/g, '$1').trim();
    address = m[2];
  } else {
    const e = /[^\s<>"(),;:]+@[^\s<>"(),;]+/.exec(s);
    address = e ? e[0] : '';
    name = e ? s.replace(e[0], '').replace(/[()"]/g, '').trim() : s;
  }
  address = address.replace(/^mailto:/i, '').trim().toLowerCase();
  const at = address.lastIndexOf('@');
  const domain = at > 0 ? address.slice(at + 1).replace(/[>\].\s]+$/, '') : '';
  return { name, address, local: at > 0 ? address.slice(0, at) : '', domain };
}

export function parseAddressList(value) {
  if (!value) return [];
  return splitOutside(value, ',')
    .map((x) => parseAddress(x))
    .filter((a) => a.address || a.name);
}

export { latin1 };
