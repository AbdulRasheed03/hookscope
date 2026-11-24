// Lightweight HTML scanner. It never renders anything; it only reads tags and text with regexes,
// which is enough to pull out links, forms and tricks used in phishing emails.

const NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®', hellip: '…', ndash: '-', mdash: '-', rsquo: "'", lsquo: "'", rdquo: '"', ldquo: '"', zwnj: '', zwj: '', shy: '' };

export function decodeEntities(s) {
  return String(s).replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (m, e) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try { return String.fromCodePoint(cp); } catch { return m; }
    }
    const v = NAMED[e.toLowerCase()];
    if (v === undefined) return m;
    if (!m.endsWith(';') && !['amp', 'lt', 'gt', 'quot', 'nbsp'].includes(e.toLowerCase())) return m;
    return v;
  });
}

export function parseAttrs(s) {
  const out = {};
  const re = /([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m;
  while ((m = re.exec(s))) {
    const k = m[1].toLowerCase();
    if (!(k in out)) out[k] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  }
  return out;
}

export function htmlToText(html) {
  return decodeEntities(
    String(html)
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(script|style|head|title)\b[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<(br|\/p|\/div|\/tr|\/li|\/h\d|\/table)\b[^>]*>/gi, '\n')
      .replace(/<[^>]+>/g, ' ')
  )
    .replace(/[​-‍﻿]/g, '')
    .replace(/[ \t ]+/g, ' ')
    .replace(/\s*\n\s*/g, '\n')
    .trim();
}

const HIDDEN_STYLE = /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|$|!)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|max-height\s*:\s*0(?:px)?\s*(?:;|$)|color\s*:\s*transparent\b)/i;

export function scanHtml(html) {
  const clean = String(html || '').replace(/<!--[\s\S]*?-->/g, '');
  const res = {
    anchors: [], urls: [], forms: [], passwordInputs: 0, scripts: 0, iframes: 0, metaRefresh: [],
    images: 0, trackingPixels: 0, hiddenText: [], eventHandlers: 0, baseHref: '', text: '',
  };
  const addUrl = (u, where) => { if (u) res.urls.push({ url: u.trim(), where }); };

  const aRe = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
  let m;
  while ((m = aRe.exec(clean))) {
    const at = parseAttrs(m[1]);
    const href = (at.href || '').trim();
    const text = htmlToText(m[2]).replace(/\s+/g, ' ').trim();
    res.anchors.push({ href, text, title: at.title || '' });
    addUrl(href, 'link');
  }

  const tagRe = /<(form|input|script|iframe|frame|meta|img|embed|object|base|button|area|link|svg)\b([^>]*)>/gi;
  while ((m = tagRe.exec(clean))) {
    const tag = m[1].toLowerCase();
    const at = parseAttrs(m[2]);
    if (tag === 'form') { res.forms.push({ action: at.action || '', method: (at.method || 'get').toLowerCase() }); addUrl(at.action, 'form'); }
    else if (tag === 'input' && (at.type || '').toLowerCase() === 'password') res.passwordInputs++;
    else if (tag === 'script') { res.scripts++; addUrl(at.src, 'script'); }
    else if (tag === 'iframe' || tag === 'frame') { res.iframes++; addUrl(at.src, 'iframe'); }
    else if (tag === 'meta' && /refresh/i.test(at['http-equiv'] || '')) {
      const u = /url\s*=\s*['"]?([^'";]+)/i.exec(at.content || '');
      res.metaRefresh.push(u ? u[1] : at.content || '');
      if (u) addUrl(u[1], 'meta-refresh');
    } else if (tag === 'img') {
      res.images++;
      const w = parseInt(at.width, 10);
      const hgt = parseInt(at.height, 10);
      if ((w <= 1 && hgt <= 1) || /width\s*:\s*[01]px/i.test(at.style || '')) res.trackingPixels++;
    } else if (tag === 'base') { res.baseHref = at.href || ''; addUrl(at.href, 'base'); }
    else if (tag === 'area') addUrl(at.href, 'link');
    else if (tag === 'embed' || tag === 'object') addUrl(at.src || at.data, 'object');
    if (Object.keys(at).some((k) => /^on[a-z]+$/.test(k))) res.eventHandlers++;
  }

  // Elements styled to be invisible that still carry text (used to confuse spam filters).
  const hidRe = /<(\w+)\b([^>]*\bstyle\s*=\s*(?:"[^"]*"|'[^']*')[^>]*)>([^<]{4,})/gi;
  while ((m = hidRe.exec(clean))) {
    const at = parseAttrs(m[2]);
    if (HIDDEN_STYLE.test(at.style || '')) {
      const t = decodeEntities(m[3]).trim();
      if (t.length >= 4) res.hiddenText.push(t.slice(0, 120));
    }
  }

  res.text = htmlToText(clean);
  // Bare URLs that appear as text inside the HTML.
  for (const u of extractUrls(res.text)) addUrl(u, 'text');
  return res;
}

export function extractUrls(text) {
  const out = [];
  const re = /\b(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"'`{}|\\^]+/gi;
  let m;
  while ((m = re.exec(String(text || '')))) out.push(m[0].replace(/[),.;:!?'"\]>]+$/, ''));
  return out;
}

// Signs that an HTML or SVG file is built to drop a file or steal a password.
export const SMUGGLING_RULES = [
  { re: /\batob\s*\(/i, label: 'Decodes hidden Base64 data with atob()', w: 1 },
  { re: /new\s+Blob\s*\(/i, label: 'Builds a file in memory with new Blob()', w: 1 },
  { re: /URL\.createObjectURL/i, label: 'Turns in-memory data into a downloadable link', w: 1 },
  { re: /msSaveOrOpenBlob|navigator\.msSaveBlob/i, label: 'Forces a save dialog (old Edge / IE trick)', w: 1 },
  { re: /\.download\s*=|\bdownload\s*=\s*["']/i, label: 'Sets a download file name from script', w: 1 },
  { re: /\.click\s*\(\s*\)/i, label: 'Clicks a link automatically from script', w: 1 },
  { re: /document\.write\s*\(\s*(unescape|decodeURIComponent|atob|window\.atob)/i, label: 'Writes decoded content into the page', w: 1 },
  { re: /\beval\s*\(/i, label: 'Runs code from a string with eval()', w: 1 },
  { re: /String\.fromCharCode\s*\(/i, label: 'Builds text from character codes (obfuscation)', w: 1 },
  { re: /[A-Za-z0-9+/]{3000,}={0,2}/, label: 'Contains a very large Base64 blob', w: 1 },
  { re: /\bfetch\s*\(|XMLHttpRequest|\$\.(ajax|post)\s*\(/i, label: 'Sends network requests from the file', w: 1 },
  { re: /window\.location(\.href)?\s*=|location\.replace\s*\(/i, label: 'Redirects the browser to another site', w: 1 },
];

export function scanActiveContent(src) {
  const hits = SMUGGLING_RULES.filter((r) => r.re.test(src)).map((r) => r.label);
  const telegram = /api\.telegram\.org\/bot/i.test(src);
  const discordHook = /discord(?:app)?\.com\/api\/webhooks/i.test(src);
  return { hits, telegram, discordHook };
}
