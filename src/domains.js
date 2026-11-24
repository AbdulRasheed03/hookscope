// Domain helpers: registrable domain, punycode, look-alike detection, brand list.

import { isIP, levenshtein } from './util.js';

// Two and three label suffixes, plus free hosting platforms where every customer gets a subdomain.
export const FREE_HOSTING = [
  'github.io', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'netlify.app',
  'vercel.app', 'blogspot.com', 'wixsite.com', 'weebly.com', 'glitch.me', 'r2.dev', '000webhostapp.com',
  'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'azurewebsites.net', 'appspot.com', 'square.site', 'webflow.io',
  'replit.app', 'repl.co', 'onrender.com', 'surge.sh', 'framer.app', 'godaddysites.com', 'mystrikingly.com',
  'firebasestorage.googleapis.com', 'storage.googleapis.com', 'ipfs.io', 'dweb.link', 'trycloudflare.com',
  'translate.goog', 'myshopify.com', 'carrd.co', 'notion.site', 'jimdosite.com', 'webcindario.com',
];

const SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my', 'mil.my', 'name.my',
  'biz.my', 'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'co.id', 'go.id', 'ac.id', 'or.id', 'web.id', 'com.ph', 'gov.ph', 'co.th', 'in.th',
  'go.th', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'com.tw', 'co.kr', 'co.in', 'net.in', 'org.in',
  'gov.in', 'com.br', 'com.mx', 'co.nz', 'co.za', 'com.tr', 'com.vn', 'com.pk', 'com.bd', 'com.ng', 'com.eg',
  'com.sa', 'co.il', 's3.amazonaws.com', 'cloudfront.net', ...FREE_HOSTING,
]);

export const FREEMAIL = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.com.my', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com',
  'msn.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com',
  'yandex.com', 'yandex.ru', 'zoho.com', 'tutanota.com', 'mail.ru', 'qq.com', '163.com', '126.com', 'inbox.lv',
]);

export const SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly', 'rebrand.ly', 's.id',
  'shorturl.at', 'rb.gy', 'tiny.cc', 'buff.ly', 'v.gd', 'qrco.de', 'lnkd.in', 't.ly', 'shorte.st', 'adf.ly',
  'bit.do', 'tiny.one', 'urlz.fr', 'clck.ru', 'u.to', 'linktr.ee', 'surl.li', 'wa.link', 'qr.link',
]);

export const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'cam',
  'icu', 'sbs', 'cfd', 'lol', 'monster', 'quest', 'buzz', 'bond', 'cyou', 'shop', 'live', 'online', 'site', 'fun',
  'loan', 'win', 'bid', 'date', 'review', 'kim', 'men', 'party', 'trade', 'webcam', 'stream', 'zone', 'info',
]);

// Brands that phishing in Malaysia and worldwide most often pretends to be.
// keywords shorter than 5 letters only match as a whole word (so "ups" does not match "groups").
export const BRANDS = [
  { name: 'Microsoft', keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'msonline', 'microsoft365'], domains: ['microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'microsoftonline.com', 'sharepoint.com', 'onedrive.com', 'hotmail.com', 'msn.com', 'azure.com', 'windows.net', 'microsoft365.com', 'office.net', 'skype.com'] },
  { name: 'Google', keywords: ['google', 'gmail'], domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'google.com.my', 'googleusercontent.com', 'googleapis.com', 'g.co', 'goo.gl', 'forms.gle', 'gstatic.com'] },
  { name: 'Apple', keywords: ['apple', 'icloud', 'itunes', 'appleid'], domains: ['apple.com', 'icloud.com', 'me.com', 'mzstatic.com'] },
  { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  { name: 'Amazon', keywords: ['amazon'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.sg', 'amazonaws.com', 'amazonses.com', 'media-amazon.com'] },
  { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com', 'nflxext.com'] },
  { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com', 'dhl.com.my', 'dhl.de'] },
  { name: 'FedEx', keywords: ['fedex'], domains: ['fedex.com'] },
  { name: 'UPS', keywords: ['ups'], domains: ['ups.com'] },
  { name: 'DocuSign', keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Dropbox', keywords: ['dropbox'], domains: ['dropbox.com', 'dropboxusercontent.com'] },
  { name: 'Adobe', keywords: ['adobe'], domains: ['adobe.com', 'adobesign.com', 'adobelogin.com'] },
  { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com', 'licdn.com'] },
  { name: 'Facebook', keywords: ['facebook', 'meta'], domains: ['facebook.com', 'fb.com', 'meta.com', 'facebookmail.com', 'fbcdn.net'] },
  { name: 'Instagram', keywords: ['instagram'], domains: ['instagram.com'] },
  { name: 'WhatsApp', keywords: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
  { name: 'Binance', keywords: ['binance'], domains: ['binance.com'] },
  { name: 'Coinbase', keywords: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'WeTransfer', keywords: ['wetransfer'], domains: ['wetransfer.com', 'we.tl'] },
  { name: 'Zoom', keywords: ['zoom'], domains: ['zoom.us', 'zoom.com'] },
  { name: 'Maybank', keywords: ['maybank', 'maybank2u', 'm2u'], domains: ['maybank2u.com.my', 'maybank.com.my', 'maybank.com', 'maybank2u.com.sg'] },
  { name: 'CIMB', keywords: ['cimb', 'cimbclicks', 'cimbbank'], domains: ['cimb.com', 'cimb.com.my', 'cimbclicks.com.my', 'cimbbank.com.my'] },
  { name: 'Public Bank', keywords: ['publicbank', 'pbebank'], domains: ['pbebank.com', 'publicbank.com.my'] },
  { name: 'RHB', keywords: ['rhb', 'rhbbank', 'rhbgroup'], domains: ['rhbgroup.com', 'rhbbank.com.my'] },
  { name: 'Hong Leong Bank', keywords: ['hongleong', 'hlbank', 'hlb'], domains: ['hlb.com.my', 'hongleongconnect.my'] },
  { name: 'AmBank', keywords: ['ambank'], domains: ['ambank.com.my', 'ambankgroup.com'] },
  { name: 'Bank Islam', keywords: ['bankislam'], domains: ['bankislam.com', 'bankislam.com.my'] },
  { name: 'BSN', keywords: ['bsn', 'mybsn'], domains: ['bsn.com.my', 'mybsn.com.my'] },
  { name: 'LHDN', keywords: ['lhdn', 'mytax', 'ezhasil', 'hasilgov'], domains: ['hasil.gov.my'] },
  { name: 'KWSP / EPF', keywords: ['kwsp', 'epf', 'i-akaun'], domains: ['kwsp.gov.my'] },
  { name: 'Pos Malaysia', keywords: ['posmalaysia', 'poslaju'], domains: ['pos.com.my'] },
  { name: 'TNB', keywords: ['tnb', 'mytnb', 'tenaganasional'], domains: ['tnb.com.my', 'mytnb.com.my'] },
  { name: "Touch 'n Go", keywords: ['touchngo', 'tngdigital', 'tngo'], domains: ['touchngo.com.my', 'tngdigital.com.my'] },
  { name: 'Shopee', keywords: ['shopee'], domains: ['shopee.com.my', 'shopee.com', 'shopee.sg', 'shopeemobile.com'] },
  { name: 'Lazada', keywords: ['lazada'], domains: ['lazada.com.my', 'lazada.com'] },
  { name: 'Grab', keywords: ['grab'], domains: ['grab.com'] },
  { name: 'JPJ', keywords: ['jpj', 'mysikap'], domains: ['jpj.gov.my'] },
  { name: 'PDRM', keywords: ['pdrm'], domains: ['rmp.gov.my', 'pdrm.gov.my'] },
  { name: 'MyEG', keywords: ['myeg'], domains: ['myeg.com.my'] },
];

const CONFUSABLE = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'l', 'ј': 'j', 'ԁ': 'd', 'ѕ': 's',
  'һ': 'h', 'ӏ': 'l', 'ɡ': 'g', 'ν': 'v', 'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'l', 'κ': 'k', 'ρ': 'p', 'τ': 't',
  'υ': 'u', 'χ': 'x', 'ⅰ': 'l', 'ı': 'l', 'ł': 'l', 'ɩ': 'l', 'ꞵ': 'b', 'ԛ': 'q', 'ԝ': 'w', 'ү': 'y', 'ｍ': 'm',
  '0': 'o', '1': 'l', 'i': 'l', '|': 'l', '!': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '$': 's', '@': 'a',
};

export function normHost(h) {
  return String(h || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/:\d+$/, '').replace(/\.+$/, '');
}

export function registrableDomain(host) {
  const h = normHost(host);
  if (!h || isIP(h)) return h;
  const labels = h.split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  for (const k of [3, 2]) {
    if (labels.length > k && SUFFIXES.has(labels.slice(-k).join('.'))) return labels.slice(-(k + 1)).join('.');
  }
  return labels.slice(-2).join('.');
}

export function sameOrg(a, b) {
  if (!a || !b) return false;
  return registrableDomain(a) === registrableDomain(b);
}

export function isFreeHosting(host) {
  const h = normHost(host);
  return FREE_HOSTING.some((d) => h === d || h.endsWith('.' + d));
}

// RFC 3492 punycode decoder.
export function punyDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const output = [];
  let i = 0, n = 128, bias = 72;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  const adapt = (delta, numPoints, first) => {
    let k = 0;
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
    return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (c) => (c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base);
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= input.length) throw new Error('bad punycode');
      const d = digit(input.charCodeAt(idx++));
      if (d >= base) throw new Error('bad punycode');
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

export function toUnicodeHost(host) {
  return normHost(host)
    .split('.')
    .map((l) => {
      if (!l.startsWith('xn--')) return l;
      try { return punyDecode(l.slice(4)); } catch { return l; }
    })
    .join('.');
}

export function hasMixedScripts(label) {
  const latin = /[a-z]/i.test(label);
  const cyr = /\p{Script=Cyrillic}/u.test(label);
  const grk = /\p{Script=Greek}/u.test(label);
  return (latin && (cyr || grk)) || (cyr && grk);
}

export function skeleton(s) {
  let out = '';
  const norm = String(s).toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '');
  for (const ch of norm) out += CONFUSABLE[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[-_.]/g, '');
}

function tokens(s) {
  return String(s).toLowerCase().split(/[^a-zÀ-￿]+/).filter(Boolean);
}

export function officialBrand(host) {
  const h = normHost(host);
  for (const b of BRANDS) if (b.domains.some((d) => h === d || h.endsWith('.' + d))) return b;
  return null;
}

// Does this text (display name, link text) claim to be a brand?
export function brandMentioned(text) {
  const joined = String(text).toLowerCase().replace(/[^a-z0-9]/g, '');
  const toks = tokens(text);
  for (const b of BRANDS) {
    const nameKey = b.name.toLowerCase().replace(/[^a-z0-9]/g, '');
    for (const kw of [...b.keywords, nameKey]) {
      const k = kw.replace(/[^a-z0-9]/g, '');
      if (k.length >= 5 ? joined.includes(k) : toks.includes(k)) return b;
    }
  }
  return null;
}

// Check a host name for brand impersonation.
// Returns null, or { brand, type: 'official' | 'homoglyph' | 'typosquat' | 'brand-keyword', target }.
export function brandCheck(host) {
  const h = normHost(host);
  if (!h || isIP(h)) return null;
  const off = officialBrand(h);
  if (off) return { brand: off.name, type: 'official' };
  const reg = registrableDomain(h);
  const regLabelAscii = reg.split('.')[0];
  const regLabel = toUnicodeHost(regLabelAscii);
  const skReg = skeleton(regLabel);
  const uni = toUnicodeHost(h);
  const skHost = skeleton(uni);
  const hostToks = tokens(uni.replace(/\d+/g, ' '));

  for (const b of BRANDS) {
    for (const d of b.domains) {
      const bl = d.split('.')[0];
      if (bl.length < 4) continue;
      const sb = skeleton(bl);
      if (skReg === sb && regLabel !== bl) return { brand: b.name, type: 'homoglyph', target: d };
      if (bl.length >= 6 && Math.abs(regLabel.length - bl.length) <= 1) {
        const dist = levenshtein(skReg, sb);
        if (dist > 0 && dist <= (bl.length >= 9 ? 2 : 1)) return { brand: b.name, type: 'typosquat', target: d };
      }
    }
  }
  for (const b of BRANDS) {
    for (const kw of b.keywords) {
      const hit = kw.length >= 5 ? skHost.includes(skeleton(kw)) : hostToks.includes(kw);
      if (!hit) continue;
      // Matched only after undoing look-alike letters (rn -> m, 0 -> o): that is imitation, not just a mention.
      const literal = kw.length >= 5 ? uni.replace(/[-_.]/g, '').includes(kw) : true;
      return { brand: b.name, type: literal ? 'brand-keyword' : 'homoglyph', target: b.domains[0] };
    }
  }
  return null;
}
