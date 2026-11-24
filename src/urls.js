// Link checks. Each flag explains in plain words why a link looks risky.

import { isIP } from './util.js';
import {
  brandCheck, registrableDomain, toUnicodeHost, isFreeHosting, SHORTENERS, SUSPICIOUS_TLDS, normHost,
} from './domains.js';

const RISKY_DOWNLOAD = /\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|msi|lnk|iso|img|vhdx?|jar|apk|xll|one|cab|appx|msix)(?:$|[?#])/i;
const LOGIN_WORDS = /(log-?in|sign-?in|verify|verif|account|password|passwd|secure|update|banking|wallet|auth|session|confirm|unlock|recover|validate|akaun|sahkan)/i;
const REDIRECT_PARAMS = ['url', 'u', 'q', 'redirect', 'redirect_uri', 'redir', 'next', 'target', 'dest', 'destination', 'continue', 'return', 'returnurl', 'goto', 'link', 'out'];

export const URL_FLAG_INFO = {
  'javascript-uri': { sev: 'high', title: 'Link runs JavaScript instead of opening a page' },
  'data-uri': { sev: 'high', title: 'Link contains a whole page hidden inside it (data: URL)' },
  'userinfo': { sev: 'high', title: "Link uses the '@' trick to hide the real website" },
  'obfuscated-ip': { sev: 'high', title: 'Link uses a disguised IP address' },
  'ip-host': { sev: 'medium', title: 'Link goes to a raw IP address instead of a website name' },
  'lookalike': { sev: 'high', title: 'Link goes to a look-alike of a well known brand' },
  'brand-keyword': { sev: 'medium', title: 'Link uses a brand name inside a domain the brand does not own' },
  'punycode': { sev: 'medium', title: 'Link uses international characters that can imitate normal letters' },
  'telegram': { sev: 'critical', title: 'Link sends data to a Telegram bot (common in phishing kits)' },
  'risky-download': { sev: 'high', title: 'Link downloads a file type that can run code (including Android APK)' },
  'free-hosting': { sev: 'medium', title: 'Link is hosted on a free site builder or file host often abused for phishing' },
  'redirect': { sev: 'medium', title: 'Link bounces through a redirect to another site' },
  'shortener': { sev: 'low', title: 'Link uses a URL shortener that hides the destination' },
  'suspicious-tld': { sev: 'low', title: 'Link uses a domain ending that is popular with scammers' },
  'http-login': { sev: 'low', title: 'Login style link without HTTPS' },
  'deep-subdomain': { sev: 'low', title: 'Link has an unusually long chain of subdomains' },
  'odd-port': { sev: 'low', title: 'Link uses an unusual network port' },
  'ipfs': { sev: 'medium', title: 'Link is hosted on IPFS, which is hard to take down' },
};

const BENIGN_HOSTS = new Set(['www.w3.org', 'w3.org', 'schemas.microsoft.com', 'schemas.openxmlformats.org', 'purl.org', 'ns.adobe.com', 'www.apple.com/dtds']);

export function isBenignInfraHost(host) {
  return BENIGN_HOSTS.has(host);
}

export function analyzeUrl(rawInput) {
  let s = String(rawInput || '').trim().replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.');
  const flags = [];
  const add = (id, note = '') => { if (!flags.some((f) => f.id === id)) flags.push({ id, ...URL_FLAG_INFO[id], note }); };

  if (/^javascript:/i.test(s)) { add('javascript-uri'); return { url: s, scheme: 'javascript', host: '', flags, valid: true }; }
  if (/^data:/i.test(s)) { add('data-uri'); return { url: s.slice(0, 120) + (s.length > 120 ? '...' : ''), scheme: 'data', host: '', flags, valid: true }; }
  if (/^www\./i.test(s)) s = 'http://' + s;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) return { url: s, valid: false, flags };

  const authority = (/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(s) || [])[1] || '';
  if (authority.includes('@')) add('userinfo', authority.split('@')[0]);
  const rawHost = authority.split('@').pop().replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  if (/^\d{8,10}$/.test(rawHost) || /^0x[0-9a-f]+$/i.test(rawHost) || /^(0x[0-9a-f]+|0\d+|\d+)(\.(0x[0-9a-f]+|0\d+|\d+)){1,3}$/i.test(rawHost) && !/^(\d{1,3}\.){3}\d{1,3}$/.test(rawHost)) {
    add('obfuscated-ip', rawHost);
  }

  let u;
  try { u = new URL(s); } catch { return { url: s, valid: false, flags }; }
  const scheme = u.protocol.replace(':', '').toLowerCase();
  if (!['http', 'https', 'ftp'].includes(scheme)) return { url: s, scheme, host: u.hostname, flags: [], valid: true, skip: true };

  const host = normHost(u.hostname);
  const unicodeHost = toUnicodeHost(host);
  const registrable = registrableDomain(host);
  const tld = host.split('.').pop();

  if (isIP(host)) add('ip-host', host);
  if (host.split('.').some((l) => l.startsWith('xn--'))) add('punycode', unicodeHost);
  const bc = brandCheck(host);
  if (bc && (bc.type === 'homoglyph' || bc.type === 'typosquat')) add('lookalike', `imitates ${bc.brand} (${bc.target})`);
  else if (bc && bc.type === 'brand-keyword' && !SHORTENERS.has(host)) add('brand-keyword', `mentions ${bc.brand}`);
  if (host === 'api.telegram.org') add('telegram');
  if (RISKY_DOWNLOAD.test(u.pathname)) add('risky-download', u.pathname.split('/').pop());
  if (isFreeHosting(host)) add('free-hosting', registrable);
  if (/(^|\.)ipfs\.|\/ipfs\/|ipfs\.io|dweb\.link/i.test(host + u.pathname)) add('ipfs');
  if (SHORTENERS.has(host) || SHORTENERS.has(registrable)) add('shortener', host);
  if (SUSPICIOUS_TLDS.has(tld) && !isIP(host)) add('suspicious-tld', '.' + tld);
  if (scheme === 'http' && LOGIN_WORDS.test(host + u.pathname)) add('http-login');
  if (!isIP(host) && host.split('.').length >= 5) add('deep-subdomain', host);
  if (u.port && !['80', '443'].includes(u.port)) add('odd-port', u.port);

  for (const [k, v] of u.searchParams) {
    if (REDIRECT_PARAMS.includes(k.toLowerCase()) && /^(https?:)?\/\//i.test(v)) {
      try {
        const inner = new URL(v.startsWith('//') ? 'http:' + v : v);
        if (registrableDomain(inner.hostname) !== registrable) add('redirect', inner.hostname);
      } catch { /* ignore */ }
    }
  }

  return { url: u.href, scheme, host, unicodeHost, registrable, flags, valid: true, brand: bc?.type === 'official' ? bc.brand : null };
}

// Does the visible text of a link look like a web address? Returns the host it shows.
export function hostShownInText(text) {
  const t = String(text || '').trim().replace(/^[<(\["']+|[>)\]"'.,]+$/g, '');
  if (t.length > 200 || /\s/.test(t)) return null;
  const m = /^(?:https?:\/\/)?((?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,})(?::\d+)?(?:[/?#]\S*)?$/i.exec(t);
  if (!m) return null;
  if (/@/.test(t)) return null;
  return normHost(m[1]);
}
