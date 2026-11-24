// HookScope engine: takes the raw bytes of an .eml file and returns a full report object.
// Runs the same way in the browser and in Node.js. No network calls.

import { parseEmail, leaves, latin1 } from './mime.js';
import { analyzeHeaders } from './headers.js';
import { scanHtml, extractUrls } from './html.js';
import { analyzeUrl, hostShownInText, isBenignInfraHost } from './urls.js';
import { analyzeAttachment } from './attachments.js';
import { analyzeContent } from './content.js';
import { registrableDomain, officialBrand, FREEMAIL, SHORTENERS } from './domains.js';
import { digest, isIP, isPrivateIP, uniq } from './util.js';

export const VERSION = '1.0.0';

export const SEVERITY = {
  critical: { weight: 40, rank: 4 },
  high: { weight: 25, rank: 3 },
  medium: { weight: 12, rank: 2 },
  low: { weight: 5, rank: 1 },
  info: { weight: 0, rank: 0 },
};

export function verdictFor(score) {
  if (score >= 70) return { level: 'malicious', label: 'Phishing / malicious' };
  if (score >= 40) return { level: 'likely', label: 'Likely phishing' };
  if (score >= 15) return { level: 'suspicious', label: 'Suspicious' };
  return { level: 'low', label: 'Low risk' };
}

function toBytesInput(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof input === 'string') return new TextEncoder().encode(input);
  throw new TypeError('analyzeEmail expects a Uint8Array, ArrayBuffer or string');
}

export async function analyzeEmail(input, opts = {}) {
  const depth = opts.depth || 0;
  const bytes = toBytesInput(input);
  const started = Date.now();
  const root = parseEmail(bytes);
  const findings = [];
  const add = (f) => findings.push({ evidence: [], mitre: '', detail: '', ...f });

  const hdr = analyzeHeaders(root, add);

  // Split the MIME tree into body text, HTML, attachments and attached emails.
  const textParts = [];
  const htmlParts = [];
  const attachNodes = [];
  const nestedNodes = [];
  for (const n of leaves(root)) {
    const ct = n.contentType;
    const named = !!n.filename;
    const isAttachment = n.disposition === 'attachment';
    if (ct === 'message/rfc822' || /\.eml$/i.test(n.filename)) { nestedNodes.push(n); attachNodes.push(n); continue; }
    if (ct.startsWith('multipart/')) continue;
    if (!named && !isAttachment && ct === 'text/plain') { textParts.push(n.text || ''); continue; }
    if (!named && !isAttachment && ct === 'text/html') { htmlParts.push(n.text || ''); continue; }
    attachNodes.push(n);
  }

  const html = scanHtml(htmlParts.join('\n'));
  const plain = textParts.join('\n\n');
  const bodyText = plain || html.text;

  // Links.
  const urlMap = new Map();
  const addUrl = (raw, source) => {
    if (!raw || /^(mailto|tel|sms|cid|about):/i.test(raw) || raw.startsWith('#')) return;
    const a = analyzeUrl(raw);
    if (!a.valid || a.skip) return;
    if (a.host && isBenignInfraHost(a.host)) return;
    const key = a.url;
    if (!urlMap.has(key)) urlMap.set(key, { ...a, sources: [], shownAs: [] });
    const rec = urlMap.get(key);
    if (!rec.sources.includes(source)) rec.sources.push(source);
  };
  extractUrls(plain).forEach((u) => addUrl(u, 'text body'));
  html.urls.forEach((u) => addUrl(u.url, u.where === 'text' ? 'html text' : 'html ' + u.where));

  // Link text that shows one website but opens another.
  const mismatches = [];
  for (const a of html.anchors) {
    if (!a.href || /^(mailto|tel|#)/i.test(a.href)) continue;
    const shown = hostShownInText(a.text);
    if (!shown) continue;
    const real = analyzeUrl(a.href);
    if (!real.valid || !real.host) continue;
    if (registrableDomain(shown) !== registrableDomain(real.host)) {
      mismatches.push(`shows "${a.text}" but opens ${real.host}`);
      const rec = urlMap.get(real.url);
      if (rec) rec.shownAs.push(a.text);
    }
  }
  if (mismatches.length) {
    add({ id: 'link-mismatch', category: 'Links', sev: 'high', title: 'Link text shows one website but opens a different one', detail: 'The address you can see is not where the link really goes.', evidence: uniq(mismatches).slice(0, 8), mitre: 'T1566.002' });
  }

  // Attachments.
  const attachments = [];
  for (const n of attachNodes) {
    const att = await analyzeAttachment(n);
    attachments.push(att);
    att.urls.forEach((u) => addUrl(u, 'attachment: ' + att.filename));
  }
  for (const att of attachments) {
    for (const f of att.flags) {
      add({ id: 'att', category: 'Attachments', sev: f.sev, title: f.title, detail: f.detail && f.detail !== att.filename ? `${att.filename}: ${f.detail}` : att.filename, evidence: [att.sha256], mitre: f.mitre || 'T1566.001' });
    }
  }

  const urls = [...urlMap.values()];
  // One finding per kind of link problem, listing the links.
  const byFlag = new Map();
  for (const u of urls) {
    for (const f of u.flags) {
      if (!byFlag.has(f.id)) byFlag.set(f.id, { flag: f, items: [] });
      byFlag.get(f.id).items.push(f.note ? `${u.url}  (${f.note})` : u.url);
    }
  }
  for (const { flag, items } of byFlag.values()) {
    add({ id: 'url-' + flag.id, category: 'Links', sev: flag.sev, title: flag.title, detail: `${items.length} link(s)`, evidence: items.slice(0, 8), mitre: 'T1566.002' });
  }

  // HTML body tricks.
  if (html.passwordInputs || html.forms.length) {
    add({ id: 'body-form', category: 'Content', sev: html.passwordInputs ? 'critical' : 'high', title: html.passwordInputs ? 'The email itself contains a password box' : 'The email contains a form that sends data somewhere', detail: html.forms.map((f) => f.action || '(no action)').join(', '), mitre: 'T1056.003' });
  }
  if (html.scripts) add({ id: 'body-script', category: 'Content', sev: 'medium', title: 'The email contains JavaScript', detail: `${html.scripts} script tag(s). Real mail apps block this, so it is unusual to send it.` });
  if (html.iframes) add({ id: 'body-iframe', category: 'Content', sev: 'medium', title: 'The email embeds another web page (iframe)', detail: `${html.iframes} frame(s)` });
  if (html.metaRefresh.length) add({ id: 'body-refresh', category: 'Content', sev: 'medium', title: 'The email tries to redirect automatically', detail: html.metaRefresh.join(', ') });
  if (html.hiddenText.length) {
    add({ id: 'hidden-text', category: 'Content', sev: html.hiddenText.length >= 3 ? 'medium' : 'low', title: 'Contains hidden text', detail: 'Invisible text is often used to fool spam filters. Newsletters also use it for preview text, so it is a weak sign on its own.', evidence: html.hiddenText.slice(0, 5) });
  }
  if (htmlParts.length && html.images >= 1 && html.text.replace(/\s+/g, '').length < 40 && !plain.trim()) {
    add({ id: 'image-only', category: 'Content', sev: 'low', title: 'The email is mostly a picture with almost no text', detail: 'Putting the message inside an image hides the words from spam filters.' });
  }

  // Wording.
  const subjectAndBody = `${hdr.subject}\n${bodyText}`;
  for (const g of analyzeContent(subjectAndBody)) {
    add({ id: 'words-' + g.id, category: 'Content', sev: g.sev, title: g.title, detail: `Found: ${g.found.slice(0, 6).map((w) => `"${w}"`).join(', ')}` });
  }
  if (findings.some((f) => f.id === 'words-credentials') && urls.some((u) => u.flags.some((f) => ['lookalike', 'brand-keyword', 'free-hosting', 'shortener', 'ip-host'].includes(f.id)))) {
    add({ id: 'combo-credential-link', category: 'Content', sev: 'high', title: 'Asks you to log in and links to a website that is not the real one', detail: 'This is the classic shape of a credential phishing email.', mitre: 'T1566.002' });
  }

  // Attached emails (for example, a user reporting phishing with "forward as attachment").
  const nested = [];
  if (depth < 3) {
    for (const n of nestedNodes) {
      try {
        nested.push(await analyzeEmail(n.bytes, { depth: depth + 1 }));
      } catch { /* ignore broken inner email */ }
    }
  }

  // Score.
  findings.sort((a, b) => SEVERITY[b.sev].rank - SEVERITY[a.sev].rank);
  const score = Math.min(100, findings.reduce((s, f) => s + SEVERITY[f.sev].weight, 0));
  const nestedMax = nested.reduce((m, r) => Math.max(m, r.overallScore), 0);
  const overallScore = Math.max(score, nestedMax);

  const iocs = collectIocs(hdr, urls, attachments);
  const tactics = uniq(findings.map((f) => f.mitre)).sort();

  return {
    tool: 'HookScope',
    version: VERSION,
    analyzedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    size: bytes.length,
    sha256: await digest('SHA-256', bytes),
    score,
    overallScore,
    verdict: verdictFor(score),
    overallVerdict: verdictFor(overallScore),
    counts: countBySev(findings),
    findings,
    positives: hdr.positives,
    summary: {
      subject: hdr.subject,
      from: hdr.from,
      replyTo: hdr.replyTo,
      returnPath: hdr.returnPath,
      to: hdr.to,
      cc: hdr.cc,
      date: hdr.date,
      messageId: hdr.messageId,
      mailer: hdr.mailer,
      originIp: hdr.originIp,
      fromFreemail: hdr.fromFreemail,
    },
    auth: hdr.auth,
    hops: hdr.hops,
    urls,
    attachments,
    body: { text: bodyText.slice(0, 200000), html: htmlParts.join('\n').slice(0, 400000), hasHtml: htmlParts.length > 0 },
    headers: root.headers.map((h) => ({ name: h.name, value: h.value })),
    mitre: tactics,
    iocs,
    nested,
  };
}

function countBySev(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => { c[f.sev]++; });
  return c;
}

const INFRA = new Set(['api.telegram.org', 'discord.com', 'discordapp.com']);

function collectIocs(hdr, urls, attachments) {
  const domains = new Set();
  const ips = new Set();
  const emails = new Set();
  const addDomain = (d) => { if (d && !officialBrand(d) && !FREEMAIL.has(d) && !SHORTENERS.has(d) && !INFRA.has(d) && !isIP(d)) domains.add(d); };
  [hdr.from, hdr.replyTo, hdr.returnPath, hdr.sender].forEach((a) => {
    if (a && a.address) emails.add(a.address);
    if (a && a.domain) addDomain(a.domain);
  });
  if (hdr.originIp) ips.add(hdr.originIp);
  hdr.hops.forEach((h) => h.ips.forEach((ip) => { if (!isPrivateIP(ip)) ips.add(ip); }));
  const iocUrls = [];
  for (const u of urls) {
    if (!u.host) continue;
    if (isIP(u.host)) ips.add(u.host);
    else addDomain(u.host);
    if (u.flags.length || !officialBrand(u.host)) iocUrls.push(u.url);
  }
  return {
    emails: [...emails],
    domains: [...domains],
    ips: [...ips],
    urls: uniq(iocUrls),
    hashes: attachments.filter((a) => a.size > 0).map((a) => ({ sha256: a.sha256, sha1: a.sha1, filename: a.filename })),
    subject: hdr.subject,
  };
}

export { latin1 };
