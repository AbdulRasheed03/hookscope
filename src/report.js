// Export helpers: JSON, Markdown report for tickets, and IOC lists.

import { defang } from './util.js';

export function toJson(result, { includeBody = false } = {}) {
  const strip = (r) => ({
    ...r,
    body: includeBody ? r.body : { hasHtml: r.body.hasHtml, textPreview: r.body.text.slice(0, 2000) },
    nested: r.nested.map(strip),
  });
  return JSON.stringify(strip(result), null, 2);
}

const mdEscape = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const addr = (a) => (a ? (a.name ? `${a.name} <${a.address}>` : a.address) : '');

export function toMarkdown(r, level = 1) {
  const h = (n) => '#'.repeat(Math.min(6, level + n - 1));
  const L = [];
  L.push(`${h(1)} HookScope report: ${mdEscape(r.summary.subject) || '(no subject)'}`);
  L.push('');
  L.push(`**Verdict:** ${r.verdict.label} (score ${r.score}/100)`);
  if (r.overallScore > r.score) L.push(`**Attached email verdict:** ${r.overallVerdict.label} (score ${r.overallScore}/100)`);
  L.push('');
  L.push(`| Field | Value |`);
  L.push(`|:--|:--|`);
  L.push(`| From | ${mdEscape(addr(r.summary.from))} |`);
  if (r.summary.replyTo) L.push(`| Reply-To | ${mdEscape(addr(r.summary.replyTo))} |`);
  if (r.summary.returnPath) L.push(`| Return-Path | ${mdEscape(r.summary.returnPath.address)} |`);
  L.push(`| To | ${mdEscape(r.summary.to.map(addr).join(', '))} |`);
  L.push(`| Date | ${mdEscape(r.summary.date)} |`);
  L.push(`| Origin IP | ${r.summary.originIp ? defang(r.summary.originIp) : 'unknown'} |`);
  L.push(`| SPF / DKIM / DMARC | ${r.auth.spf} / ${r.auth.dkim} / ${r.auth.dmarc} |`);
  L.push(`| File SHA-256 | \`${r.sha256}\` |`);
  L.push('');

  L.push(`${h(2)} Findings (${r.findings.filter((f) => f.sev !== 'info').length})`);
  L.push('');
  if (!r.findings.length) L.push('No findings.');
  for (const f of r.findings) {
    L.push(`- **[${f.sev.toUpperCase()}]** ${mdEscape(f.title)}${f.mitre ? ` (${f.mitre})` : ''}`);
    if (f.detail) L.push(`  - ${mdEscape(defangText(f.detail))}`);
    for (const e of (f.evidence || []).slice(0, 5)) L.push(`  - \`${mdEscape(defangText(e))}\``);
  }
  L.push('');
  if (r.positives.length) {
    L.push(`${h(2)} Passed checks`);
    L.push('');
    r.positives.forEach((p) => L.push(`- ${mdEscape(p)}`));
    L.push('');
  }

  if (r.hops.length) {
    L.push(`${h(2)} Delivery route (oldest first)`);
    L.push('');
    L.push('| Hop | From | By | IP | Delay |');
    L.push('|:--|:--|:--|:--|:--|');
    r.hops.forEach((x) => L.push(`| ${x.hop} | ${mdEscape(x.from)} | ${mdEscape(x.by)} | ${x.ip ? defang(x.ip) : ''} | ${x.delay === null ? '' : x.delay + 's'} |`));
    L.push('');
  }

  if (r.attachments.length) {
    L.push(`${h(2)} Attachments`);
    L.push('');
    L.push('| File | Real type | Size | SHA-256 |');
    L.push('|:--|:--|--:|:--|');
    r.attachments.forEach((a) => L.push(`| ${mdEscape(a.filename)} | ${mdEscape(a.typeLabel)} | ${a.size} | \`${a.sha256}\` |`));
    L.push('');
  }

  L.push(`${h(2)} Indicators (defanged)`);
  L.push('');
  L.push('```');
  L.push(toIocText(r));
  L.push('```');
  if (r.mitre.length) {
    L.push('');
    L.push(`**MITRE ATT&CK:** ${r.mitre.join(', ')}`);
  }
  for (const n of r.nested) {
    L.push('');
    L.push(toMarkdown(n, level + 1).replace(/^#+ HookScope report:/, `${h(2)} Attached email:`));
  }
  L.push('');
  return L.join('\n');
}

function defangText(s) {
  return String(s).replace(/\bhttps?:\/\/\S+/gi, (u) => defang(u));
}

export function toIocText(r) {
  const L = [];
  const sec = (name, arr) => { if (arr.length) { L.push(`# ${name}`); arr.forEach((x) => L.push(x)); L.push(''); } };
  sec('Sender emails', r.iocs.emails.map(defang));
  sec('Domains', r.iocs.domains.map(defang));
  sec('IP addresses', r.iocs.ips.map(defang));
  sec('URLs', r.iocs.urls.map(defang));
  sec('SHA-256', r.iocs.hashes.map((h) => `${h.sha256}  ${h.filename}`));
  return L.join('\n').trim() || '(none)';
}

export function toIocCsv(r) {
  const rows = [['type', 'value', 'context']];
  const q = (s) => `"${String(s).replace(/"/g, '""')}"`;
  r.iocs.emails.forEach((v) => rows.push(['email', v, 'sender']));
  r.iocs.domains.forEach((v) => rows.push(['domain', v, '']));
  r.iocs.ips.forEach((v) => rows.push(['ip', v, v === r.summary.originIp ? 'origin' : 'route']));
  r.iocs.urls.forEach((v) => rows.push(['url', v, '']));
  r.iocs.hashes.forEach((h) => rows.push(['sha256', h.sha256, h.filename]));
  r.nested.forEach((n) => toIocCsv(n).split('\n').slice(1).forEach((line) => rows.push(line)));
  return rows.map((row) => (Array.isArray(row) ? row.map(q).join(',') : row)).join('\n');
}
