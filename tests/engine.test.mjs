import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzeEmail } from '../src/engine.js';
import { toMarkdown, toIocCsv, toJson } from '../src/report.js';

const sample = (name) => new Uint8Array(readFileSync(new URL(`../samples/${name}`, import.meta.url)));
const ids = (r) => r.findings.map((f) => f.id + ':' + f.title);
const has = (r, text) => r.findings.some((f) => (f.id + ' ' + f.title).includes(text));

test('bank credential phish is flagged as malicious', async () => {
  const r = await analyzeEmail(sample('maybank-credential-phish.eml'));
  assert.equal(r.verdict.level, 'malicious', ids(r).join('\n'));
  assert.equal(r.summary.subject, 'RE: Akaun anda akan disekat ⚠️');
  assert.equal(r.auth.dmarc, 'fail');
  assert.equal(r.summary.originIp, '185.234.72.19');
  assert.ok(has(r, 'from-lookalike'));
  assert.ok(has(r, 'link-mismatch'));
  assert.ok(has(r, 'reply-to-mismatch'));
  assert.ok(has(r, 'fake-reply'));
  assert.ok(has(r, 'words-credentials'));
  assert.ok(r.iocs.domains.includes('rnaybank2u-secure.com'));
  assert.ok(!r.iocs.domains.includes('gmail.com'), 'free webmail should not be listed as a domain IOC');
});

test('HTML smuggling attachment is detected', async () => {
  const r = await analyzeEmail(sample('microsoft-html-smuggling.eml'));
  assert.equal(r.verdict.level, 'malicious');
  const att = r.attachments[0];
  assert.equal(att.filename, 'Remittance_Advice.pdf.html');
  assert.equal(att.type, 'html');
  assert.match(att.sha256, /^[0-9a-f]{64}$/);
  const titles = att.flags.map((f) => f.title).join('\n');
  assert.match(titles, /HTML smuggling/);
  assert.match(titles, /Telegram/);
  assert.match(titles, /double extension/);
  assert.match(titles, /fake login page/);
  assert.ok(r.mitre.includes('T1027.006'));
});

test('CEO fraud with macro document and locked zip', async () => {
  const r = await analyzeEmail(sample('ceo-fraud-macro-docm.eml'));
  assert.equal(r.verdict.level, 'malicious');
  assert.ok(has(r, 'display-email-spoof'));
  assert.ok(has(r, 'exec-freemail'));
  const doc = r.attachments.find((a) => a.filename === 'Payment_Details.docm');
  assert.ok(doc.flags.some((f) => /VBA macros/.test(f.title)));
  assert.ok(doc.flags.some((f) => f.mitre === 'T1221'), 'remote template injection should be found');
  const zip = r.attachments.find((a) => a.filename === 'Invoice_8842.zip');
  assert.ok(zip, 'RFC 2231 filename should decode');
  assert.ok(zip.flags.some((f) => /Password-protected/.test(f.title)));
  assert.ok(zip.entries.some((e) => e.name === 'Invoice_8842.pdf.exe'));
  assert.ok(r.iocs.ips.includes('45.137.21.9'));
});

test('normal newsletter stays low risk', async () => {
  const r = await analyzeEmail(sample('legit-newsletter.eml'));
  assert.equal(r.verdict.level, 'low', ids(r).join('\n'));
  assert.ok(r.score < 15);
  assert.equal(r.auth.dmarc, 'pass');
  assert.ok(r.auth.dkimAligned);
  assert.ok(r.positives.length >= 2);
});

test('forwarded report: the attached email is analyzed too', async () => {
  const r = await analyzeEmail(sample('user-report-forward.eml'));
  assert.equal(r.nested.length, 1);
  assert.equal(r.nested[0].verdict.level, 'malicious');
  assert.equal(r.overallVerdict.level, 'malicious');
  assert.ok(r.score < 15, 'the outer report email itself is harmless');
});

test('exports do not crash and contain no em dashes', async () => {
  const r = await analyzeEmail(sample('user-report-forward.eml'));
  const md = toMarkdown(r);
  assert.match(md, /HookScope report/);
  assert.match(md, /Attached email/);
  assert.match(md, /hxxp/);
  assert.ok(!md.includes('\u2014'));
  assert.match(toIocCsv(r), /^"type","value","context"/);
  const json = JSON.parse(toJson(r));
  assert.equal(json.tool, 'HookScope');
});

test('works on a minimal email given as a string', async () => {
  const r = await analyzeEmail('From: a@b.com\r\nSubject: hi\r\n\r\nhello world');
  assert.equal(r.summary.subject, 'hi');
  assert.equal(r.body.text.trim(), 'hello world');
  assert.equal(r.verdict.level, 'low');
});
