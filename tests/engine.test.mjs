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

// Malaysian scam set. Each sample shows a different technique, so each test pins the signal that matters.
const finding = (r, id) => r.findings.find((f) => f.id === id);

test('LHDN tax refund: passes SPF, DKIM and DMARC but is still phishing', async () => {
  const r = await analyzeEmail(sample('lhdn-tax-refund-form.eml'));
  assert.equal(r.verdict.level, 'malicious', ids(r).join('\n'));
  // The scammer owns ezhasil-refund.online, so authentication passes. That must not save it.
  assert.equal(r.auth.spf, 'pass');
  assert.equal(r.auth.dkim, 'pass');
  assert.equal(r.auth.dmarc, 'pass');
  assert.ok(r.positives.some((p) => /DMARC passed/.test(p)));
  assert.equal(finding(r, 'from-brand-domain').sev, 'high');
  assert.match(finding(r, 'from-brand-domain').title, /LHDN/);
  assert.equal(finding(r, 'body-form').sev, 'critical', 'a password box inside the email is critical');
  assert.ok(has(r, 'link-mismatch'), 'link text shows mytax.hasil.gov.my but opens web.app');
  assert.ok(has(r, 'url-free-hosting'));
  assert.ok(has(r, 'words-money'), '"bayaran balik" is a refund lure');
  assert.ok(r.iocs.domains.includes('hasil-gov-my.web.app'));
  assert.ok(!r.iocs.domains.includes('mytax.hasil.gov.my'), 'the real LHDN domain is never an IOC');
});

test('Pos Laju customs fee: small fee, card number and TAC, hidden behind redirects', async () => {
  const r = await analyzeEmail(sample('poslaju-customs-fee.eml'));
  assert.equal(r.verdict.level, 'malicious', ids(r).join('\n'));
  assert.match(r.summary.subject, /caj kastam RM2\.80/);
  assert.ok(has(r, 'from-brand-domain'));
  assert.ok(has(r, 'spf-fail'));
  assert.ok(has(r, 'words-delivery'));
  assert.match(finding(r, 'words-credentials').detail, /kod tac/i);
  assert.ok(has(r, 'url-redirect'), 'google.com/url?q= open redirect');
  assert.ok(has(r, 'url-shortener'));
  assert.ok(has(r, 'combo-credential-link'));
  assert.ok(r.iocs.domains.includes('poslaju-redelivery.top'), 'the redirect destination is an IOC');
  assert.ok(!r.iocs.domains.includes('google.com'), 'the redirect host itself is not');
});

test("Touch 'n Go eWallet: look-alike domain pushing an APK", async () => {
  const r = await analyzeEmail(sample('tng-ewallet-apk-update.eml'));
  assert.equal(r.verdict.level, 'malicious', ids(r).join('\n'));
  const lookalike = finding(r, 'from-lookalike');
  assert.equal(lookalike.sev, 'critical');
  assert.match(lookalike.detail, /tngdigital\.com\.my/, 'tngdlgital uses an l in place of the i');
  assert.ok(has(r, 'url-risky-download'));
  assert.ok(has(r, 'url-lookalike'));
  assert.ok(finding(r, 'link-mismatch').evidence.some((e) => e.includes('play.google.com')), 'fake Google Play link');
  assert.ok(has(r, 'words-urgency'), '"akan dibekukan" (will be frozen)');
  assert.ok(r.urls.some((u) => u.url.endsWith('.apk')));
});

test("KWSP Akaun Fleksibel: the '@' trick hides a raw IP behind kwsp.gov.my", async () => {
  const r = await analyzeEmail(sample('kwsp-akaun-fleksibel-at-trick.eml'));
  assert.equal(r.verdict.level, 'malicious', ids(r).join('\n'));
  assert.equal(r.auth.dmarc, 'pass', 'Gmail passes DMARC for its own users');
  assert.match(finding(r, 'display-brand').title, /KWSP/);
  assert.ok(has(r, 'url-userinfo'));
  assert.ok(has(r, 'url-ip-host'));
  assert.ok(has(r, 'link-mismatch'));
  assert.ok(r.iocs.ips.includes('198.51.100.47'), 'the real server behind the @ is an IOC');
  assert.ok(!r.iocs.domains.includes('kwsp.gov.my'));
});

test('Shopee part-time task scam: job wording and a hand-off to WhatsApp or Telegram', async () => {
  const r = await analyzeEmail(sample('shopee-task-job-scam.eml'));
  assert.ok(['likely', 'malicious'].includes(r.verdict.level), `${r.score}\n${ids(r).join('\n')}`);
  assert.match(finding(r, 'display-brand').title, /Shopee/);
  assert.equal(finding(r, 'words-job').sev, 'medium');
  assert.ok(finding(r, 'url-chat-handoff').evidence.length >= 2, 'both wa.me and t.me links');
  assert.ok(!r.iocs.domains.includes('t.me'), 'never tell people to block all of Telegram');
});

test('real Pos Malaysia notice stays low risk even with a "we never ask for your TAC" footer', async () => {
  const r = await analyzeEmail(sample('legit-pos-malaysia-tracking.eml'));
  assert.equal(r.verdict.level, 'low', ids(r).join('\n'));
  assert.equal(r.score, 0);
  const words = r.findings.filter((f) => f.id.startsWith('words-'));
  assert.ok(words.length, 'the wording is still shown for context');
  assert.ok(words.every((f) => f.sev === 'info' && /Not scored/.test(f.detail)));
  assert.deepEqual(r.iocs.domains, [], 'the real courier domain is never an IOC');
});

test('a spoofed pos.com.my sender that fails DMARC does not get the verified-brand pass', async () => {
  const raw = new TextDecoder().decode(sample('legit-pos-malaysia-tracking.eml'))
    .replace('dmarc=pass (p=REJECT)', 'dmarc=fail (p=REJECT)')
    .replace('dkim=pass header.d=pos.com.my', 'dkim=fail header.d=pos.com.my')
    .replaceAll('https://www.pos.com.my/track?no=ER771204338MY', 'https://bit.ly/pos-track-ER77');
  const r = await analyzeEmail(raw);
  assert.ok(has(r, 'dmarc-fail'));
  assert.equal(finding(r, 'words-credentials').sev, 'medium', 'wording counts again');
  assert.ok(has(r, 'combo-credential-link'));
  assert.ok(r.score >= 40, `score ${r.score}\n${ids(r).join('\n')}`);
});

test('every sample on the page has a matching file and a verdict', async () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  const listed = [...html.matchAll(/data-sample="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(listed.length >= 11);
  for (const name of listed) {
    const r = await analyzeEmail(sample(name));
    assert.ok(r.verdict.level, name);
  }
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
