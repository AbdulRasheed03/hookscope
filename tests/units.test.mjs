import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeEncodedWords, parseStructured, qpDecode, parseAddress, parseEmail, leaves } from '../src/mime.js';
import { brandCheck, punyDecode, toUnicodeHost, registrableDomain, skeleton } from '../src/domains.js';
import { analyzeUrl, hostShownInText } from '../src/urls.js';
import { sniff } from '../src/attachments.js';
import { scanHtml } from '../src/html.js';
import { analyzeContent } from '../src/content.js';
import { defang } from '../src/util.js';

test('RFC 2047 encoded words', () => {
  assert.equal(decodeEncodedWords('=?UTF-8?B?SGVsbG8=?= =?UTF-8?Q?_W=C3=B6rld?='), 'Hello Wörld');
  assert.equal(decodeEncodedWords('=?iso-8859-1?Q?Caf=E9?='), 'Café');
});

test('RFC 2231 parameters', () => {
  const p = parseStructured("attachment; filename*=UTF-8''%E2%82%AC%20rates.pdf");
  assert.equal(p.value, 'attachment');
  assert.equal(p.params.filename, '€ rates.pdf');
  const q = parseStructured('text/plain; charset="utf-8"; name="a; b.txt"');
  assert.equal(q.params.name, 'a; b.txt');
});

test('quoted-printable', () => {
  assert.equal(new TextDecoder().decode(qpDecode('caf=C3=A9 =\r\nau lait')), 'café au lait');
});

test('address parsing', () => {
  const a = parseAddress('"Support, Team" <Help@Example.COM>');
  assert.equal(a.name, 'Support, Team');
  assert.equal(a.address, 'help@example.com');
  assert.equal(a.domain, 'example.com');
});

test('nested multipart', () => {
  const raw = 'Content-Type: multipart/mixed; boundary=A\r\n\r\n--A\r\nContent-Type: multipart/alternative; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nplain\r\n--B\r\nContent-Type: text/html\r\n\r\n<b>html</b>\r\n--B--\r\n--A\r\nContent-Type: application/pdf; name=x.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n--A--\r\n';
  const parts = leaves(parseEmail(new TextEncoder().encode(raw)));
  assert.deepEqual(parts.map((p) => p.contentType), ['text/plain', 'text/html', 'application/pdf']);
  assert.equal(parts[2].filename, 'x.pdf');
  assert.equal(sniff(parts[2].bytes), 'pdf');
});

test('punycode and homoglyphs', () => {
  assert.equal(punyDecode('pypal-4ve'), 'pаypal');
  assert.equal(toUnicodeHost('xn--pypal-4ve.com'), 'pаypal.com');
  assert.equal(brandCheck('xn--pypal-4ve.com').type, 'homoglyph');
  assert.equal(brandCheck('paypa1.com').type, 'homoglyph');
  assert.equal(brandCheck('rnaybank2u.com').type, 'homoglyph');
  assert.equal(brandCheck('maybamk2u.com.my').type, 'typosquat');
  assert.equal(brandCheck('maybank2u-login.top').type, 'brand-keyword');
  assert.equal(brandCheck('secure.maybank2u.com.my').type, 'official');
  assert.equal(brandCheck('kopirawang.example'), null);
  assert.equal(brandCheck('groups.example.com'), null, 'short keyword "ups" should not match inside words');
  assert.equal(skeleton('micr0soft'), 'mlcrosoft');
});

test('registrable domain', () => {
  assert.equal(registrableDomain('a.b.maybank2u.com.my'), 'maybank2u.com.my');
  assert.equal(registrableDomain('evil.pages.dev'), 'evil.pages.dev');
  assert.equal(registrableDomain('x.y.example.co.uk'), 'example.co.uk');
});

test('URL tricks', () => {
  const ids = (u) => analyzeUrl(u).flags.map((f) => f.id);
  assert.ok(ids('https://www.paypal.com@evil.example/login').includes('userinfo'));
  assert.ok(ids('http://3232235777/login').includes('obfuscated-ip'));
  assert.ok(ids('http://192.168.1.1/a').includes('ip-host'));
  assert.ok(ids('https://bit.ly/abc').includes('shortener'));
  assert.ok(ids('https://foo.pages.dev/m2u').includes('free-hosting'));
  assert.ok(ids('https://www.google.com/url?q=https://evil.example/x').includes('redirect'));
  assert.ok(ids('https://cdn.example.com/files/MyBank.apk').includes('risky-download'));
  assert.ok(ids('javascript:alert(1)').includes('javascript-uri'));
  assert.deepEqual(ids('https://www.maybank2u.com.my/home'), []);
  assert.equal(hostShownInText('https://www.maybank2u.com.my'), 'www.maybank2u.com.my');
  assert.equal(hostShownInText('Click here'), null);
});

test('file type sniffing', () => {
  assert.equal(sniff(Uint8Array.from([0x4d, 0x5a, 0x90, 0])), 'pe');
  assert.equal(sniff(new TextEncoder().encode('<!DOCTYPE html><html>')), 'html');
  assert.equal(sniff(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg">')), 'svg');
  assert.equal(sniff(Uint8Array.from([0x50, 0x4b, 3, 4])), 'zip');
});

test('HTML scanning', () => {
  const h = scanHtml('<a href="http://evil.example/x">https://bank.example</a><form action="https://x.example/p"><input type="password"></form><span style="font-size:0px;">hidden words here</span>');
  assert.equal(h.anchors[0].text, 'https://bank.example');
  assert.equal(h.passwordInputs, 1);
  assert.equal(h.forms[0].action, 'https://x.example/p');
  assert.equal(h.hiddenText.length, 1);
});

test('Malay and English wording', () => {
  const groups = analyzeContent('Akaun anda akan disekat. Sila log masuk segera.').map((g) => g.id);
  assert.ok(groups.includes('urgency'));
  assert.ok(groups.includes('credentials'));
  assert.equal(analyzeContent('persamaan matematik').length, 0, 'should match whole words only');
});

test('Malaysian brand look-alikes', () => {
  assert.equal(brandCheck('tngdlgital.com.my').type, 'homoglyph', 'l in place of i');
  assert.equal(brandCheck('tngdigital.com.my').type, 'official');
  assert.equal(brandCheck('poslaju-tracking.support').type, 'brand-keyword');
  assert.equal(brandCheck('www.pos.com.my').type, 'official');
  assert.equal(brandCheck('ezhasil-refund.online').brand, 'LHDN');
  assert.equal(brandCheck('hasil-gov-my.web.app').brand, 'LHDN');
  assert.equal(brandCheck('mytax.hasil.gov.my').type, 'official');
  assert.equal(brandCheck('kwsp-akaunfleksibel.info').brand, 'KWSP / EPF');
  assert.equal(brandCheck('postal.example'), null, 'short brand words must not match inside other words');
});

test('chat hand-off links', () => {
  const ids = (u) => analyzeUrl(u).flags.map((f) => f.id);
  assert.ok(ids('https://wa.me/60123456789').includes('chat-handoff'));
  assert.ok(ids('https://t.me/some_group').includes('chat-handoff'));
  assert.ok(!ids('https://www.whatsapp.com/download').includes('chat-handoff'), 'the WhatsApp website is not a hand-off');
});

test('Malay scam wording: frozen accounts, IC numbers and task jobs', () => {
  const groups = (t) => analyzeContent(t).map((g) => g.id);
  assert.ok(groups('Akaun eWallet anda telah dibekukan.').includes('urgency'));
  assert.ok(groups('Sila masukkan nombor kad pengenalan anda.').includes('credentials'));
  assert.ok(groups('Kerja sambilan, gaji harian RM300, tugasan mudah.').includes('job'));
  assert.ok(groups('Part time job, daily commission, no experience needed.').includes('job'));
  assert.ok(!groups('Mesyuarat kerja pada hari Isnin.').includes('job'), 'ordinary work talk is fine');
});

test('defang', () => {
  assert.equal(defang('http://evil.example/a.b'), 'hxxp://evil[.]example/a[.]b');
});
