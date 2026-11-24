// Sender, authentication (SPF / DKIM / DMARC) and delivery route checks.

import { parseAddress, parseAddressList } from './mime.js';
import { isIP, isPrivateIP, uniq } from './util.js';
import {
  registrableDomain, sameOrg, brandCheck, brandMentioned, officialBrand, FREEMAIL, toUnicodeHost,
} from './domains.js';

function parseAuthResult(v) {
  const res = { raw: v, server: v.split(';')[0].trim(), dkim: [] };
  for (const method of ['spf', 'dmarc', 'arc', 'compauth']) {
    const m = new RegExp('\\b' + method + '\\s*=\\s*([a-z]+)', 'i').exec(v);
    if (m) res[method] = m[1].toLowerCase();
  }
  const dk = /\bdkim\s*=\s*([a-z]+)([^;]*)/gi;
  let m;
  while ((m = dk.exec(v))) {
    const d = (/header\.d\s*=\s*"?([^\s;"]+)/i.exec(m[2]) || /header\.i\s*=\s*"?@?([^\s;"]+)/i.exec(m[2]) || [])[1] || '';
    res.dkim.push({ result: m[1].toLowerCase(), domain: d.toLowerCase().replace(/^.*@/, '') });
  }
  const g = (re) => ((re.exec(v) || [])[1] || '').toLowerCase();
  res.mailfrom = g(/smtp\.mailfrom\s*=\s*"?([^\s;"]+)/i).replace(/^.*@/, '');
  res.headerFrom = g(/header\.from\s*=\s*"?([^\s;"]+)/i);
  return res;
}

function parseReceived(values) {
  const hops = values.map((v) => {
    const semi = v.lastIndexOf(';');
    const datePart = semi >= 0 ? v.slice(semi + 1).trim() : '';
    const body = semi >= 0 ? v.slice(0, semi) : v;
    const fromSection = body.split(/\sby\s/i)[0];
    const fromM = /\bfrom\s+(\S+)/i.exec(body);
    const byM = /\bby\s+(\S+)/i.exec(body);
    const withM = /\bwith\s+(\S+)/i.exec(body);
    const ips = uniq([
      ...[...fromSection.matchAll(/\[(?:IPv6:)?([0-9a-f:.]+)\]/gi)].map((x) => x[1]),
      ...[...fromSection.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)].map((x) => x[1]),
    ]).filter(isIP);
    const t = Date.parse(datePart.replace(/\s*\([^)]*\)\s*$/, ''));
    return {
      from: fromM ? fromM[1] : '',
      by: byM ? byM[1] : '',
      with: withM ? withM[1] : '',
      ip: ips.find((ip) => !isPrivateIP(ip)) || ips[0] || '',
      ips,
      date: datePart,
      time: Number.isNaN(t) ? null : t,
    };
  });
  hops.reverse(); // oldest first
  return hops.map((h, i) => ({
    ...h,
    hop: i + 1,
    delay: i > 0 && h.time !== null && hops[i - 1].time !== null ? Math.round((h.time - hops[i - 1].time) / 1000) : null,
  }));
}

export function analyzeHeaders(root, add) {
  const all = (k) => root.headers.filter((h) => h.key === k);
  const first = (k) => (all(k)[0] || {}).value || '';

  const from = parseAddressList(first('from'))[0] || { name: '', address: '', domain: '', local: '' };
  const replyTo = parseAddressList(first('reply-to'))[0] || null;
  const returnPath = first('return-path') ? parseAddress(first('return-path')) : null;
  const sender = first('sender') ? parseAddress(first('sender')) : null;
  const to = parseAddressList(first('to'));
  const cc = parseAddressList(first('cc'));
  const subject = first('subject');
  const date = first('date');
  const messageId = first('message-id').replace(/[<>]/g, '');
  const mailer = first('x-mailer') || first('user-agent');

  // Authentication results: the top-most header is the one added by the receiving server.
  const arList = all('authentication-results').map((h) => parseAuthResult(h.value));
  const ar = arList.find((a) => a.spf || a.dmarc || a.dkim.length) || null;
  const receivedSpf = (first('received-spf').match(/^\s*(\w+)/) || [])[1]?.toLowerCase() || '';
  const dkimSigs = all('dkim-signature').map((h) => ({
    domain: ((/\bd\s*=\s*([^;\s]+)/i.exec(h.value) || [])[1] || '').toLowerCase(),
    selector: ((/\bs\s*=\s*([^;\s]+)/i.exec(h.value) || [])[1] || '').toLowerCase(),
  }));

  const auth = {
    spf: ar?.spf || receivedSpf || 'none',
    dkim: ar?.dkim.length ? (ar.dkim.some((d) => d.result === 'pass') ? 'pass' : ar.dkim[0].result) : dkimSigs.length ? 'unchecked' : 'none',
    dmarc: ar?.dmarc || 'none',
    server: ar?.server || '',
    mailfrom: ar?.mailfrom || returnPath?.domain || '',
    dkimDomains: uniq([...(ar?.dkim || []).filter((d) => d.result === 'pass').map((d) => d.domain), ...dkimSigs.map((d) => d.domain)]),
    spfAligned: false,
    dkimAligned: false,
    present: !!ar || !!receivedSpf,
  };
  auth.spfAligned = auth.spf === 'pass' && sameOrg(auth.mailfrom, from.domain);
  auth.dkimAligned = (ar?.dkim || []).some((d) => d.result === 'pass' && sameOrg(d.domain, from.domain));

  const hops = parseReceived(all('received').map((h) => h.value));
  const originHop = hops.find((h) => h.ip && !isPrivateIP(h.ip));
  const xOrigIp = (first('x-originating-ip') || first('x-sender-ip')).replace(/[[\]\s]/g, '');
  const originIp = isIP(xOrigIp) && !isPrivateIP(xOrigIp) ? xOrigIp : originHop?.ip || '';

  const positives = [];
  const fromDom = from.domain;
  const fromBrand = brandCheck(fromDom);
  const fromIsFreemail = FREEMAIL.has(fromDom);

  // Authentication.
  if (!auth.present) {
    add({ id: 'auth-missing', category: 'Authentication', sev: 'info', title: 'No authentication results in the headers', detail: 'The receiving server did not record SPF / DKIM / DMARC results, or the file was saved without full headers. The sender could not be verified.' });
  } else {
    if (auth.dmarc === 'fail') add({ id: 'dmarc-fail', category: 'Authentication', sev: 'high', title: `DMARC failed for ${fromDom || 'the sender domain'}`, detail: 'The receiving mail server checked and this email was not really sent by the domain shown in the From address.', mitre: 'T1566' });
    if (['fail', 'permerror'].includes(auth.spf)) add({ id: 'spf-fail', category: 'Authentication', sev: 'medium', title: 'SPF failed', detail: `The server that sent this email (${originIp || 'unknown IP'}) is not allowed to send mail for ${auth.mailfrom || 'this domain'}.` });
    else if (auth.spf === 'softfail') add({ id: 'spf-softfail', category: 'Authentication', sev: 'low', title: 'SPF soft fail', detail: 'The sending server is probably not allowed to send for this domain.' });
    if (['fail', 'invalid', 'permerror'].includes(auth.dkim)) add({ id: 'dkim-fail', category: 'Authentication', sev: 'medium', title: 'DKIM signature failed', detail: 'The digital signature is broken. The email may have been changed after it was sent or the signature is fake.' });
    if (auth.dkim === 'none' && auth.dmarc === 'none') add({ id: 'dkim-none', category: 'Authentication', sev: 'low', title: 'No DKIM signature and no DMARC policy', detail: 'Nothing proves this email came from the sender domain.' });
    if (auth.spf === 'pass' && !auth.spfAligned && auth.dmarc !== 'pass' && !auth.dkimAligned) add({ id: 'spf-unaligned', category: 'Authentication', sev: 'low', title: 'SPF passed, but for a different domain than the From address', detail: `SPF checked ${auth.mailfrom}, while the From address shows ${fromDom}.` });
    if (auth.dmarc === 'pass') positives.push(`DMARC passed for ${fromDom}`);
    if (auth.spf === 'pass') positives.push(`SPF passed (${auth.mailfrom || 'envelope sender'})`);
    if (auth.dkim === 'pass') positives.push(`DKIM passed (${auth.dkimDomains.join(', ') || 'signed'})`);
  }

  // Sender identity.
  if (fromBrand && (fromBrand.type === 'homoglyph' || fromBrand.type === 'typosquat')) {
    add({ id: 'from-lookalike', category: 'Sender', sev: 'critical', title: `Sender domain imitates ${fromBrand.brand}`, detail: `${toUnicodeHost(fromDom)} looks like ${fromBrand.target} but is a different domain.`, evidence: [from.address], mitre: 'T1583.001' });
  } else if (fromBrand && fromBrand.type === 'brand-keyword') {
    add({ id: 'from-brand-domain', category: 'Sender', sev: 'high', title: `Sender domain uses the ${fromBrand.brand} name but is not owned by ${fromBrand.brand}`, detail: `${fromDom} is not one of ${fromBrand.brand}'s real domains.`, evidence: [from.address], mitre: 'T1656' });
  }
  if (fromDom.split('.').some((l) => l.startsWith('xn--'))) add({ id: 'from-punycode', category: 'Sender', sev: 'medium', title: 'Sender domain uses international look-alike characters', detail: `Shown as ${toUnicodeHost(fromDom)}`, evidence: [fromDom] });

  const nameEmail = /[^\s<>"]+@([^\s<>"]+)/.exec(from.name || '');
  if (nameEmail && !sameOrg(nameEmail[1], fromDom)) {
    add({ id: 'display-email-spoof', category: 'Sender', sev: 'high', title: 'Display name shows a different email address than the real sender', detail: `The name says "${from.name}" but the email actually came from ${from.address}.`, mitre: 'T1656' });
  }
  const claimed = brandMentioned(from.name || '');
  if (claimed && officialBrand(fromDom)?.name !== claimed.name) {
    const already = fromBrand && fromBrand.brand === claimed.name && fromBrand.type !== 'official';
    if (!already) {
      add({ id: 'display-brand', category: 'Sender', sev: 'high', title: `Display name claims to be ${claimed.name}, but the email is not from ${claimed.name}`, detail: `"${from.name}" <${from.address}>${fromIsFreemail ? ' is a free webmail account.' : ''}`, mitre: 'T1656' });
    }
  }

  if (fromIsFreemail && /\b(ceo|cfo|coo|cto|md|managing director|director|president|chairman|founder|datuk|dato'?|tan sri|tun|pengarah|ketua pegawai|finance manager|hr manager|payroll)\b/i.test(from.name || '')) {
    add({ id: 'exec-freemail', category: 'Sender', sev: 'medium', title: 'A senior title is used on a personal webmail account', detail: `"${from.name}" is writing from ${fromDom}. Boss impersonation (CEO fraud) emails often look like this.`, mitre: 'T1656' });
  }
  if (replyTo && replyTo.domain && !sameOrg(replyTo.domain, fromDom)) {
    const rFree = FREEMAIL.has(replyTo.domain);
    add({ id: 'reply-to-mismatch', category: 'Sender', sev: rFree ? 'high' : 'medium', title: 'Replies go to a different address than the sender', detail: `From ${from.address}, but Reply-To is ${replyTo.address}${rFree ? ' (free webmail)' : ''}. Scammers do this so your reply reaches them.`, mitre: 'T1566' });
  }
  if (returnPath && returnPath.domain && fromDom && !sameOrg(returnPath.domain, fromDom) && auth.dmarc !== 'pass') {
    add({ id: 'return-path-mismatch', category: 'Sender', sev: 'low', title: 'Bounce address (Return-Path) uses a different domain', detail: `Return-Path is ${returnPath.address}. Mailing services do this too, so it is only a weak sign.` });
  }
  if (messageId && fromDom) {
    const midDom = messageId.split('@')[1] || '';
    if (midDom && !sameOrg(midDom, fromDom) && !/(google|outlook|microsoft|amazonses|sendgrid|mailgun|mailchimp|mcsv|sparkpost|mandrill|zoho)/i.test(midDom)) {
      add({ id: 'msgid-mismatch', category: 'Sender', sev: 'info', title: 'Message-ID domain differs from the sender', detail: `Message-ID was made by ${midDom}.` });
    }
  }
  if (/^\s*(re|fw|fwd|aw|balas|bls|tr)\s*:/i.test(subject) && !first('in-reply-to') && !first('references')) {
    add({ id: 'fake-reply', category: 'Content', sev: 'medium', title: 'Subject pretends to be a reply or forward, but it is not part of any thread', detail: `"${subject}" has no In-Reply-To or References header. This makes a cold email look like an ongoing conversation.`, mitre: 'T1566' });
  }
  if (mailer && /phpmailer|swiftmailer|python|curl|outlook express|the bat!|king ?mailer|atomic mail|turbo-?mailer|gammadyne|sendblaster|leaf ?php/i.test(mailer)) {
    add({ id: 'mailer', category: 'Sender', sev: 'low', title: 'Sent with a script or bulk mailing tool', detail: mailer });
  }
  if (!to.length && !cc.length) add({ id: 'no-recipient', category: 'Sender', sev: 'low', title: 'No visible recipient (sent as BCC or "undisclosed recipients")', detail: first('to') || '(empty)' });

  // Time checks.
  const dateT = Date.parse(date);
  const lastHop = [...hops].reverse().find((h) => h.time !== null);
  if (!Number.isNaN(dateT) && lastHop) {
    const diffH = (lastHop.time - dateT) / 3600000;
    if (diffH < -2) add({ id: 'date-future', category: 'Headers', sev: 'low', title: 'Date header is later than the time it was received', detail: `${Math.round(-diffH)} hours ahead. The Date header can be set to anything by the sender.` });
    else if (diffH > 48) add({ id: 'date-old', category: 'Headers', sev: 'info', title: 'Date header is much older than the delivery time', detail: `${Math.round(diffH)} hours difference.` });
  }

  return {
    from, replyTo, returnPath, sender, to, cc, subject, date, messageId, mailer,
    auth, hops, originIp, positives,
    fromRegistrable: registrableDomain(fromDom),
    fromFreemail: fromIsFreemail,
  };
}
