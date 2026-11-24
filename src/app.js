// Browser UI. Every value from the email is inserted with textContent, never as HTML,
// so a malicious email cannot run code inside this page.

import { analyzeEmail, VERSION } from './engine.js';
import { toJson, toMarkdown, toIocText, toIocCsv } from './report.js';
import { defang } from './util.js';

const $ = (sel) => document.querySelector(sel);
const MAX_SIZE = 40 * 1024 * 1024;

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (k === 'href') node.href = safeHref(v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function safeHref(v) {
  return /^https:\/\//i.test(v) ? v : '#';
}

const sevBadge = (sev) => el('span', { class: `badge sev-${sev}`, text: sev });
const mitreTag = (id) => (id ? el('a', { class: 'tag', href: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`, target: '_blank', rel: 'noopener noreferrer', title: 'MITRE ATT&CK technique' }, id) : null);
const addr = (a) => (a ? (a.name ? `${a.name} <${a.address}>` : a.address) : '');

function toast(msg) {
  const t = el('div', { class: 'toast', text: msg });
  document.body.append(t);
  setTimeout(() => t.remove(), 1600);
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Copied'); } catch { toast('Copy failed'); }
}

function download(name, text, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el('a', {});
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function safeName(s) {
  return (String(s || 'email').replace(/[^\w\- ]+/g, '').trim().slice(0, 50) || 'email').replace(/\s+/g, '_');
}

// State: a stack so the user can open an attached email and come back.
const stack = [];
let activeTab = 'findings';

function showError(msg) {
  const e = $('#error');
  e.textContent = msg;
  e.hidden = !msg;
}

async function run(bytes, name) {
  showError('');
  if (bytes.length > MAX_SIZE) { showError('This file is larger than 40 MB. Please use the command line version for very large files.'); return; }
  const r = $('#results');
  r.hidden = false;
  r.replaceChildren(el('div', { class: 'status', text: `Analyzing ${name}...` }));
  try {
    const result = await analyzeEmail(bytes);
    result.fileName = name;
    stack.length = 0;
    stack.push(result);
    activeTab = 'findings';
    render();
    r.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    r.hidden = true;
    showError('Could not read this file as an email: ' + err.message);
  }
}

function render() {
  const res = stack[stack.length - 1];
  const root = $('#results');
  const side = el('aside', { class: 'side' });
  const main = el('div', { class: 'main' });

  if (stack.length > 1) {
    side.append(el('div', { class: 'crumbs' },
      el('button', { class: 'btn small', type: 'button', onclick: () => { stack.pop(); activeTab = 'findings'; render(); } }, 'Back to outer email'),
      el('span', { class: 'muted', text: `Viewing attached email (level ${stack.length - 1})` })));
  }

  // Verdict: big number, a ruler with the four bands, then the counts.
  const lvl = res.verdict.level;
  const scale = el('div', { class: 'scale', role: 'img', 'aria-label': `Score ${res.score} out of 100, ${res.verdict.label}` },
    el('div', { class: 'scale-track' }, ['low', 'suspicious', 'likely', 'malicious'].map((k) => el('span', { class: `seg seg-${k}${k === lvl ? ' on' : ''}` }))),
    el('div', { class: 'scale-marker' }),
    el('div', { class: 'scale-ticks' }, [0, 15, 40, 70, 100].map((t) => el('span', { class: `t${t}`, text: String(t) }))));
  scale.style.setProperty('--pct', String(res.score));
  const counts = el('div', { class: 'counts' }, ['critical', 'high', 'medium', 'low'].filter((s) => res.counts[s]).map((s) => el('span', { class: `badge sev-${s}` }, `${res.counts[s]} ${s}`)));
  if (!res.findings.filter((f) => f.sev !== 'info').length) counts.append(el('span', { class: 'badge sev-pass', text: 'no warnings' }));
  if (res.overallScore > res.score) {
    const lvl = { malicious: 'critical', likely: 'high', suspicious: 'medium', low: 'low' }[res.overallVerdict.level];
    counts.append(el('span', { class: `badge sev-${lvl}`, text: `attached email: ${res.overallVerdict.label} ${res.overallScore}/100` }));
  }
  const base = safeName(res.summary.subject);
  side.append(
    el('section', { class: `verdict lvl-${lvl}` },
      el('h2', { class: 'label', text: 'Verdict' }),
      el('div', { class: 'score' }, el('span', { class: 'score-num', text: String(res.score) }), el('span', { class: 'score-of', text: '/ 100' })),
      el('div', { class: 'stamp', text: res.verdict.label }),
      el('p', { class: 'verdict-subject', text: res.summary.subject || '(no subject)' }),
      scale,
      counts),
    el('section', { class: 'exports' },
      el('h2', { class: 'label', text: 'Export' }),
      el('div', { class: 'export-list' },
        el('button', { class: 'btn', type: 'button', onclick: () => download(`hookscope_${base}.md`, toMarkdown(res), 'text/markdown') }, 'Download report (.md)'),
        el('button', { class: 'btn', type: 'button', onclick: () => download(`hookscope_${base}.json`, toJson(res), 'application/json') }, 'Download JSON'),
        el('button', { class: 'btn', type: 'button', onclick: () => download(`hookscope_${base}_iocs.csv`, toIocCsv(res), 'text/csv') }, 'Download IOCs (.csv)'))));

  // Message details.
  const a = res.auth;
  const authBadge = (label, v, aligned) => el('span', { class: `badge ${v === 'pass' ? 'sev-pass' : v === 'fail' ? 'sev-critical' : ['softfail', 'neutral', 'temperror'].includes(v) ? 'sev-medium' : 'sev-info'}`, title: aligned === undefined ? '' : aligned ? 'Aligned with the From domain' : 'Not aligned with the From domain' }, `${label} ${v}`);
  const s = res.summary;
  side.append(el('section', { class: 'facts' },
    el('h2', { class: 'label', text: 'Message details' }),
    kv('From', addr(s.from) || '(none)'),
    s.replyTo ? kv('Reply-To', addr(s.replyTo)) : null,
    s.returnPath ? kv('Return-Path', s.returnPath.address) : null,
    kv('To', s.to.map(addr).join(', ') || '(none)'),
    kv('Date', s.date || '(none)'),
    kv('Origin IP', s.originIp || 'unknown'),
    el('div', { class: 'kv' }, el('div', { class: 'k', text: 'Authentication' }), el('div', { class: 'auth-row' }, authBadge('SPF', a.spf, a.spfAligned), authBadge('DKIM', a.dkim, a.dkimAligned), authBadge('DMARC', a.dmarc))),
    kv('File', `${res.fileName || 'email'} (${fmtSize(res.size)})`)));

  // Attached emails.
  res.nested.forEach((n, i) => {
    main.append(el('div', { class: 'banner' },
      el('div', {},
        el('b', { text: 'This email has another email attached. ' }),
        el('span', { text: `"${n.summary.subject || '(no subject)'}" scored ${n.overallScore}/100 (${n.overallVerdict.label}).` }),
        el('div', { class: 'note', text: 'Common when a user reports phishing with "forward as attachment".' })),
      el('button', { class: 'btn primary', type: 'button', onclick: () => { n.fileName = `attachment ${i + 1}`; stack.push(n); activeTab = 'findings'; render(); } }, 'Open attached email')));
  });

  // Tabs.
  const tabs = [
    ['findings', 'Findings', res.findings.filter((f) => f.sev !== 'info').length],
    ['links', 'Links', res.urls.length],
    ['attachments', 'Attachments', res.attachments.length],
    ['route', 'Route & auth', res.hops.length],
    ['iocs', 'IOCs', res.iocs.domains.length + res.iocs.ips.length + res.iocs.urls.length + res.iocs.hashes.length],
    ['body', 'Message', null],
    ['headers', 'Headers', res.headers.length],
  ];
  const panel = el('div', { class: 'panel' });
  const nav = el('div', { class: 'tabs', role: 'tablist' }, tabs.map(([id, label, n]) => el('button', {
    class: 'tab' + (id === activeTab ? ' active' : ''), type: 'button', role: 'tab',
    onclick: () => { activeTab = id; render(); },
  }, label, n === null ? null : el('span', { class: 'n', text: String(n) }))));
  main.append(nav, panel);
  panel.append(PANELS[activeTab](res));

  root.replaceChildren(el('div', { class: 'report' }, side, main));
}

function kv(k, v) {
  return el('div', { class: 'kv' }, el('div', { class: 'k', text: k }), el('div', { class: 'v', text: v }));
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const PANELS = {
  findings(res) {
    const wrap = el('div');
    if (!res.findings.length) wrap.append(el('p', { class: 'muted', text: 'Nothing suspicious was found. Still use your judgement: a clean result does not prove an email is safe.' }));
    for (const f of res.findings) {
      wrap.append(el('div', { class: `finding f-${f.sev}` },
        el('div', {}, sevBadge(f.sev)),
        el('div', {},
          el('div', { class: 'f-title', text: f.title }),
          f.detail ? el('div', { class: 'f-detail', text: f.detail }) : null,
          f.evidence && f.evidence.length ? el('ul', { class: 'evidence' }, f.evidence.map((e) => el('li', { text: e }))) : null,
          el('div', { class: 'f-meta' }, el('span', { class: 'tag', text: f.category }), mitreTag(f.mitre)))));
    }
    if (res.positives.length) {
      wrap.append(el('div', { class: 'positives' },
        el('div', { class: 'k muted', text: 'Passed checks' }),
        el('ul', {}, res.positives.map((p) => el('li', { text: p }))),
        el('p', { class: 'note', text: 'Passing these checks only proves the email came from the domain shown. It does not prove that domain is honest.' })));
    }
    return wrap;
  },

  links(res) {
    if (!res.urls.length) return el('p', { class: 'muted', text: 'No links found.' });
    return el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, el('th', { text: 'Link' }), el('th', { text: 'Website' }), el('th', { text: 'Warnings' }), el('th', { text: 'Found in' }))),
      el('tbody', {}, res.urls.map((u) => el('tr', {},
        el('td', { class: 'mono' }, defang(u.url), u.shownAs.length ? el('div', { class: 'note', text: `Shown to reader as: ${u.shownAs[0]}` }) : null),
        el('td', { class: 'mono' }, u.unicodeHost && u.unicodeHost !== u.host ? `${u.host} (${u.unicodeHost})` : u.host || '', u.brand ? el('div', { class: 'note', text: `official ${u.brand} domain` }) : null),
        el('td', {}, el('div', { class: 'flags' }, u.flags.length ? u.flags.map((f) => el('span', { class: `badge sev-${f.sev}`, title: f.title + (f.note ? `: ${f.note}` : ''), text: f.id })) : el('span', { class: 'muted', text: 'none' }))),
        el('td', { class: 'note', text: u.sources.join(', ') }))))),
    el('p', { class: 'note', text: 'Links are shown defanged (hxxp, [.]) so they cannot be clicked by accident. Hover a warning to see what it means.' }));
  },

  attachments(res) {
    if (!res.attachments.length) return el('p', { class: 'muted', text: 'No attachments.' });
    return el('div', {}, res.attachments.map((a) => el('div', { class: 'att' },
      el('div', { class: 'att-head' },
        el('div', { class: 'att-name', text: a.filename }),
        el('div', { class: 'muted', text: `${a.typeLabel} | ${fmtSize(a.size)}${a.inline ? ' | inline' : ''}` })),
      el('div', { class: 'hash' }, `SHA-256  ${a.sha256}`),
      el('div', { class: 'hash' }, `SHA-1    ${a.sha1}`),
      el('div', { class: 'toolbar' },
        el('button', { class: 'btn small', type: 'button', onclick: () => copy(a.sha256) }, 'Copy SHA-256'),
        el('a', { class: 'tag', href: `https://www.virustotal.com/gui/file/${a.sha256}`, target: '_blank', rel: 'noopener noreferrer', title: 'Opens VirusTotal with only the hash. The file is not uploaded.' }, 'Look up hash on VirusTotal')),
      a.flags.length ? el('div', {}, a.flags.map((f) => el('div', { class: 'f-meta' }, sevBadge(f.sev), el('span', { text: f.title }), mitreTag(f.mitre)))) : el('div', { class: 'note', text: 'No warnings for this file.' }),
      a.entries && a.entries.length ? el('div', {}, el('div', { class: 'note', text: `Archive contents (${a.entries.length}):` }), el('ul', { class: 'inner' }, a.entries.slice(0, 40).map((e) => el('li', { text: `${e.name}${e.encrypted ? '  [password protected]' : ''}` })))) : null)));
  },

  route(res) {
    const a = res.auth;
    const wrap = el('div');
    wrap.append(el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, el('th', { text: 'Check' }), el('th', { text: 'Result' }), el('th', { text: 'What it means' }))),
      el('tbody', {},
        el('tr', {}, el('td', { text: 'SPF' }), el('td', { class: 'mono', text: `${a.spf}${a.mailfrom ? ' (' + a.mailfrom + ')' : ''}` }), el('td', { class: 'note', text: 'Is the sending server allowed to send for this domain?' })),
        el('tr', {}, el('td', { text: 'DKIM' }), el('td', { class: 'mono', text: `${a.dkim}${a.dkimDomains.length ? ' (' + a.dkimDomains.join(', ') + ')' : ''}` }), el('td', { class: 'note', text: 'Is the email digitally signed, and is the signature intact?' })),
        el('tr', {}, el('td', { text: 'DMARC' }), el('td', { class: 'mono', text: a.dmarc }), el('td', { class: 'note', text: 'Does the From address match a passing SPF or DKIM check?' })),
        el('tr', {}, el('td', { text: 'Checked by' }), el('td', { class: 'mono', text: a.server || 'unknown' }), el('td', { class: 'note', text: 'The mail server that recorded these results.' }))))));
    if (!res.hops.length) { wrap.append(el('p', { class: 'muted', text: 'No Received headers found.' })); return wrap; }
    wrap.append(el('h4', { text: 'Delivery route, oldest hop first' }));
    wrap.append(el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, ['#', 'From', 'By', 'IP', 'With', 'Delay', 'Time'].map((t) => el('th', { text: t })))),
      el('tbody', {}, res.hops.map((h) => el('tr', {},
        el('td', { text: String(h.hop) }),
        el('td', { class: 'mono', text: h.from }),
        el('td', { class: 'mono', text: h.by }),
        el('td', { class: 'mono' }, h.ip || '', h.ip && h.ip === res.summary.originIp ? el('div', {}, el('span', { class: 'badge sev-medium', text: 'origin' }), ' ', el('a', { class: 'tag', href: `https://www.abuseipdb.com/check/${h.ip}`, target: '_blank', rel: 'noopener noreferrer' }, 'AbuseIPDB')) : null),
        el('td', { class: 'mono', text: h.with }),
        el('td', { class: 'mono', text: h.delay === null ? '' : `${h.delay}s` }),
        el('td', { class: 'note', text: h.date })))))));
    return wrap;
  },

  iocs(res) {
    const text = toIocText(res);
    return el('div', {},
      el('div', { class: 'toolbar' },
        el('button', { class: 'btn small', type: 'button', onclick: () => copy(text) }, 'Copy defanged IOCs'),
        el('button', { class: 'btn small', type: 'button', onclick: () => copy([...res.iocs.domains, ...res.iocs.ips, ...res.iocs.urls, ...res.iocs.hashes.map((h) => h.sha256)].join('\n')) }, 'Copy raw (for blocklists)'),
        el('button', { class: 'btn small', type: 'button', onclick: () => download(`hookscope_${safeName(res.summary.subject)}_iocs.csv`, toIocCsv(res), 'text/csv') }, 'Download CSV')),
      el('pre', { class: 'box', text }),
      el('p', { class: 'note', text: 'Well known domains (real brand domains, free webmail, URL shorteners) are left out of the domain list on purpose, so you do not block them by mistake.' }));
  },

  body(res) {
    const wrap = el('div');
    const pre = el('pre', { class: 'box', text: res.body.text || '(empty)' });
    const tb = el('div', { class: 'toolbar' }, el('span', { class: 'note', text: 'Shown as plain text only. HTML is never rendered here.' }));
    if (res.body.hasHtml) {
      let showSource = false;
      tb.prepend(el('button', { class: 'btn small', type: 'button', onclick: (e) => { showSource = !showSource; pre.textContent = showSource ? res.body.html : res.body.text; e.target.textContent = showSource ? 'Show text' : 'Show HTML source'; } }, 'Show HTML source'));
    }
    wrap.append(tb, pre);
    return wrap;
  },

  headers(res) {
    return el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, el('th', { text: 'Header' }), el('th', { text: 'Value' }))),
      el('tbody', {}, res.headers.map((h) => el('tr', {}, el('td', { class: 'mono', text: h.name }), el('td', { class: 'mono', text: h.value }))))));
  },
};

// Wiring.
function init() {
  $('#ver').textContent = 'v' + VERSION;
  const dz = $('#dropzone');
  const fileInput = $('#file');
  const readFile = async (f) => run(new Uint8Array(await f.arrayBuffer()), f.name);

  fileInput.addEventListener('change', () => { if (fileInput.files[0]) readFile(fileInput.files[0]); fileInput.value = ''; });
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, () => dz.classList.remove('over')));
  dz.addEventListener('drop', (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) readFile(f); });
  // Allow dropping anywhere on the page.
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => { e.preventDefault(); const f = e.dataTransfer?.files[0]; if (f && !dz.contains(e.target)) readFile(f); });

  $('#paste-go').addEventListener('click', () => {
    const v = $('#paste').value;
    if (!v.trim()) { showError('Paste the email source first.'); return; }
    run(new TextEncoder().encode(v), 'pasted source');
  });

  document.querySelectorAll('[data-sample]').forEach((b) => b.addEventListener('click', async () => {
    const name = b.dataset.sample;
    try {
      const resp = await fetch(`samples/${name}`);
      if (!resp.ok) throw new Error(resp.statusText);
      run(new Uint8Array(await resp.arrayBuffer()), name);
    } catch (err) {
      showError(`Could not load the sample (${err.message}). If you opened index.html straight from disk, start the local server instead: npm run serve`);
    }
  }));
}

init();
