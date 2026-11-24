// Attachment checks: real file type, risky names, macros, archives, PDFs, RTF, HTML smuggling.

import { latin1, decodeText, digest, indexOfBytes, utf16le } from './util.js';
import { scanHtml, scanActiveContent, extractUrls } from './html.js';

const DANGEROUS_EXT = new Set(['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'psm1', 'msi', 'msp', 'lnk', 'jar', 'cpl', 'dll', 'reg', 'chm', 'xll', 'appx', 'msix', 'appinstaller', 'url', 'library-ms', 'scf', 'apk', 'inf', 'gadget', 'application', 'sct', 'wsc']);
const DISK_IMAGE_EXT = new Set(['iso', 'img', 'vhd', 'vhdx']);
const MACRO_EXT = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm']);
const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'cab', 'arj', 'ace', 'lzh', 'z', 'xz', 'bz2']);
const WEB_EXT = new Set(['html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml', 'svg', 'svgz']);
const DECOY_EXT = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|rtf|zip|rar|mp3|mp4|wav)\s*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|iso|img|vhdx?|html?|shtml|svg|jar|msi|ps1|apk|one|xll)$/i;

// What each extension should look like inside.
const EXPECTED = {
  pdf: 'pdf', docx: 'zip', xlsx: 'zip', pptx: 'zip', docm: 'zip', xlsm: 'zip', pptm: 'zip', odt: 'zip', ods: 'zip',
  zip: 'zip', jar: 'zip', apk: 'zip', doc: 'ole', xls: 'ole', ppt: 'ole', msg: 'ole', msi: 'ole', exe: 'pe', dll: 'pe',
  scr: 'pe', png: 'png', jpg: 'jpeg', jpeg: 'jpeg', gif: 'gif', rtf: 'rtf', iso: 'iso', lnk: 'lnk', rar: 'rar',
  '7z': '7z', gz: 'gzip', one: 'onenote', html: 'html', htm: 'html', svg: 'svg', txt: 'text', csv: 'text',
};

const LABELS = {
  pe: 'Windows program (EXE/DLL)', elf: 'Linux program', pdf: 'PDF document', zip: 'ZIP archive / Office file',
  ole: 'Old Office / OLE file', rar: 'RAR archive', '7z': '7-Zip archive', gzip: 'GZIP archive', iso: 'ISO disk image',
  lnk: 'Windows shortcut (LNK)', rtf: 'RTF document', png: 'PNG image', jpeg: 'JPEG image', gif: 'GIF image',
  onenote: 'OneNote file', cab: 'CAB archive', html: 'HTML page', svg: 'SVG image (can contain script)',
  text: 'Plain text', unknown: 'Unknown',
};

export function sniff(b) {
  const at = (i, arr) => arr.every((v, j) => b[i + j] === v);
  if (b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a) return 'pe';
  if (at(0, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (at(0, [0x25, 0x50, 0x44, 0x46])) return 'pdf';
  if (at(0, [0x50, 0x4b, 0x03, 0x04]) || at(0, [0x50, 0x4b, 0x05, 0x06])) return 'zip';
  if (at(0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole';
  if (at(0, [0x52, 0x61, 0x72, 0x21])) return 'rar';
  if (at(0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (at(0, [0x1f, 0x8b])) return 'gzip';
  if (at(0, [0x4d, 0x53, 0x43, 0x46])) return 'cab';
  if (at(0, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return 'lnk';
  if (at(0, [0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d])) return 'onenote';
  if (b.length > 0x8006 && at(0x8001, [0x43, 0x44, 0x30, 0x30, 0x31])) return 'iso';
  if (at(0, [0x7b, 0x5c, 0x72, 0x74])) return 'rtf';
  if (at(0, [0x89, 0x50, 0x4e, 0x47])) return 'png';
  if (at(0, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (at(0, [0x47, 0x49, 0x46, 0x38])) return 'gif';
  const head = latin1(b.subarray(0, 1024)).replace(/^﻿|^\xEF\xBB\xBF/, '').trimStart().toLowerCase();
  if (/^<svg|^<\?xml[\s\S]*<svg/.test(head)) return 'svg';
  if (/^<!doctype html|^<html|^<head|^<body|^<script|^<meta|^<form/.test(head)) return 'html';
  if (head.length && !/[\x00-\x08\x0e-\x1f]/.test(head)) return 'text';
  return 'unknown';
}

export function readZipEntries(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const entries = [];
  for (let n = 0; n < count && p + 46 <= bytes.length; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const flags = dv.getUint16(p + 8, true);
    const nlen = dv.getUint16(p + 28, true);
    const elen = dv.getUint16(p + 30, true);
    const clen = dv.getUint16(p + 32, true);
    entries.push({
      name: decodeText(bytes.subarray(p + 46, p + 46 + nlen), 'utf-8'),
      encrypted: !!(flags & 1),
      method: dv.getUint16(p + 10, true),
      csize: dv.getUint32(p + 20, true),
      usize: dv.getUint32(p + 24, true),
      offset: dv.getUint32(p + 42, true),
    });
    p += 46 + nlen + elen + clen;
  }
  return entries;
}

// Inflate with a hard output limit so a zip bomb cannot exhaust memory.
export async function inflate(data, format, maxBytes = 16 * 1024 * 1024) {
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream(format)).getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) { await reader.cancel(); break; }
      chunks.push(value);
    }
    const out = new Uint8Array(Math.min(total, maxBytes));
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out.subarray(0, off);
  } catch {
    return null;
  }
}

export async function readZipEntry(bytes, e) {
  if (e.encrypted || e.usize > 8 * 1024 * 1024) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const p = e.offset;
  if (p + 30 > bytes.length || dv.getUint32(p, true) !== 0x04034b50) return null;
  const start = p + 30 + dv.getUint16(p + 26, true) + dv.getUint16(p + 28, true);
  const data = bytes.subarray(start, start + e.csize);
  if (e.method === 0) return data;
  if (e.method === 8) return inflate(data, 'deflate-raw');
  return null;
}

function extOf(name) {
  const m = /\.([a-z0-9-]{1,14})$/i.exec(String(name || '').trim());
  return m ? m[1].toLowerCase() : '';
}

async function scanPdf(bytes) {
  const s = latin1(bytes);
  const out = { keys: [], urls: [] };
  let text = s;
  // Inflate a limited number of compressed streams so links and scripts inside them are visible too.
  const re = /\/FlateDecode[\s\S]{0,300}?stream\r?\n/g;
  let m;
  let count = 0;
  while ((m = re.exec(s)) && count < 60) {
    const start = m.index + m[0].length;
    const end = s.indexOf('endstream', start);
    if (end < 0 || end - start > 4 * 1024 * 1024) continue;
    const inflated = await inflate(bytes.subarray(start, end), 'deflate');
    if (inflated) { text += '\n' + latin1(inflated); count++; }
  }
  const checks = [
    [/\/JavaScript\b|\/JS\s*[(<\[]/, 'JavaScript'],
    [/\/OpenAction\b/, 'Runs an action when opened (/OpenAction)'],
    [/\/AA\b/, 'Automatic actions (/AA)'],
    [/\/Launch\b/, 'Can launch programs (/Launch)'],
    [/\/EmbeddedFile\b/, 'Contains embedded files'],
    [/\/SubmitForm\b/, 'Submits form data to a server'],
    [/\/XFA\b/, 'XFA form'],
  ];
  for (const [r, label] of checks) if (r.test(text)) out.keys.push(label);
  const uriRe = /\/URI\s*\(([^)]{4,2000})\)/g;
  while ((m = uriRe.exec(text))) out.urls.push(m[1].replace(/\\(.)/g, '$1'));
  return out;
}

export async function analyzeAttachment(node) {
  const bytes = node.bytes || new Uint8Array(0);
  const filename = node.filename || '';
  const ext = extOf(filename);
  const type = sniff(bytes);
  const flags = [];
  const urls = [];
  const add = (sev, title, detail = '', mitre = '') => flags.push({ sev, title, detail, mitre });

  const att = {
    filename: filename || '(no name)',
    contentType: node.contentType,
    size: bytes.length,
    inline: node.disposition === 'inline' || (!!node.contentId && node.disposition !== 'attachment'),
    ext,
    type,
    typeLabel: node.contentType === 'message/rfc822' || ext === 'eml' ? 'Email message (analyzed separately)' : LABELS[type] || type,
    sha256: await digest('SHA-256', bytes),
    sha1: await digest('SHA-1', bytes),
    flags,
    urls,
    entries: null,
  };

  // File name tricks.
  if (/[‪-‮⁦-⁩]/.test(filename)) add('critical', 'File name uses a hidden right-to-left character to fake its extension', JSON.stringify(filename), 'T1036.002');
  if (DECOY_EXT.test(filename)) add('high', 'File name has a fake double extension', filename, 'T1036.007');
  else if (/\s{4,}\.\w+$/.test(filename)) add('medium', 'File name hides its real extension after many spaces', filename, 'T1036');
  if (DANGEROUS_EXT.has(ext)) add('high', `.${ext} files can run code when opened`, filename, 'T1204.002');
  if (DISK_IMAGE_EXT.has(ext) || type === 'iso') add('high', 'Disk image attachment (used to slip malware past Windows download warnings)', filename, 'T1553.005');
  if (MACRO_EXT.has(ext)) add('high', 'Macro-enabled Office file', filename, 'T1204.002');
  if (ext === 'one' || type === 'onenote') add('high', 'OneNote attachment (abused to hide malicious scripts behind fake buttons)', filename, 'T1204.002');
  if (type === 'pe' || type === 'elf') add('high', 'The attachment is a program', att.typeLabel, 'T1204.002');
  if (type === 'lnk') add('high', 'The attachment is a Windows shortcut that can run commands', '', 'T1204.002');

  // Real type vs claimed extension.
  const expected = EXPECTED[ext];
  if (expected && type !== 'unknown' && expected !== type && !(expected === 'text' && type === 'html')) {
    add(['pe', 'elf', 'lnk', 'html', 'svg', 'rtf'].includes(type) ? 'high' : 'medium',
      `Real file type does not match its name: named .${ext} but it is a ${LABELS[type] || type}`, '', 'T1036.008');
  }

  // Archives and Office files.
  if (type === 'zip') {
    const entries = readZipEntries(bytes) || [];
    att.entries = entries.slice(0, 200).map((e) => ({ name: e.name, size: e.usize, encrypted: e.encrypted }));
    const names = entries.map((e) => e.name);
    const isOoxml = names.includes('[Content_Types].xml');
    if (entries.some((e) => e.encrypted)) add('medium', 'Password-protected archive (security scanners cannot look inside)', '', 'T1027.013');
    for (const e of entries) {
      const ee = extOf(e.name);
      if (DANGEROUS_EXT.has(ee) || DISK_IMAGE_EXT.has(ee)) add('high', `Archive contains a risky file: ${e.name}`, '', 'T1204.002');
      else if (DECOY_EXT.test(e.name)) add('high', `Archive contains a file with a fake double extension: ${e.name}`, '', 'T1036.007');
      else if (WEB_EXT.has(ee)) add('medium', `Archive contains a web page file: ${e.name}`);
      else if (ARCHIVE_EXT.has(ee)) add('low', `Archive inside an archive: ${e.name}`, '', 'T1027');
    }
    if (isOoxml) {
      if (names.some((n) => /vbaProject\.bin$/i.test(n))) add('high', 'Office file contains VBA macros', '', 'T1204.002');
      if (names.some((n) => /activeX/i.test(n))) add('medium', 'Office file contains ActiveX controls');
      if (names.some((n) => /oleObject\d*\.bin$/i.test(n))) add('medium', 'Office file has embedded OLE objects', '', 'T1559.001');
      for (const e of entries.filter((x) => /\.rels$/i.test(x.name)).slice(0, 40)) {
        const data = await readZipEntry(bytes, e);
        if (!data) continue;
        const xml = decodeText(data, 'utf-8');
        const relRe = /<Relationship\b[^>]*>/gi;
        let m;
        while ((m = relRe.exec(xml))) {
          const tag = m[0];
          if (!/TargetMode\s*=\s*"External"/i.test(tag)) continue;
          const target = (/Target\s*=\s*"([^"]+)"/i.exec(tag) || [])[1] || '';
          const relType = (/Type\s*=\s*"([^"]+)"/i.exec(tag) || [])[1] || '';
          if (/attachedTemplate|oleObject|frame|subDocument/i.test(relType) && /^(https?:|\\\\|file:)/i.test(target)) {
            add('high', 'Office file loads a template or object from the internet when opened (remote template injection)', target, 'T1221');
            urls.push(target);
          } else if (/^https?:/i.test(target)) urls.push(target);
        }
      }
    }
  }

  if (type === 'ole') {
    if (indexOfBytes(bytes, utf16le('_VBA_PROJECT')) >= 0 || indexOfBytes(bytes, utf16le('Macros')) >= 0) {
      add('high', 'Old-format Office file contains VBA macros', '', 'T1204.002');
    }
  }

  if (type === 'pdf') {
    const pdf = await scanPdf(bytes);
    for (const k of pdf.keys) {
      add(/JavaScript|Launch/.test(k) ? 'high' : /OpenAction|AA|Embedded/.test(k) ? 'medium' : 'low', `PDF feature: ${k}`);
    }
    urls.push(...pdf.urls);
    if (pdf.urls.length) add('info', `PDF contains ${pdf.urls.length} link(s)`, '', 'T1566.001');
  }

  if (type === 'rtf') {
    const s = latin1(bytes.subarray(0, 4 * 1024 * 1024)).toLowerCase();
    if (/\\objdata|\\objupdate|\\object\b/.test(s)) add('high', 'RTF file contains embedded objects', '', 'T1203');
    if (/equation\.3|0002ce02/.test(s)) add('critical', 'RTF file targets the old Equation Editor bug (CVE-2017-11882)', '', 'T1203');
  }

  if (type === 'html' || type === 'svg' || WEB_EXT.has(ext)) {
    const src = decodeText(bytes, node.params?.charset || 'utf-8');
    const html = scanHtml(src);
    const active = scanActiveContent(src);
    urls.push(...html.urls.map((u) => u.url), ...extractUrls(src));
    add('medium', type === 'svg' || ext === 'svg' ? 'SVG image attachment (can carry script and links)' : 'HTML file attachment (opens a local web page outside normal browser protection)', '', 'T1566.001');
    if (html.passwordInputs || (html.forms.length && /password|passwd|pass|kata laluan/i.test(src))) {
      add('critical', 'Attachment is a fake login page that asks for a password', '', 'T1056.003');
    }
    if (active.telegram) add('critical', 'Attachment sends data to a Telegram bot (stolen passwords are often sent this way)', '', 'T1567');
    if (active.discordHook) add('high', 'Attachment sends data to a Discord webhook', '', 'T1567');
    const smuggle = active.hits.filter((h) => !/network|Redirects/.test(h));
    if (smuggle.length >= 3) add('high', 'HTML smuggling: the file builds and drops another file from hidden data', smuggle.join('; '), 'T1027.006');
    else if (active.hits.length) add('medium', 'Attachment contains active script', active.hits.join('; '), 'T1059.007');
    if (html.metaRefresh.length) add('medium', 'Attachment redirects to a website as soon as it opens', html.metaRefresh[0]);
  }

  if (ARCHIVE_EXT.has(ext) && !flags.length) add('low', 'Archive attachment', filename);

  return att;
}
