#!/usr/bin/env node
// HookScope command line. Same engine as the web app.
//   node cli/hookscope.mjs suspicious.eml
//   node cli/hookscope.mjs inbox/*.eml --fail-above 40
//   node cli/hookscope.mjs mail.eml --json > report.json

import { readFile, stat, readdir } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { analyzeEmail, VERSION } from '../src/engine.js';
import { toJson, toMarkdown, toIocText, toIocCsv } from '../src/report.js';

const HELP = `HookScope ${VERSION}: offline phishing email analyzer

Usage: hookscope <file.eml | folder> [...] [options]

Options:
  --json            Print the full JSON report
  --md              Print a Markdown report (good for tickets)
  --iocs            Print defanged IOCs only
  --csv             Print IOCs as CSV
  --fail-above <n>  Exit with code 2 if any email scores n or more (for scripts and CI)
  --no-color        Plain output
  -h, --help        Show this help
`;

const args = process.argv.slice(2);
if (!args.length || args.includes('-h') || args.includes('--help')) {
  process.stdout.write(HELP);
  process.exit(args.length ? 0 : 1);
}

const opt = { json: false, md: false, iocs: false, csv: false, failAbove: null, color: process.stdout.isTTY };
const inputs = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--json') opt.json = true;
  else if (a === '--md') opt.md = true;
  else if (a === '--iocs') opt.iocs = true;
  else if (a === '--csv') opt.csv = true;
  else if (a === '--no-color') opt.color = false;
  else if (a === '--fail-above') opt.failAbove = Number(args[++i]);
  else if (a.startsWith('--')) { console.error(`Unknown option ${a}`); process.exit(1); }
  else inputs.push(a);
}

const C = (code) => (s) => (opt.color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const col = { critical: C('1;31'), high: C('31'), medium: C('33'), low: C('36'), info: C('90'), ok: C('32'), dim: C('90'), bold: C('1') };
const verdictColor = { malicious: col.critical, likely: col.high, suspicious: col.medium, low: col.ok };

async function expand(p) {
  const s = await stat(p);
  if (!s.isDirectory()) return [p];
  const names = await readdir(p);
  return names.filter((n) => /\.eml$/i.test(n)).map((n) => join(p, n));
}

function printPretty(file, r) {
  const v = verdictColor[r.verdict.level];
  console.log('');
  console.log(col.bold(basename(file)));
  console.log(`  ${v(`${r.verdict.label.toUpperCase()}  ${r.score}/100`)}${r.overallScore > r.score ? col.dim(`   (attached email: ${r.overallScore}/100)`) : ''}`);
  console.log(col.dim(`  Subject: ${r.summary.subject || '(none)'}`));
  console.log(col.dim(`  From:    ${r.summary.from.name ? r.summary.from.name + ' ' : ''}<${r.summary.from.address}>`));
  console.log(col.dim(`  Auth:    SPF ${r.auth.spf} | DKIM ${r.auth.dkim} | DMARC ${r.auth.dmarc} | origin ${r.summary.originIp || 'unknown'}`));
  for (const f of r.findings.filter((x) => x.sev !== 'info')) {
    console.log(`  ${col[f.sev](`[${f.sev.toUpperCase()}]`.padEnd(11))}${f.title}${f.mitre ? col.dim(`  ${f.mitre}`) : ''}`);
  }
  for (const n of r.nested) {
    console.log(col.dim(`  Attached email: "${n.summary.subject}" ${n.overallScore}/100 ${n.overallVerdict.label}`));
    for (const f of n.findings.filter((x) => ['critical', 'high'].includes(x.sev))) console.log(`    ${col[f.sev](`[${f.sev.toUpperCase()}]`.padEnd(11))}${f.title}`);
  }
}

let worst = 0;
const files = (await Promise.all(inputs.map(expand))).flat();
if (!files.length) { console.error('No .eml files found.'); process.exit(1); }
const jsonOut = [];
for (const file of files) {
  let r;
  try {
    r = await analyzeEmail(new Uint8Array(await readFile(file)));
  } catch (err) {
    console.error(`${file}: ${err.message}`);
    continue;
  }
  worst = Math.max(worst, r.overallScore);
  if (opt.json) jsonOut.push({ file, ...JSON.parse(toJson(r)) });
  else if (opt.md) console.log(toMarkdown(r));
  else if (opt.iocs) console.log(toIocText(r));
  else if (opt.csv) console.log(toIocCsv(r));
  else printPretty(file, r);
}
if (opt.json) console.log(JSON.stringify(jsonOut.length === 1 ? jsonOut[0] : jsonOut, null, 2));
if (!opt.json && !opt.md && !opt.iocs && !opt.csv) console.log('');
if (opt.failAbove !== null && worst >= opt.failAbove) process.exit(2);
