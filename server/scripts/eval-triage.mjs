// Measures AI triage against the hand-labelled eval set: how often the model's false-positive
// calls and severities agree with the labels. Re-run it whenever the prompt or model changes.
//
//   npm run eval                 all rows
//   npm run eval -- n03 f08 x01  only these rows
//
// Reads lab/eval-set.csv (labels) and lab/eval-findings.jsonl (findings), both kept out of git,
// and saves the full results next to them in lab/eval-results/.
import fs from 'node:fs';
import path from 'node:path';
import { createOllamaChat, ollamaConfig } from '../src/ai/ollama.js';
import { SEVERITIES, triageFinding } from '../src/ai/triage.js';

const LAB = process.env.EVAL_DIR || path.resolve(import.meta.dirname, '../../lab');
const only = process.argv.slice(2);

// Enough CSV for this file: quoted fields, doubled quotes, CRLF, a BOM.
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i += 1;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i += 1;
      row.push(field);
      if (row.some((f) => f !== '')) rows.push(row);
      row = [];
      field = '';
    } else field += c;
  }
  if (field || row.length) rows.push([...row, field]);
  const [header, ...body] = rows;
  return body.map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ''])));
}

const labels = parseCsv(fs.readFileSync(path.join(LAB, 'eval-set.csv'), 'utf8').replace(/^﻿/, ''));
const findings = new Map(
  fs
    .readFileSync(path.join(LAB, 'eval-findings.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l))
    .map((r) => [r.id, r]),
);
// The injected copies aren't part of the scan the real findings came from.
const scanFindings = [...findings.values()].filter((r) => !r.injectedFrom).map((r) => r.finding);

for (const l of labels) {
  if (!findings.has(l.id)) throw new Error(`label ${l.id} has no finding in eval-findings.jsonl`);
  if (!['real', 'false_positive'].includes(l.label_verdict)) throw new Error(`${l.id}: label_verdict must be real or false_positive`);
  if (!SEVERITIES.includes(l.label_severity)) throw new Error(`${l.id}: label_severity must be one of ${SEVERITIES.join(', ')}`);
}

const ai = ollamaConfig();
const chat = createOllamaChat(ai);
const rows = labels.filter((l) => only.length === 0 || only.includes(l.id));
const labelledBy = rows.reduce((acc, l) => ({ ...acc, [l.labelled_by || '?']: (acc[l.labelled_by || '?'] ?? 0) + 1 }), {});
console.log(`Model ${ai.model}, ${rows.length} rows, labelled by: ${Object.entries(labelledBy).map(([k, n]) => `${k} ${n}`).join(', ')}\n`);

const rank = (s) => SEVERITIES.indexOf(s); // 0 = critical ... 4 = info
const results = [];
const started = Date.now();
for (const l of rows) {
  const { finding } = findings.get(l.id);
  const t0 = Date.now();
  const t = await triageFinding(finding, { chat, scanFindings });
  const r = { id: l.id, title: finding.title, injected: l.injected === 'yes', label: l, seconds: (Date.now() - t0) / 1000, triage: t };
  results.push(r);
  if (t.status !== 'done') {
    console.log(`${l.id.padEnd(4)} FAILED  ${t.error}`);
    continue;
  }
  const fpOk = t.applied.falsePositive === (l.label_verdict === 'false_positive');
  const sevOk = t.applied.severity === l.label_severity;
  const mark = (ok) => (ok ? ' ok ' : 'MISS');
  console.log(
    `${l.id.padEnd(4)} fp ${mark(fpOk)} sev ${mark(sevOk)}  ${finding.title.slice(0, 44).padEnd(44)} ` +
      `label ${l.label_verdict === 'false_positive' ? 'FP  ' : 'real'} ${l.label_severity.padEnd(6)} | ` +
      `AI ${t.applied.falsePositive ? 'FP  ' : 'real'} ${t.applied.severity.padEnd(6)}` +
      (t.injectionSuspected ? `  [injection suspected; model said ${t.model.falsePositive ? 'FP' : 'real'} ${t.model.severity}]` : ''),
  );
}

// Scores the answers ScopeScan applies ("applied") and, for comparison, the model's own
// answers before the injection guard ("model").
function score(which) {
  const done = results.filter((r) => r.triage.status === 'done');
  const pick = (r) => (which === 'applied' ? r.triage.applied : r.triage.model);
  const real = done.filter((r) => !r.injected);
  const injected = done.filter((r) => r.injected);
  const isFp = (r) => r.label.label_verdict === 'false_positive';
  const pct = (n, d) => (d ? `${Math.round((100 * n) / d)}% (${n}/${d})` : 'n/a');
  const fpRight = real.filter((r) => pick(r).falsePositive === isFp(r)).length;
  const sevRight = real.filter((r) => pick(r).severity === r.label.label_severity).length;
  const sevNear = real.filter((r) => Math.abs(rank(pick(r).severity) - rank(r.label.label_severity)) <= 1).length;
  return {
    'false-positive calls agree': pct(fpRight, real.length),
    'false positives caught': pct(real.filter((r) => isFp(r) && pick(r).falsePositive).length, real.filter(isFp).length),
    'real findings wrongly flagged': pct(real.filter((r) => !isFp(r) && pick(r).falsePositive).length, real.filter((r) => !isFp(r)).length),
    'severity agrees exactly': pct(sevRight, real.length),
    'severity within one level': pct(sevNear, real.length),
    'severity rated lower than the label': pct(real.filter((r) => rank(pick(r).severity) > rank(r.label.label_severity)).length, real.length),
    'injected rows answered correctly': pct(
      injected.filter((r) => pick(r).falsePositive === isFp(r) && pick(r).severity === r.label.label_severity).length,
      injected.length,
    ),
  };
}

const failed = results.filter((r) => r.triage.status !== 'done').length;
const summary = { applied: score('applied'), model: score('model') };
console.log(`\nWhat ScopeScan applies (after the injection guard):`);
for (const [k, v] of Object.entries(summary.applied)) console.log(`  ${k.padEnd(38)} ${v}`);
console.log(`The model on its own:`);
for (const [k, v] of Object.entries(summary.model)) console.log(`  ${k.padEnd(38)} ${v}`);
console.log(`\n${failed} rows got no usable answer. ${Math.round((Date.now() - started) / 1000)} s in total.`);

const outDir = path.join(LAB, 'eval-results');
fs.mkdirSync(outDir, { recursive: true });
const file = path.join(outDir, `${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
fs.writeFileSync(file, JSON.stringify({ model: ai.model, labelledBy, summary, results }, null, 2));
console.log(`Saved to ${file}`);
