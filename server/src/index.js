import { createOllamaChat, ollamaConfig } from './ai/ollama.js';
import { createTriageQueue } from './ai/queue.js';
import { createApp } from './app.js';
import { defaultDbPath, openDb } from './db.js';
import { createScanQueue, DEFAULT_TIMEOUT_MS, recoverScans } from './jobs.js';
import { findBrowser, htmlToPdf } from './report/pdf.js';

// Hard-coded on purpose: ScopeScan must never be reachable from the network (no 0.0.0.0).
const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT ?? 4000);
const dbPath = process.env.DB_PATH || defaultDbPath();
const allowedOrigins = (process.env.CLIENT_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

function positiveNumber(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!(value > 0)) throw new Error(`${name} must be a positive number, got "${raw}"`);
  return value;
}

const timeoutMs = positiveNumber('SCAN_TIMEOUT_MINUTES', DEFAULT_TIMEOUT_MS / 60_000) * 60_000;
const concurrency = positiveNumber('SCAN_CONCURRENCY', 1);
const aiEnabled = process.env.AI_TRIAGE !== 'off';
// Checked before anything starts: a non-local model URL stops the server instead of
// quietly sending scan data elsewhere.
const ai = aiEnabled ? ollamaConfig() : null;

const db = openDb(dbPath);
const { killed, stale } = await recoverScans(db);
if (stale.length) console.log(`Marked ${stale.length} interrupted scan(s) as failed`);
if (killed.length) console.log(`Killed ${killed.length} scanner process(es) left over from the last run`);

const triage = ai ? createTriageQueue({ db, chat: createOllamaChat(ai) }) : null;
triage?.resume();
const queue = createScanQueue({ db, concurrency, timeoutMs, onFinished: (scanId) => triage?.enqueue(scanId) });

const browser = findBrowser();
const renderPdf = browser ? (html) => htmlToPdf(html, { browser }) : null;

const server = createApp({ db, allowedOrigins, queue, triage, renderPdf }).listen(PORT, HOST, () => {
  console.log(`ScopeScan API listening on http://${HOST}:${PORT}`);
  console.log(`Database: ${dbPath}`);
  console.log(`Scans: ${queue.limit} at a time, time limit ${timeoutMs / 60_000} minutes each`);
  console.log(ai ? `AI triage: ${ai.model} at ${ai.url}` : 'AI triage: off');
  console.log(browser ? `PDF reports: printed with ${browser}` : 'PDF reports: off (no Edge or Chrome found; set REPORT_BROWSER)');
});

// Ctrl+C: don't leave scanners running with nobody to collect their results.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    queue.shutdown();
    triage?.shutdown();
    server.close();
    db.close();
    process.exit(0);
  });
}
