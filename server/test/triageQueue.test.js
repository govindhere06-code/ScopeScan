import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { AiUnavailableError } from '../src/ai/ollama.js';
import { createTriageQueue } from '../src/ai/queue.js';
import { queueTriage, triageStatus } from '../src/ai/store.js';
import { openDb } from '../src/db.js';
import { createScan, finishScan, getScan, saveToolResult } from '../src/scans.js';
import { finding } from '../src/tools/findings.js';
import { startApp } from './helpers/server.js';

const f = (title, severity = 'info') =>
  finding({ tool: 'nuclei', type: 'template-match', severity, title, location: 'http://127.0.0.1:3000', ref: title, raw: {} });

const scanResult = (findings) => ({ status: 'done', error: null, findings, log: '', version: 'v1', durationMs: 1 });

// A fake model that answers by finding title, with a delay so tests can see it running.
function modelAnswering(byTitle) {
  const chat = async (messages) => {
    await new Promise((r) => setTimeout(r, 5));
    const title = JSON.parse(messages[1].content.split('\n').slice(1, -1).join('\n')).title;
    const a = byTitle[title] ?? {};
    if (a instanceof Error) throw a;
    return JSON.stringify({
      false_positive: false,
      false_positive_reason: '',
      severity: 'info',
      severity_reason: '',
      explanation: `about ${title}`,
      fix: 'fix it',
      owasp: 'A02',
      cwe: '',
      ...a,
    });
  };
  chat.model = 'fake-model';
  return chat;
}

async function until(check, what) {
  const deadline = Date.now() + 2000;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

// Runs one fake scan through the real queue and returns its id once triage has finished.
async function scanThenTriage(app, findings) {
  const scanners = app.scanners;
  scanners.nuclei = async () => scanResult(findings);
  const { id } = (await app.fromPage('POST', '/api/scans', { target: 'localhost:3000', tools: ['nuclei'] })).body;
  await until(() => ['done', 'failed'].includes(triageStatus(app.db, id)), 'triage to finish');
  return id;
}

async function lab(chat) {
  const scanners = {};
  const app = await startApp({ chat, queue: { scanners } });
  await app.fromPage('POST', '/api/targets', { host: 'localhost', ports: '3000' });
  return Object.assign(app, { scanners });
}

describe('AI triage after a scan', () => {
  it('runs by itself when a scan finishes, and keeps every finding', async () => {
    const app = await lab(
      modelAnswering({
        'qm-system': { false_positive: true, false_positive_reason: 'matches any Angular app' },
        '/ftp': { severity: 'high', severity_reason: 'password database downloadable' },
      }),
    );
    const id = await scanThenTriage(app, [f('qm-system'), f('/ftp'), f('security.txt')]);
    const scan = (await app.send('GET', `/api/scans/${id}`)).body;

    assert.equal(scan.status, 'done');
    assert.deepEqual(
      { status: scan.triage.status, done: scan.triage.done, total: scan.triage.total, flagged: scan.triage.flagged },
      { status: 'done', done: 3, total: 3, flagged: 1 },
    );
    const byTitle = Object.fromEntries(scan.results[0].findings.map((x) => [x.title, x]));
    assert.equal(Object.keys(byTitle).length, 3, 'a flagged false positive is still listed');
    assert.equal(byTitle['qm-system'].triage.falsePositive, true);
    assert.equal(byTitle['qm-system'].severity, 'info', "the tool's own fields are untouched");
    assert.equal(byTitle['/ftp'].triage.severity, 'high');
    assert.equal(byTitle['/ftp'].triage.severityReason, 'password database downloadable');
    assert.deepEqual(byTitle['/ftp'].triage.owasp, { id: 'A02:2025', name: 'Security Misconfiguration' });
    assert.equal(byTitle['security.txt'].triage.explanation, 'about security.txt');

    const list = (await app.send('GET', '/api/scans')).body;
    assert.equal(list[0].triage.status, 'done');
    const events = (await app.send('GET', '/api/audit')).body.filter((e) => e.action === 'ai_triage');
    assert.deepEqual(events.map((e) => e.decision).reverse(), ['queued', 'started', 'done']);
    assert.match(events[0].reason, /3 findings, 1 flagged as likely false positives, 1 severity changes/);
    await app.close();
  });

  it('records a finding the model could not answer, and carries on', async () => {
    const app = await lab(modelAnswering({ broken: { severity: 'nonsense' } }));
    const id = await scanThenTriage(app, [f('broken'), f('fine')]);
    const scan = (await app.send('GET', `/api/scans/${id}`)).body;
    assert.equal(scan.triage.status, 'done');
    assert.match(scan.triage.error, /1 of 2 findings got no usable answer/);
    const [broken, fine] = scan.results[0].findings;
    assert.equal(broken.triage.status, 'failed');
    assert.equal(fine.triage.status, 'done');
    await app.close();
  });

  it('fails cleanly when the model is not running, leaving the scan as it was', async () => {
    const app = await lab(modelAnswering({ first: new AiUnavailableError("can't reach Ollama: is it running?") }));
    const id = await scanThenTriage(app, [f('first'), f('second')]);
    const scan = (await app.send('GET', `/api/scans/${id}`)).body;
    assert.equal(scan.status, 'done');
    assert.equal(scan.triage.status, 'failed');
    assert.match(scan.triage.error, /is it running/);
    assert.equal(scan.results[0].findings.length, 2);
    await app.close();
  });

  it('does nothing for a scan without findings', async () => {
    const app = await lab(modelAnswering({}));
    app.scanners.nuclei = async () => scanResult([]);
    const { id } = (await app.fromPage('POST', '/api/scans', { target: 'localhost:3000', tools: ['nuclei'] })).body;
    await until(() => getScan(app.db, id).status === 'done', 'scan');
    assert.equal(getScan(app.db, id).triage, null);
    await app.close();
  });
});

describe('re-running triage', () => {
  it('replaces the earlier opinions', async () => {
    let verdict = { false_positive: true, false_positive_reason: 'first opinion' };
    const chat = async (...args) => modelAnswering({ only: verdict })(...args);
    chat.model = 'fake-model';
    const app = await lab(chat);
    const id = await scanThenTriage(app, [f('only')]);

    verdict = {};
    const res = await app.fromPage('POST', `/api/scans/${id}/triage`, {});
    assert.equal(res.status, 202);
    await until(() => triageStatus(app.db, id) === 'done', 'second triage');
    const scan = (await app.send('GET', `/api/scans/${id}`)).body;
    assert.equal(scan.results[0].findings[0].triage.falsePositive, false);
    assert.equal(scan.triage.done, 1);
    await app.close();
  });

  it('refuses while the scan is still running, for unknown scans, and from other websites', async () => {
    const app = await lab(modelAnswering({}));
    let finish;
    app.scanners.nuclei = () => new Promise((resolve) => (finish = resolve));
    const { id } = (await app.fromPage('POST', '/api/scans', { target: 'localhost:3000', tools: ['nuclei'] })).body;
    await until(() => finish, 'scan to start');
    assert.equal((await app.fromPage('POST', `/api/scans/${id}/triage`, {})).status, 409);
    assert.equal((await app.fromPage('POST', '/api/scans/999/triage', {})).status, 404);
    const foreign = await app.send('POST', `/api/scans/${id}/triage`, {
      body: {},
      headers: { Origin: 'http://evil.test', 'X-ScopeScan': '1', 'Content-Type': 'application/json' },
    });
    assert.equal(foreign.status, 403);
    finish(scanResult([]));
    await app.close();
  });

  it('answers 503 when AI triage is turned off', async () => {
    const app = await startApp();
    assert.equal((await app.fromPage('POST', '/api/scans/1/triage', {})).status, 503);
    await app.close();
  });
});

describe('server restart', () => {
  it('picks up triage that was interrupted', async () => {
    const db = openDb(':memory:');
    const id = createScan(db, { target: { url: 'http://127.0.0.1:3000', host: '127.0.0.1', port: 3000 }, tools: ['nuclei'] });
    saveToolResult(db, id, 'nuclei', scanResult([f('a'), f('b')]));
    finishScan(db, id, 'done');
    queueTriage(db, id, 'fake-model');
    db.prepare("UPDATE scan_triage SET status = 'running' WHERE scan_id = ?").run(id);

    createTriageQueue({ db, chat: modelAnswering({}) }).resume();
    await until(() => triageStatus(db, id) === 'done', 'resumed triage');
    assert.equal(getScan(db, id).triage.done, 2);
  });
});
