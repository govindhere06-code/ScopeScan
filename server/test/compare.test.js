import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { compareScans, fingerprint } from '../src/compare.js';
import { openDb } from '../src/db.js';
import { reportData } from '../src/report/data.js';
import { reportHtml } from '../src/report/html.js';
import { createScan, finishScan, markScanRunning, saveToolResult } from '../src/scans.js';
import { ScopeError } from '../src/scope.js';
import { finding } from '../src/tools/findings.js';
import { startApp } from './helpers/server.js';

const JUICE = { url: 'http://127.0.0.1:3000', host: '127.0.0.1', port: 3000 };
const DVWA = { url: 'http://127.0.0.1:8080', host: '127.0.0.1', port: 8080 };

const header = (name, extra = {}) =>
  finding({
    tool: 'nuclei',
    type: 'template-match',
    title: 'HTTP Missing Security Headers',
    location: 'http://127.0.0.1:3000',
    ref: 'http-missing-security-headers',
    raw: { 'matcher-name': name, ...extra },
  });
const path = (p, length = 100) =>
  finding({ tool: 'ffuf', type: 'path', title: `200 ${p}`, location: `http://127.0.0.1:3000${p}`, ref: p, raw: { length } });

// One finished scan: { tool: findings } for tools that completed, { tool: 'failed' } for ones that didn't.
function scan(db, target, results) {
  const tools = Object.keys(results);
  const id = createScan(db, { target, tools });
  markScanRunning(db, id, { id: 1, host: target.host, ports: String(target.port) });
  for (const [tool, findings] of Object.entries(results)) {
    const failed = findings === 'failed';
    saveToolResult(db, id, tool, {
      status: failed ? 'failed' : 'done',
      error: failed ? `${tool} crashed` : null,
      findings: failed ? [] : findings,
      log: '',
    });
  }
  finishScan(db, id, Object.values(results).includes('failed') ? 'failed' : 'done');
  return id;
}

describe('comparing a scan with the previous one', () => {
  it('finds what is new, what is no longer found, and what stayed', () => {
    const db = openDb(':memory:');
    scan(db, JUICE, { nuclei: [header('csp'), header('hsts'), header('referrer-policy')], ffuf: [path('/ftp')] });
    const id = scan(db, JUICE, { nuclei: [header('csp'), header('referrer-policy'), header('x-frame-options')], ffuf: [path('/ftp', 999)] });

    const c = compareScans(db, id);
    assert.equal(c.previous.id, 1);
    assert.deepEqual(c.compared.sort(), ['ffuf', 'nuclei']);
    assert.deepEqual(c.gone.map((g) => g.matcher), ['hsts']);
    assert.equal(c.newIds.length, 1);
    assert.equal(c.unchanged, 3, 'a different response size is still the same /ftp');
  });

  it('does not count findings from a tool that failed in either scan as gone or new', () => {
    const db = openDb(':memory:');
    scan(db, JUICE, { nuclei: [header('csp')], ffuf: [path('/ftp'), path('/media')] });
    const id = scan(db, JUICE, { nuclei: 'failed', ffuf: [path('/ftp')] });
    const c = compareScans(db, id);
    assert.deepEqual(c.compared, ['ffuf']);
    assert.deepEqual(c.notCompared, [{ tool: 'nuclei', reason: 'did not complete in scan #2' }]);
    assert.deepEqual(c.gone.map((g) => g.location), ['http://127.0.0.1:3000/media']);
  });

  it('skips earlier scans of other targets, still-running scans and scans with no tool in common', () => {
    const db = openDb(':memory:');
    const first = scan(db, JUICE, { nuclei: [header('csp')] });
    scan(db, DVWA, { nuclei: [header('csp')] });
    scan(db, JUICE, { nmap: [] });
    createScan(db, { target: JUICE, tools: ['nuclei'] }); // queued
    const id = scan(db, JUICE, { nuclei: [header('csp')] });
    assert.equal(compareScans(db, id).previous.id, first);
  });

  it('says so when there is nothing to compare with', () => {
    const db = openDb(':memory:');
    const id = scan(db, JUICE, { nuclei: [header('csp')] });
    assert.deepEqual(compareScans(db, id), { previous: null, compared: [], notCompared: [], newIds: [], gone: [], unchanged: 0 });
    assert.equal(compareScans(db, 99), null);
  });

  it('can compare with a chosen scan, but only of the same target', () => {
    const db = openDb(':memory:');
    const a = scan(db, JUICE, { nuclei: [header('csp')] });
    scan(db, JUICE, { nuclei: [] });
    const other = scan(db, DVWA, { nuclei: [] });
    const id = scan(db, JUICE, { nuclei: [header('csp')] });
    assert.equal(compareScans(db, id, a).unchanged, 1);
    assert.throws(() => compareScans(db, id, other), ScopeError);
    assert.throws(() => compareScans(db, id, id), ScopeError);
    assert.throws(() => compareScans(db, id, 99), ScopeError);
  });

  it('matches nuclei findings by template and matcher, not by what they extracted', () => {
    assert.equal(fingerprint(header('csp', { 'extracted-results': ['a'] })), fingerprint(header('csp', { 'extracted-results': ['b'] })));
    assert.notEqual(fingerprint(header('csp')), fingerprint(header('hsts')));
  });
});

describe('the comparison on the page and in the report', () => {
  it('is served at /api/scans/:id/comparison', async () => {
    const app = await startApp();
    scan(app.db, JUICE, { nuclei: [header('csp'), header('hsts')] });
    const id = scan(app.db, JUICE, { nuclei: [header('csp')] });
    const res = await app.send('GET', `/api/scans/${id}/comparison`);
    assert.equal(res.status, 200);
    assert.equal(res.body.gone[0].matcher, 'hsts');
    assert.equal((await app.send('GET', `/api/scans/${id}/comparison?with=abc`)).status, 400);
    assert.equal((await app.send('GET', '/api/scans/99/comparison')).status, 404);
    await app.close();
  });

  it('shows up in the report, worded as "no longer found", not "fixed"', () => {
    const db = openDb(':memory:');
    scan(db, JUICE, { nuclei: [header('csp'), header('hsts')] });
    const id = scan(db, JUICE, { nuclei: [header('csp'), header('x-frame-options')] });
    const r = reportData(db, id);
    assert.deepEqual(r.findings.map((f) => [f.heading, f.isNew]), [
      ['HTTP Missing Security Headers: csp', false],
      ['HTTP Missing Security Headers: x-frame-options', true],
    ]);
    const html = reportHtml(r);
    assert.match(html, /Changes since scan #1/);
    assert.match(html, /1 new finding[\s\S]*?1 finding no longer found/);
    assert.match(html, /HTTP Missing Security Headers: hsts/);
    assert.match(html, /may have been fixed, or the tool may not have reached it this time/);
  });

  it('is left out of the report of a first scan', () => {
    const db = openDb(':memory:');
    const id = scan(db, JUICE, { nuclei: [header('csp')] });
    assert.doesNotMatch(reportHtml(reportData(db, id)), /Changes since/);
  });
});
