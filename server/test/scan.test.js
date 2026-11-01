import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers/server.js';

// Stands in for nuclei: records what it was asked to scan, and finishes when told to.
function fakeScanner() {
  const calls = [];
  let finish;
  return {
    calls,
    finish: (result) => finish(result),
    runNuclei(target) {
      calls.push(target.url);
      return new Promise((resolve) => (finish = resolve));
    },
  };
}

const DONE = { status: 'done', error: null, findings: [{ templateId: 'x' }], versions: null, durationMs: 1 };

let app;
let scanner;
before(async () => {
  scanner = fakeScanner();
  app = await startApp({ scanner });
  await app.fromPage('POST', '/api/targets', { host: 'localhost', ports: '3000' });
});
after(() => app.close());

describe('nuclei scans go through the scope gate', () => {
  it('refuses an unlisted target without starting a scan', async () => {
    const res = await app.fromPage('POST', '/api/scans/nuclei', { target: 'scanme.nmap.org' });
    assert.equal(res.status, 403);
    assert.equal(scanner.calls.length, 0);
  });

  it('refuses a listed host on an unlisted port', async () => {
    const res = await app.fromPage('POST', '/api/scans/nuclei', { target: 'localhost:8080' });
    assert.equal(res.status, 403);
    assert.equal(scanner.calls.length, 0);
  });

  it('refuses a flag-like target', async () => {
    const res = await app.fromPage('POST', '/api/scans/nuclei', { target: '-l targets.txt' });
    assert.equal(res.status, 403);
    assert.equal(scanner.calls.length, 0);
  });

  it('refuses a scan requested by another website', async () => {
    const res = await app.send('POST', '/api/scans/nuclei', {
      body: { target: 'localhost:3000' },
      headers: { Origin: 'http://evil.test', 'X-ScopeScan': '1', 'Content-Type': 'application/json' },
    });
    assert.equal(res.status, 403);
    assert.equal(scanner.calls.length, 0);
  });

  it('scans the canonical URL, refuses a second scan meanwhile, and logs both ends', async () => {
    const first = app.fromPage('POST', '/api/scans/nuclei', { target: 'http://LOCALHOST:3000/' });
    while (scanner.calls.length === 0) await new Promise((r) => setTimeout(r, 5));
    assert.deepEqual(scanner.calls, ['http://127.0.0.1:3000']);

    const second = await app.fromPage('POST', '/api/scans/nuclei', { target: 'localhost:3000' });
    assert.equal(second.status, 409);

    scanner.finish(DONE);
    const res = await first;
    assert.equal(res.status, 200);
    assert.equal(res.body.findings.length, 1);

    const scans = (await app.send('GET', '/api/audit')).body.filter((e) => e.action === 'scan_nuclei');
    assert.deepEqual(scans.map((e) => e.decision).sort(), ['done', 'started']);
  });
});
