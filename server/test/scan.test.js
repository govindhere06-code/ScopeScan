import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startApp } from './helpers/server.js';

// Stands in for the real tools: records what each was asked to scan, and lets the test
// decide when a tool finishes.
function fakeScanners() {
  const calls = [];
  const pending = [];
  const make = (tool) => (job) => {
    calls.push({ tool, url: job.target.url, ports: job.ports });
    return new Promise((resolve) => pending.push(resolve));
  };
  return {
    calls,
    finishNext: (result) => pending.shift()(result),
    scanners: { nmap: make('nmap'), ffuf: make('ffuf'), nuclei: make('nuclei') },
  };
}

const done = (n) => ({ status: 'done', error: null, findings: Array(n).fill({}), version: null, durationMs: 1 });
const until = async (check) => {
  while (!check()) await new Promise((r) => setTimeout(r, 5));
};

let app;
let fake;
before(async () => {
  fake = fakeScanners();
  app = await startApp({ scanners: fake.scanners });
  await app.fromPage('POST', '/api/targets', { host: 'localhost', ports: '3000,8080' });
});
after(() => app.close());

describe('scans go through the scope gate', () => {
  const scan = (target, tools = ['nuclei']) => app.fromPage('POST', '/api/scans', { target, tools });

  it('refuses an unlisted target without starting any tool', async () => {
    assert.equal((await scan('scanme.nmap.org', ['nmap', 'ffuf', 'nuclei'])).status, 403);
    assert.equal(fake.calls.length, 0);
  });

  it('refuses a listed host on an unlisted port', async () => {
    assert.equal((await scan('localhost:22', ['nmap'])).status, 403);
    assert.equal(fake.calls.length, 0);
  });

  it('refuses a flag-like target', async () => {
    assert.equal((await scan('-iL targets.txt', ['nmap'])).status, 403);
    assert.equal(fake.calls.length, 0);
  });

  it('refuses unknown or missing tools', async () => {
    assert.equal((await scan('localhost:3000', ['sqlmap'])).status, 400);
    assert.equal((await scan('localhost:3000', [])).status, 400);
    assert.equal((await scan('localhost:3000', 'nmap')).status, 400);
    assert.equal(fake.calls.length, 0);
  });

  it('refuses a scan requested by another website', async () => {
    const res = await app.send('POST', '/api/scans', {
      body: { target: 'localhost:3000', tools: ['nmap'] },
      headers: { Origin: 'http://evil.test', 'X-ScopeScan': '1', 'Content-Type': 'application/json' },
    });
    assert.equal(res.status, 403);
    assert.equal(fake.calls.length, 0);
  });
});

describe('running tools', () => {
  it('runs the chosen tools in a fixed order, one at a time, on the canonical target', async () => {
    const request = app.fromPage('POST', '/api/scans', {
      target: 'http://LOCALHOST:3000/',
      tools: ['nuclei', 'nmap', 'ffuf'],
    });

    await until(() => fake.calls.length === 1);
    assert.deepEqual(fake.calls[0], { tool: 'nmap', url: 'http://127.0.0.1:3000', ports: '3000,8080' });

    // A second scan can't start while this one runs.
    const second = await app.fromPage('POST', '/api/scans', { target: 'localhost:3000', tools: ['nmap'] });
    assert.equal(second.status, 409);

    fake.finishNext(done(2));
    await until(() => fake.calls.length === 2);
    assert.equal(fake.calls[1].tool, 'ffuf');
    fake.finishNext(done(20));
    await until(() => fake.calls.length === 3);
    assert.equal(fake.calls[2].tool, 'nuclei');
    fake.finishNext(done(19));

    const res = await request;
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.results.map((r) => [r.tool, r.findings.length]), [['nmap', 2], ['ffuf', 20], ['nuclei', 19]]);
  });

  it('logs the start and end of every tool', async () => {
    const events = (await app.send('GET', '/api/audit')).body;
    for (const tool of ['nmap', 'ffuf', 'nuclei']) {
      const decisions = events.filter((e) => e.action === `scan_${tool}`).map((e) => e.decision).sort();
      assert.deepEqual(decisions, ['done', 'started'], tool);
    }
  });
});
