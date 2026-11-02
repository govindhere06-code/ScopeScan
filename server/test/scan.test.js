import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { scanStatus } from '../src/scans.js';
import { startApp } from './helpers/server.js';

// Stands in for the real tools: records what each was asked to scan and lets the test decide
// when a tool finishes. Like a real tool, aborting its signal ends it early.
function fakeScanners() {
  const calls = [];
  const pending = [];
  const make = (tool) => (job, { signal }) => {
    calls.push({ tool, url: job.target.url, ports: job.ports });
    return new Promise((resolve) => {
      const entry = { tool, resolve };
      pending.push(entry);
      signal.addEventListener(
        'abort',
        () => {
          pending.splice(pending.indexOf(entry), 1);
          resolve({ status: 'failed', error: 'scan was cancelled', findings: [], log: 'killed' });
        },
        { once: true },
      );
    });
  };
  return {
    calls,
    pending,
    finish: (tool, result) => {
      const i = pending.findIndex((p) => p.tool === tool);
      pending.splice(i, 1)[0].resolve(result);
    },
    scanners: { nmap: make('nmap'), ffuf: make('ffuf'), nuclei: make('nuclei') },
  };
}

const finding = (tool, i) => ({
  tool,
  type: 'test',
  severity: i === 0 ? 'medium' : 'info',
  title: `${tool} finding ${i}`,
  location: 'http://127.0.0.1:3000',
  detail: null,
  ref: `ref-${i}`,
  raw: { i },
});
const done = (tool, n) => ({
  status: 'done',
  error: null,
  findings: Array.from({ length: n }, (_, i) => finding(tool, i)),
  log: '',
  version: 'v1',
  durationMs: 1,
});

async function until(check, what = 'condition') {
  const deadline = Date.now() + 2000;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function startLab(queue = {}) {
  const fake = fakeScanners();
  const app = await startApp({ queue: { scanners: fake.scanners, ...queue } });
  await app.fromPage('POST', '/api/targets', { host: 'localhost', ports: '3000,8080' });
  const scan = (target, tools = ['nuclei']) => app.fromPage('POST', '/api/scans', { target, tools });
  const statusOf = (id) => scanStatus(app.db, id);
  const waitFor = (id, status) => until(() => statusOf(id) === status, `scan #${id} to be ${status}`);
  return { app, fake, scan, statusOf, waitFor };
}

describe('scans go through the scope gate', () => {
  let lab;
  before(async () => (lab = await startLab()));
  after(() => lab.app.close());

  const nothingQueued = async () => {
    assert.equal(lab.fake.calls.length, 0);
    assert.deepEqual((await lab.app.send('GET', '/api/scans')).body, []);
  };

  it('refuses an unlisted target without queuing anything', async () => {
    assert.equal((await lab.scan('scanme.nmap.org', ['nmap', 'ffuf', 'nuclei'])).status, 403);
    await nothingQueued();
  });

  it('refuses a listed host on an unlisted port', async () => {
    assert.equal((await lab.scan('localhost:22', ['nmap'])).status, 403);
    await nothingQueued();
  });

  it('refuses a flag-like target', async () => {
    assert.equal((await lab.scan('-iL targets.txt', ['nmap'])).status, 403);
    await nothingQueued();
  });

  it('refuses unknown or missing tools', async () => {
    assert.equal((await lab.scan('localhost:3000', ['sqlmap'])).status, 400);
    assert.equal((await lab.scan('localhost:3000', [])).status, 400);
    assert.equal((await lab.scan('localhost:3000', 'nmap')).status, 400);
    await nothingQueued();
  });

  it('refuses a scan requested by another website', async () => {
    const res = await lab.app.send('POST', '/api/scans', {
      body: { target: 'localhost:3000', tools: ['nmap'] },
      headers: { Origin: 'http://evil.test', 'X-ScopeScan': '1', 'Content-Type': 'application/json' },
    });
    assert.equal(res.status, 403);
    await nothingQueued();
  });

  it('refuses cancelling from another website', async () => {
    const res = await lab.app.send('POST', '/api/scans/1/cancel', {
      body: {},
      headers: { Origin: 'http://evil.test', 'X-ScopeScan': '1', 'Content-Type': 'application/json' },
    });
    assert.equal(res.status, 403);
  });
});

describe('background scans', () => {
  let lab;
  before(async () => (lab = await startLab()));
  after(() => lab.app.close());

  it('answers at once and runs the tools in the background, in a fixed order', async () => {
    const res = await lab.scan('http://LOCALHOST:3000/', ['nuclei', 'nmap', 'ffuf']);
    assert.equal(res.status, 202);
    assert.equal(res.body.target, 'http://127.0.0.1:3000');
    assert.deepEqual(res.body.results.map((r) => r.tool), ['nmap', 'ffuf', 'nuclei']);
    const { id } = res.body;

    await until(() => lab.fake.calls.length === 1, 'nmap to start');
    assert.deepEqual(lab.fake.calls[0], { tool: 'nmap', url: 'http://127.0.0.1:3000', ports: '3000,8080' });

    // While nmap runs, the page can see the progress.
    const progress = (await lab.app.send('GET', `/api/scans/${id}`)).body;
    assert.equal(progress.status, 'running');
    assert.deepEqual(progress.results.map((r) => r.status), ['running', 'queued', 'queued']);

    lab.fake.finish('nmap', done('nmap', 2));
    await until(() => lab.fake.calls.length === 2, 'ffuf to start');
    assert.equal(lab.fake.calls[1].tool, 'ffuf');
    lab.fake.finish('ffuf', done('ffuf', 20));
    await until(() => lab.fake.calls.length === 3, 'nuclei to start');
    lab.fake.finish('nuclei', done('nuclei', 19));
    await lab.waitFor(id, 'done');

    const scan = (await lab.app.send('GET', `/api/scans/${id}`)).body;
    assert.deepEqual(
      scan.results.map((r) => [r.tool, r.status, r.findings.length]),
      [['nmap', 'done', 2], ['ffuf', 'done', 20], ['nuclei', 'done', 19]],
    );
    assert.equal(scan.ports, '3000,8080');
    assert.deepEqual(scan.results[0].findings[1].raw, { i: 1 });
    assert.ok(scan.startedAt && scan.finishedAt);
  });

  it('keeps the scan in the history list', async () => {
    const [scan] = (await lab.app.send('GET', '/api/scans')).body;
    assert.equal(scan.status, 'done');
    assert.equal(scan.findingCount, 41);
    assert.deepEqual(scan.severityCounts, { medium: 3, info: 38 });
    assert.deepEqual(scan.tools.map((t) => t.tool), ['nmap', 'ffuf', 'nuclei']);
  });

  it('runs one scan at a time; the next waits in the queue', async () => {
    const first = (await lab.scan('localhost:3000', ['nmap'])).body.id;
    const second = (await lab.scan('localhost:8080', ['nmap'])).body.id;
    await until(() => lab.fake.pending.length === 1, 'first scan to start');
    assert.equal(lab.statusOf(first), 'running');
    assert.equal(lab.statusOf(second), 'queued');

    lab.fake.finish('nmap', done('nmap', 1));
    await lab.waitFor(second, 'running');
    assert.equal(lab.statusOf(first), 'done');
    lab.fake.finish('nmap', done('nmap', 1));
    await lab.waitFor(second, 'done');
  });

  it('keeps running the remaining tools after one fails, and marks the scan failed', async () => {
    const { id } = (await lab.scan('localhost:3000', ['nmap', 'ffuf'])).body;
    await until(() => lab.fake.pending.length === 1, 'nmap to start');
    lab.fake.finish('nmap', { status: 'failed', error: 'nmap exited with code 1', findings: [], log: '' });
    await until(() => lab.fake.pending.some((p) => p.tool === 'ffuf'), 'ffuf to start');
    lab.fake.finish('ffuf', done('ffuf', 3));
    await lab.waitFor(id, 'failed');
    const scan = (await lab.app.send('GET', `/api/scans/${id}`)).body;
    assert.deepEqual(scan.results.map((r) => r.status), ['failed', 'done']);
    assert.equal(scan.results[0].error, 'nmap exited with code 1');
  });

  it('records a tool that crashes instead of losing the scan', async () => {
    const crashing = await startApp({
      queue: {
        scanners: {
          nmap: async () => {
            throw new Error('boom');
          },
        },
      },
    });
    await crashing.fromPage('POST', '/api/targets', { host: 'localhost', ports: '3000' });
    const { id } = (await crashing.fromPage('POST', '/api/scans', { target: 'localhost:3000', tools: ['nmap'] })).body;
    await until(() => scanStatus(crashing.db, id) === 'failed', 'crashed scan to fail');
    const scan = (await crashing.send('GET', `/api/scans/${id}`)).body;
    assert.equal(scan.results[0].error, 'nmap could not run: boom');
    await crashing.close();
  });

  it('logs every step of a scan', async () => {
    const events = (await lab.app.send('GET', '/api/audit')).body.filter((e) => /^scan #1(\D|$)/.test(e.reason ?? ''));
    const steps = events.map((e) => `${e.action}:${e.decision}`).reverse();
    assert.deepEqual(steps, [
      'scan_queued:queued',
      'scan_started:started',
      'scan_nmap:started',
      'scan_nmap:done',
      'scan_ffuf:started',
      'scan_ffuf:done',
      'scan_nuclei:started',
      'scan_nuclei:done',
      'scan_finished:done',
    ]);
  });

  it('returns 404 for a scan that does not exist', async () => {
    assert.equal((await lab.app.send('GET', '/api/scans/999')).status, 404);
    assert.equal((await lab.app.send('GET', '/api/scans/abc')).status, 400);
  });
});

describe('the allowlist is checked again when a queued scan starts', () => {
  let lab;
  before(async () => (lab = await startLab()));
  after(() => lab.app.close());

  it('refuses a scan whose entry was removed while it waited', async () => {
    const first = (await lab.scan('localhost:3000', ['nmap'])).body.id;
    const second = (await lab.scan('localhost:8080', ['nmap', 'nuclei'])).body.id;
    await until(() => lab.fake.pending.length === 1, 'first scan to start');

    const [entry] = (await lab.app.send('GET', '/api/targets')).body;
    assert.equal((await lab.app.fromPage('DELETE', `/api/targets/${entry.id}`)).status, 204);
    lab.fake.finish('nmap', done('nmap', 1));

    await lab.waitFor(second, 'failed');
    assert.equal(lab.statusOf(first), 'done');
    assert.equal(lab.fake.calls.length, 1, 'no tool ran for the second scan');
    const scan = (await lab.app.send('GET', `/api/scans/${second}`)).body;
    assert.match(scan.error, /^refused when it was about to start/);
    assert.deepEqual(scan.results.map((r) => r.status), ['skipped', 'skipped']);
    const events = (await lab.app.send('GET', '/api/audit')).body;
    assert.ok(events.some((e) => e.action === 'scan_refused' && e.reason.startsWith(`scan #${second}`)));
  });
});

describe('time limit', () => {
  let lab;
  before(async () => (lab = await startLab({ timeoutMs: 100 })));
  after(() => lab.app.close());

  it('kills a scan that runs too long and marks it timed out', async () => {
    const { id } = (await lab.scan('localhost:3000', ['nmap', 'nuclei'])).body;
    // The fake nmap never finishes on its own; only the time limit can end it.
    await lab.waitFor(id, 'timed_out');
    const scan = (await lab.app.send('GET', `/api/scans/${id}`)).body;
    assert.equal(scan.error, 'stopped at the time limit of 0.1 seconds');
    assert.deepEqual(scan.results.map((r) => r.status), ['timed_out', 'skipped']);
    assert.equal(scan.results[0].log, 'killed', 'what the tool said before it was killed is kept');
    assert.deepEqual(lab.fake.calls.map((c) => c.tool), ['nmap']);
    const events = (await lab.app.send('GET', '/api/audit')).body;
    assert.ok(events.some((e) => e.action === 'scan_finished' && e.decision === 'timed_out'));
  });
});

describe('cancelling', () => {
  let lab;
  before(async () => (lab = await startLab()));
  after(() => lab.app.close());
  const cancel = (id) => lab.app.fromPage('POST', `/api/scans/${id}/cancel`, {});

  it('stops a running scan and drops a queued one', async () => {
    const running = (await lab.scan('localhost:3000', ['nmap', 'ffuf'])).body.id;
    const waiting = (await lab.scan('localhost:8080', ['nmap'])).body.id;
    await until(() => lab.fake.pending.length === 1, 'first scan to start');

    assert.equal((await cancel(waiting)).status, 200);
    assert.equal(lab.statusOf(waiting), 'cancelled');

    assert.equal((await cancel(running)).status, 200);
    await lab.waitFor(running, 'cancelled');
    const scan = (await lab.app.send('GET', `/api/scans/${running}`)).body;
    assert.deepEqual(scan.results.map((r) => r.status), ['cancelled', 'skipped']);
    assert.equal(lab.fake.calls.length, 1, 'neither ffuf nor the queued scan ever started');
  });

  it('refuses to cancel a finished scan, and 404s an unknown one', async () => {
    assert.equal((await cancel(1)).status, 409);
    assert.equal((await cancel(999)).status, 404);
  });
});

describe('two scans at a time', () => {
  let lab;
  before(async () => (lab = await startLab({ concurrency: 2 })));
  after(() => lab.app.close());

  it('runs different targets side by side but never the same target twice', async () => {
    const a = (await lab.scan('localhost:3000', ['nmap'])).body.id;
    const b = (await lab.scan('localhost:3000', ['ffuf'])).body.id;
    const c = (await lab.scan('localhost:8080', ['nuclei'])).body.id;
    await until(() => lab.fake.pending.length === 2, 'two scans to start');
    assert.deepEqual([lab.statusOf(a), lab.statusOf(b), lab.statusOf(c)], ['running', 'queued', 'running']);

    lab.fake.finish('nmap', done('nmap', 0));
    await lab.waitFor(b, 'running');
    lab.fake.finish('ffuf', done('ffuf', 0));
    lab.fake.finish('nuclei', done('nuclei', 0));
    await lab.waitFor(b, 'done');
    await lab.waitFor(c, 'done');
  });

  it('never allows more than two, whatever it is configured with', async () => {
    const big = await startApp({ queue: { concurrency: 10 } });
    assert.equal(big.queue.limit, 2);
    await big.close();
  });
});
