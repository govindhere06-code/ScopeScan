import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { createApp } from '../src/app.js';
import { openDb } from '../src/db.js';

const ORIGIN = 'http://localhost:5173';
let server;
let port;

before(async () => {
  const app = createApp({ db: openDb(':memory:'), allowedOrigins: [ORIGIN] });
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  port = server.address().port;
});

after(() => server.close());

// node:http rather than fetch, because fetch won't let a test forge the Host header.
function send(method, path, { body, headers = {} } = {}) {
  const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }));
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

// What the real React page sends.
const PAGE_HEADERS = { Origin: ORIGIN, 'X-ScopeScan': '1', 'Content-Type': 'application/json' };
const fromPage = (method, path, body) => send(method, path, { body, headers: PAGE_HEADERS });

describe('allowlist and scope checks', () => {
  it('adds localhost:3000', async () => {
    const res = await fromPage('POST', '/api/targets', { host: 'localhost:3000', note: 'Juice Shop' });
    assert.equal(res.status, 201);
    assert.equal(res.body.host, '127.0.0.1');
    assert.equal(res.body.ports, '3000');
  });

  it('refuses a duplicate host', async () => {
    const res = await fromPage('POST', '/api/targets', { host: '127.0.0.1', ports: '8080' });
    assert.equal(res.status, 400);
  });

  it('refuses an entry with no ports', async () => {
    const res = await fromPage('POST', '/api/targets', { host: 'example.test' });
    assert.equal(res.status, 400);
  });

  it('allows the listed target', async () => {
    const res = await fromPage('POST', '/api/scope/check', { target: 'http://localhost:3000/#/login' });
    assert.equal(res.status, 200);
    assert.equal(res.body.allowed, true);
  });

  it('rejects an unlisted target', async () => {
    const res = await fromPage('POST', '/api/scope/check', { target: 'scanme.nmap.org' });
    assert.equal(res.status, 403);
    assert.equal(res.body.allowed, false);
  });

  it('rejects a listed host on an unlisted port', async () => {
    const res = await fromPage('POST', '/api/scope/check', { target: 'localhost:8080' });
    assert.equal(res.status, 403);
  });

  it('logs every decision, including denials', async () => {
    const res = await send('GET', '/api/audit');
    const checks = res.body.filter((e) => e.action === 'scope_check');
    assert.ok(checks.some((e) => e.decision === 'allowed'));
    assert.ok(checks.some((e) => e.decision === 'denied' && e.input === 'scanme.nmap.org'));
  });

  it('removing an entry takes it out of scope', async () => {
    const [entry] = (await send('GET', '/api/targets')).body;
    assert.equal((await send('DELETE', `/api/targets/${entry.id}`, { headers: PAGE_HEADERS })).status, 204);
    const res = await fromPage('POST', '/api/scope/check', { target: 'localhost:3000' });
    assert.equal(res.status, 403);
  });
});

describe('only ScopeScan\'s own page on this machine can make changes', () => {
  const attempt = { host: 'evil.test', ports: '*' };

  it('rejects a request from another website (CSRF)', async () => {
    const res = await send('POST', '/api/targets', {
      body: attempt,
      headers: { ...PAGE_HEADERS, Origin: 'http://evil.test' },
    });
    assert.equal(res.status, 403);
  });

  it('rejects a request without the X-ScopeScan header', async () => {
    const res = await send('POST', '/api/targets', {
      body: attempt,
      headers: { Origin: ORIGIN, 'Content-Type': 'application/json' },
    });
    assert.equal(res.status, 403);
  });

  it('rejects a plain HTML-form style post', async () => {
    const res = await send('POST', '/api/targets', {
      body: 'host=evil.test&ports=*',
      headers: { 'X-ScopeScan': '1', 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(res.status, 403);
  });

  it('rejects a cross-site delete', async () => {
    const res = await send('DELETE', '/api/targets/1', { headers: { Origin: 'http://evil.test' } });
    assert.equal(res.status, 403);
  });

  it('rejects requests for another Host name (DNS rebinding)', async () => {
    const res = await send('GET', '/api/targets', { headers: { Host: `evil.test:${port}` } });
    assert.equal(res.status, 403);
  });

  it('none of the rejected attempts changed the allowlist', async () => {
    const res = await send('GET', '/api/targets');
    assert.equal(res.body.some((e) => e.host === 'evil.test'), false);
  });
});
