import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { ORIGIN, PAGE_HEADERS, startApp } from './helpers/server.js';

let app;
before(async () => {
  app = await startApp();
});
after(() => app.close());

describe('allowlist and scope checks', () => {
  it('adds localhost:3000', async () => {
    const res = await app.fromPage('POST', '/api/targets', { host: 'localhost:3000', note: 'Juice Shop' });
    assert.equal(res.status, 201);
    assert.equal(res.body.host, '127.0.0.1');
    assert.equal(res.body.ports, '3000');
  });

  it('refuses a duplicate host', async () => {
    const res = await app.fromPage('POST', '/api/targets', { host: '127.0.0.1', ports: '8080' });
    assert.equal(res.status, 400);
  });

  it('refuses an entry with no ports', async () => {
    const res = await app.fromPage('POST', '/api/targets', { host: 'example.test' });
    assert.equal(res.status, 400);
  });

  it('allows the listed target', async () => {
    const res = await app.fromPage('POST', '/api/scope/check', { target: 'http://localhost:3000/#/login' });
    assert.equal(res.status, 200);
    assert.equal(res.body.allowed, true);
  });

  it('rejects an unlisted target', async () => {
    const res = await app.fromPage('POST', '/api/scope/check', { target: 'scanme.nmap.org' });
    assert.equal(res.status, 403);
    assert.equal(res.body.allowed, false);
  });

  it('rejects a listed host on an unlisted port', async () => {
    const res = await app.fromPage('POST', '/api/scope/check', { target: 'localhost:8080' });
    assert.equal(res.status, 403);
  });

  it('logs every decision, including denials', async () => {
    const res = await app.send('GET', '/api/audit');
    const checks = res.body.filter((e) => e.action === 'scope_check');
    assert.ok(checks.some((e) => e.decision === 'allowed'));
    assert.ok(checks.some((e) => e.decision === 'denied' && e.input === 'scanme.nmap.org'));
  });

  it('removing an entry takes it out of scope', async () => {
    const [entry] = (await app.send('GET', '/api/targets')).body;
    assert.equal((await app.send('DELETE', `/api/targets/${entry.id}`, { headers: PAGE_HEADERS })).status, 204);
    const res = await app.fromPage('POST', '/api/scope/check', { target: 'localhost:3000' });
    assert.equal(res.status, 403);
  });
});

describe('only ScopeScan\'s own page on this machine can make changes', () => {
  const attempt = { host: 'evil.test', ports: '*' };

  it('rejects a request from another website (CSRF)', async () => {
    const res = await app.send('POST', '/api/targets', {
      body: attempt,
      headers: { ...PAGE_HEADERS, Origin: 'http://evil.test' },
    });
    assert.equal(res.status, 403);
  });

  it('rejects a request without the X-ScopeScan header', async () => {
    const res = await app.send('POST', '/api/targets', {
      body: attempt,
      headers: { Origin: ORIGIN, 'Content-Type': 'application/json' },
    });
    assert.equal(res.status, 403);
  });

  it('rejects a plain HTML-form style post', async () => {
    const res = await app.send('POST', '/api/targets', {
      body: 'host=evil.test&ports=*',
      headers: { 'X-ScopeScan': '1', 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(res.status, 403);
  });

  it('rejects a cross-site delete', async () => {
    const res = await app.send('DELETE', '/api/targets/1', { headers: { Origin: 'http://evil.test' } });
    assert.equal(res.status, 403);
  });

  it('rejects requests for another Host name (DNS rebinding)', async () => {
    const res = await app.send('GET', '/api/targets', { headers: { Host: `evil.test:${app.port}` } });
    assert.equal(res.status, 403);
  });

  it('none of the rejected attempts changed the allowlist', async () => {
    const res = await app.send('GET', '/api/targets');
    assert.equal(res.body.some((e) => e.host === 'evil.test'), false);
  });
});
