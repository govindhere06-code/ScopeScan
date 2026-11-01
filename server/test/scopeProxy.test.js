import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { after, before, describe, it } from 'node:test';
import { startScopeProxy } from '../src/scopeProxy.js';

// Two local web servers: one in scope, one standing in for "another port on the same host".
function startUpstream(name) {
  const server = http.createServer((req, res) => res.end(`${name} ${req.method} ${req.url}`));
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

let inScope;
let offScope;
let proxy;
let proxyPort;

before(async () => {
  inScope = await startUpstream('in-scope');
  offScope = await startUpstream('off-scope');
  proxy = await startScopeProxy({ host: '127.0.0.1', port: inScope.address().port });
  proxyPort = Number(new URL(proxy.url).port);
});

after(async () => {
  await proxy.close();
  inScope.close();
  offScope.close();
});

// A plain-http request sent through the proxy, the way nuclei sends it.
function viaProxy(url) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: proxyPort, path: url, agent: false }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', () => resolve({ status: 'dropped' }));
    req.end();
  });
}

// A CONNECT tunnel request; resolves with the proxy's status line.
function connect(address) {
  return new Promise((resolve) => {
    const socket = net.connect(proxyPort, '127.0.0.1', () => socket.write(`CONNECT ${address} HTTP/1.1\r\nHost: ${address}\r\n\r\n`));
    socket.once('data', (d) => {
      resolve({ statusLine: d.toString().split('\r\n')[0], socket });
    });
    socket.on('error', () => resolve({ statusLine: 'dropped', socket }));
  });
}

describe('scope proxy', () => {
  it('forwards requests to the allowed host:port', async () => {
    const res = await viaProxy(`http://127.0.0.1:${inScope.address().port}/metrics?x=1`);
    assert.equal(res.status, 200);
    assert.equal(res.body, 'in-scope GET /metrics?x=1');
  });

  it('treats localhost as the same allowed host', async () => {
    const res = await viaProxy(`http://localhost:${inScope.address().port}/`);
    assert.equal(res.status, 200);
  });

  it('drops requests to another port on the same host', async () => {
    const res = await viaProxy(`http://127.0.0.1:${offScope.address().port}/`);
    assert.equal(res.status, 'dropped');
  });

  it('drops requests to port 80 and to other hosts', async () => {
    assert.equal((await viaProxy('http://127.0.0.1/SMS_DP_SMSPKG$/Datalib')).status, 'dropped');
    assert.equal((await viaProxy('http://evil.test:3000/')).status, 'dropped');
  });

  it('drops requests that are not proxy requests at all', async () => {
    assert.equal((await viaProxy('/just-a-path')).status, 'dropped');
  });

  it('refuses an https tunnel to an off-scope port', async () => {
    const { statusLine, socket } = await connect('127.0.0.1:4040');
    socket.destroy();
    assert.match(statusLine, /403/);
  });

  it('opens a tunnel to the allowed port', async () => {
    const { statusLine, socket } = await connect(`127.0.0.1:${inScope.address().port}`);
    assert.match(statusLine, /200/);
    const reply = await new Promise((resolve) => {
      socket.once('data', (d) => resolve(d.toString()));
      socket.write('GET /through-tunnel HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
    });
    socket.destroy();
    assert.match(reply, /in-scope GET \/through-tunnel/);
  });

  it('closes a request the target never answers, instead of hanging forever', async () => {
    // A target that accepts the request and then never responds, like Juice Shop
    // waiting for body bytes a malformed template request promised but never sent.
    const silent = http.createServer(() => {});
    await new Promise((resolve) => silent.listen(0, '127.0.0.1', resolve));
    const port = silent.address().port;
    const quickProxy = await startScopeProxy({ host: '127.0.0.1', port }, { idleTimeoutMs: 200 });
    const started = Date.now();
    const res = await new Promise((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port: Number(new URL(quickProxy.url).port), path: `http://127.0.0.1:${port}/`, agent: false },
        (r) => resolve({ status: r.statusCode }),
      );
      req.on('error', () => resolve({ status: 'dropped' }));
      req.end();
    });
    const elapsed = Date.now() - started;
    const stats = quickProxy.stats();
    await quickProxy.close();
    silent.closeAllConnections();
    silent.close();
    assert.ok(res.status === 502 || res.status === 'dropped', `got ${res.status}`);
    assert.ok(elapsed < 2000, `took ${elapsed}ms`);
    assert.equal(stats.targetTimeouts, 1);
    assert.deepEqual(stats.timedOut, [{ request: 'GET /', count: 1 }]);
  });

  it('counts allowed requests the target never answered', async () => {
    // Nothing listens on this port, so every forwarded request fails.
    const dead = net.createServer();
    await new Promise((resolve) => dead.listen(0, '127.0.0.1', resolve));
    const port = dead.address().port;
    await new Promise((resolve) => dead.close(resolve));
    const deadProxy = await startScopeProxy({ host: '127.0.0.1', port });
    const res = await new Promise((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port: Number(new URL(deadProxy.url).port), path: `http://127.0.0.1:${port}/`, agent: false },
        (r) => resolve(r.statusCode),
      );
      req.on('error', () => resolve('dropped'));
      req.end();
    });
    const stats = deadProxy.stats();
    await deadProxy.close();
    assert.equal(res, 502);
    assert.deepEqual([stats.allowedRequests, stats.upstreamErrors], [1, 1]);
  });

  it('does not pass connection headers on to the target', async () => {
    const seen = [];
    const echo = http.createServer((req, res) => {
      seen.push(req.headers);
      res.end('ok');
    });
    await new Promise((resolve) => echo.listen(0, '127.0.0.1', resolve));
    const port = echo.address().port;
    const echoProxy = await startScopeProxy({ host: '127.0.0.1', port });
    await new Promise((resolve) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: Number(new URL(echoProxy.url).port),
          path: `http://127.0.0.1:${port}/`,
          headers: { Connection: 'keep-alive, X-Secret-Hop', 'Keep-Alive': 'timeout=60', 'X-Secret-Hop': '1', 'X-Kept': 'yes' },
          agent: false,
        },
        (r) => r.resume().on('end', resolve),
      );
      req.end();
    });
    await echoProxy.close();
    echo.close();
    assert.equal(seen[0]['keep-alive'], undefined);
    assert.equal(seen[0]['x-secret-hop'], undefined);
    assert.notEqual(seen[0].connection, 'keep-alive');
    assert.equal(seen[0]['x-kept'], 'yes');
  });

  it('counts what it allowed and blocked', () => {
    const stats = proxy.stats();
    assert.equal(stats.allowedRequests, 3);
    assert.ok(stats.blockedRequests >= 5);
    assert.ok(stats.blocked.some((b) => b.address === '127.0.0.1:4040'));
  });
});
