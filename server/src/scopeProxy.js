import http from 'node:http';
import net from 'node:net';
import { ScopeError, parseTarget } from './scope.js';

// A forward proxy that lets traffic reach exactly one host:port. Scanners are pointed at
// it, so a template that hard-codes another port (Spark on 4040, Redis on 6379, ...) is
// stopped at the network level instead of trusting every template to stay in scope.

const MAX_BLOCKED_LISTED = 50;
// Some templates send deliberately malformed requests (e.g. a Content-Length longer than
// the body) that make the target wait forever. Through a proxy, nuclei's own -timeout
// doesn't end them, so the proxy closes any connection that goes quiet for this long.
const DEFAULT_IDLE_TIMEOUT_MS = 30_000;

function isInScope(address, allowed) {
  try {
    const t = parseTarget(address);
    return t.host === allowed.host && t.port === allowed.port;
  } catch (err) {
    if (err instanceof ScopeError) return false;
    throw err;
  }
}

// `allowed` is a canonical target from isAllowed(): { host, port }.
export function startScopeProxy(allowed, { idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS } = {}) {
  // Always connect to the canonical address, never re-resolve the name the client sent.
  const upstreamHost = allowed.host.replace(/^\[|\]$/g, '');
  const sockets = new Set();
  const blocked = new Map();
  let allowedRequests = 0;
  let blockedRequests = 0;
  let timedOut = 0;

  // Every socket, on both sides, is closed after `idleTimeoutMs` without traffic.
  function track(socket) {
    sockets.add(socket);
    socket.setTimeout(idleTimeoutMs, () => {
      timedOut += 1;
      socket.destroy();
    });
    socket.on('close', () => sockets.delete(socket));
  }

  function block(address) {
    blockedRequests += 1;
    const key = String(address).slice(0, 200);
    if (blocked.has(key) || blocked.size < MAX_BLOCKED_LISTED) blocked.set(key, (blocked.get(key) ?? 0) + 1);
  }

  // Plain http: the client sends the full URL ("GET http://host:port/path").
  const server = http.createServer((req, res) => {
    let url;
    try {
      url = new URL(req.url);
    } catch {
      block(req.url);
      return req.socket.destroy();
    }
    if (url.protocol !== 'http:' || !isInScope(`http://${url.host}`, allowed)) {
      block(url.host || req.url);
      // Drop the connection rather than answer: a made-up response could trip a template's matchers.
      return req.socket.destroy();
    }
    allowedRequests += 1;
    const headers = { ...req.headers };
    delete headers['proxy-connection'];
    delete headers['proxy-authorization'];
    const upstream = http.request(
      // A fresh connection per request (no pooling), so every upstream socket gets the idle timeout.
      { host: upstreamHost, port: allowed.port, method: req.method, path: url.pathname + url.search, headers, agent: false },
      (up) => {
        res.writeHead(up.statusCode, up.statusMessage, up.headers);
        up.pipe(res);
      },
    );
    upstream.on('socket', track);
    upstream.on('error', () => (res.headersSent ? res.destroy() : res.writeHead(502).end()));
    // If the scanner gives up on a request, stop waiting on the target too.
    res.on('close', () => {
      if (!res.writableFinished) upstream.destroy();
    });
    req.pipe(upstream);
  });

  // https: the client asks for a tunnel ("CONNECT host:port") and encrypts inside it.
  server.on('connect', (req, clientSocket, head) => {
    if (!isInScope(`https://${req.url}`, allowed)) {
      block(req.url);
      return clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    }
    allowedRequests += 1;
    const upstream = net.connect(allowed.port, upstreamHost, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    track(upstream);
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });

  server.on('connection', track);
  server.on('clientError', (err, socket) => socket.destroy());

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        stats: () => ({
          allowedRequests,
          blockedRequests,
          timedOutConnections: timedOut,
          blocked: [...blocked].map(([address, count]) => ({ address, count })).sort((a, b) => b.count - a.count),
        }),
        close: () =>
          new Promise((done) => {
            for (const socket of sockets) socket.destroy();
            server.close(() => done());
          }),
      });
    });
  });
}
