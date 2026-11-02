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

// Headers that describe one connection, not the request. A proxy must not pass them on:
// forwarding the scanner's "Connection: keep-alive" would hold target connections open.
const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer', 'upgrade'];

function withoutHopByHop(headers) {
  const out = { ...headers };
  const listed = String(headers.connection ?? '').split(',').map((h) => h.trim().toLowerCase());
  for (const name of [...HOP_BY_HOP, ...listed]) delete out[name];
  return out;
}

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
  // Allowed requests the target never answered (connection failed, or went quiet): lets a
  // scanner that exits "successfully" against a dead target be caught.
  let upstreamErrors = 0;
  let targetTimeouts = 0;
  const timedOut = new Map();

  // Counts occurrences per key, keeping at most MAX_BLOCKED_LISTED distinct keys.
  function tally(map, key) {
    const k = String(key).slice(0, 200);
    if (map.has(k) || map.size < MAX_BLOCKED_LISTED) map.set(k, (map.get(k) ?? 0) + 1);
  }

  // Every socket, on both sides, is closed after a while without traffic. Only a quiet
  // connection to the target counts as a timeout (an idle scanner connection is normal), and
  // it's recorded by the request it was carrying. The scanner side waits twice as long:
  // while the target is silent the scanner is silent too, and if its timer went first the
  // target's silence would never be counted.
  function track(socket, { toTarget = false, label = '' } = {}) {
    sockets.add(socket);
    socket.setTimeout(toTarget ? idleTimeoutMs : idleTimeoutMs * 2, () => {
      if (toTarget) {
        targetTimeouts += 1;
        tally(timedOut, label);
      }
      socket.destroy();
    });
    socket.on('close', () => sockets.delete(socket));
  }

  function block(address) {
    blockedRequests += 1;
    tally(blocked, address);
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
    const upstream = http.request(
      // A fresh connection per request (no pooling), closed once the response is done.
      {
        host: upstreamHost,
        port: allowed.port,
        method: req.method,
        path: url.pathname + url.search,
        headers: withoutHopByHop(req.headers),
        agent: false,
      },
      (up) => {
        res.writeHead(up.statusCode, up.statusMessage, withoutHopByHop(up.headers));
        up.pipe(res);
      },
    );
    upstream.on('socket', (socket) => track(socket, { toTarget: true, label: `${req.method} ${url.pathname}` }));
    upstream.on('error', () => {
      upstreamErrors += 1;
      if (res.headersSent) res.destroy();
      else res.writeHead(502).end();
    });
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
    track(upstream, { toTarget: true, label: `CONNECT ${req.url}` });
    upstream.on('error', () => {
      upstreamErrors += 1;
      clientSocket.destroy();
    });
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
          upstreamErrors,
          targetTimeouts,
          blocked: [...blocked].map(([address, count]) => ({ address, count })).sort((a, b) => b.count - a.count),
          timedOut: [...timedOut].map(([request, count]) => ({ request, count })).sort((a, b) => b.count - a.count),
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
