import http from 'node:http';
import { createApp } from '../../src/app.js';
import { openDb } from '../../src/db.js';

export const ORIGIN = 'http://localhost:5173';

// What the real React page sends.
export const PAGE_HEADERS = { Origin: ORIGIN, 'X-ScopeScan': '1', 'Content-Type': 'application/json' };

// Starts the app on a random port with a fresh in-memory database.
export async function startApp(options = {}) {
  const db = openDb(':memory:');
  const server = createApp({ db, allowedOrigins: [ORIGIN], ...options }).listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const { port } = server.address();

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

  const fromPage = (method, path, body) => send(method, path, { body, headers: PAGE_HEADERS });
  const close = () => new Promise((resolve) => server.close(resolve));
  return { db, port, send, fromPage, close };
}
