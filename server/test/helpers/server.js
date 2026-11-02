import http from 'node:http';
import { createApp } from '../../src/app.js';
import { openDb } from '../../src/db.js';
import { createScanQueue } from '../../src/jobs.js';

export const ORIGIN = 'http://localhost:5173';

// What the real React page sends.
export const PAGE_HEADERS = { Origin: ORIGIN, 'X-ScopeScan': '1', 'Content-Type': 'application/json' };

// A test that doesn't pass its own scanners must never launch a real one.
const refuse = () => {
  throw new Error('this test tried to run a real scanner');
};
const NO_SCANNERS = { nmap: refuse, ffuf: refuse, nuclei: refuse };

// Starts the app on a random port with a fresh in-memory database. `queue` options
// (scanners, timeoutMs, concurrency, ...) go to the scan queue.
export async function startApp({ queue: queueOptions = {} } = {}) {
  const db = openDb(':memory:');
  const queue = createScanQueue({ db, scanners: NO_SCANNERS, ...queueOptions });
  const server = createApp({ db, allowedOrigins: [ORIGIN], queue }).listen(0, '127.0.0.1');
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
  return { db, queue, port, send, fromPage, close };
}
