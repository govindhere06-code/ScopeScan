import express from 'express';
import { addTarget, isAllowed, listTargets, removeTarget } from './allowlist.js';
import { listEvents, logEvent } from './audit.js';
import { ScopeError } from './scope.js';
import { requireLocalHost, requireSameSite } from './security.js';
import { runNucleiScan } from './tools/nuclei.js';

// `scanner` is swappable so tests can check the gate without launching real scans.
export function createApp({ db, allowedOrigins, scanner = { runNuclei: runNucleiScan } }) {
  const app = express();
  let scanRunning = false;
  app.disable('x-powered-by');

  app.use(requireLocalHost(['127.0.0.1', 'localhost']));
  app.use('/api', requireSameSite(allowedOrigins));
  app.use(express.json({ limit: '10kb' }));

  app.get('/api/health', (req, res) => res.json({ ok: true }));

  app.get('/api/targets', (req, res) => res.json(listTargets(db)));

  app.post('/api/targets', (req, res) => {
    res.status(201).json(addTarget(db, req.body ?? {}));
  });

  app.delete('/api/targets/:id', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'invalid id' });
    if (!removeTarget(db, id)) return res.status(404).json({ error: 'no such allowlist entry' });
    res.status(204).end();
  });

  // Asks the gate directly, without scanning.
  app.post('/api/scope/check', (req, res) => {
    const result = isAllowed(db, req.body?.target);
    res.status(result.allowed ? 200 : 403).json(result);
  });

  // Runs nuclei and holds the request open until it finishes (15-25 minutes for a full
  // scan). Ticket 4 replaces this with background jobs.
  app.post('/api/scans/nuclei', async (req, res) => {
    const scope = isAllowed(db, req.body?.target);
    if (!scope.allowed) return res.status(403).json({ error: `refused: ${scope.reason}` });
    // One at a time: two parallel scans are enough to knock Juice Shop over.
    if (scanRunning) return res.status(409).json({ error: 'a scan is already running; wait for it to finish' });

    scanRunning = true;
    const { target } = scope;
    const controller = new AbortController();
    // Closing the page closes the connection; don't leave nuclei running unattended.
    res.on('close', () => {
      if (!res.writableFinished) controller.abort();
    });
    const audit = { action: 'scan_nuclei', input: target.url, host: target.host, port: target.port };
    logEvent(db, { ...audit, decision: 'started' });
    try {
      const result = await scanner.runNuclei(target, { signal: controller.signal });
      const summary = `${result.findings.length} findings, ${result.scope?.blockedRequests ?? 0} off-scope requests blocked`;
      logEvent(db, {
        ...audit,
        decision: result.status,
        reason: result.error ? `${result.error} (${summary})` : summary,
      });
      if (!controller.signal.aborted) res.json({ target, ...result });
    } finally {
      scanRunning = false;
    }
  });

  app.get('/api/audit', (req, res) => res.json(listEvents(db)));

  app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

  app.use((err, req, res, next) => {
    if (err instanceof ScopeError) return res.status(400).json({ error: err.message });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid JSON' });
    console.error(err);
    res.status(500).json({ error: 'internal error' });
  });

  return app;
}
