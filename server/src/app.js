import express from 'express';
import { addTarget, isAllowed, listTargets, removeTarget } from './allowlist.js';
import { listEvents, logEvent } from './audit.js';
import { QueueFullError } from './jobs.js';
import { ACTIVE, getScan, listScans, scanStatus } from './scans.js';
import { ScopeError } from './scope.js';
import { requireLocalHost, requireSameSite } from './security.js';

// Quickest first, so the slow nuclei scan doesn't hold up the other results.
const TOOL_ORDER = ['nmap', 'ffuf', 'nuclei'];

function parseTools(input) {
  if (!Array.isArray(input) || input.length === 0) throw new ScopeError(`pick at least one tool: ${TOOL_ORDER.join(', ')}`);
  for (const tool of input) {
    if (!TOOL_ORDER.includes(tool)) throw new ScopeError(`unknown tool: ${String(tool).slice(0, 40)}`);
  }
  return TOOL_ORDER.filter((tool) => input.includes(tool));
}

function scanId(req) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) throw new ScopeError('invalid scan id');
  return id;
}

// `queue` (see jobs.js) runs the scans; tests give it fake scanners. `triage` (see ai/queue.js)
// is null when AI triage is turned off.
export function createApp({ db, allowedOrigins, queue, triage = null }) {
  const app = express();
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

  // Queues the scan and answers at once (202); the scan runs in the background and its
  // progress is read from GET /api/scans/:id. Refused targets never reach the queue.
  app.post('/api/scans', (req, res) => {
    const tools = parseTools(req.body?.tools);
    const scope = isAllowed(db, req.body?.target);
    if (!scope.allowed) return res.status(403).json({ error: `refused: ${scope.reason}` });
    res.status(202).json(queue.enqueue({ target: scope.target, tools }));
  });

  app.get('/api/scans', (req, res) => res.json(listScans(db)));

  app.get('/api/scans/:id', (req, res) => {
    const scan = getScan(db, scanId(req));
    if (!scan) return res.status(404).json({ error: 'no such scan' });
    res.json(scan);
  });

  app.post('/api/scans/:id/cancel', (req, res) => {
    const id = scanId(req);
    const outcome = queue.cancel(id);
    if (outcome === null) return res.status(404).json({ error: 'no such scan' });
    if (outcome === 'finished') return res.status(409).json({ error: 'this scan has already finished' });
    res.json(getScan(db, id));
  });

  // Sends a finished scan to the local model again, e.g. after changing the model or prompt.
  // Earlier opinions are replaced; the findings themselves never change.
  app.post('/api/scans/:id/triage', (req, res) => {
    const id = scanId(req);
    if (!triage) return res.status(503).json({ error: 'AI triage is turned off (AI_TRIAGE=off in server/.env)' });
    const status = scanStatus(db, id);
    if (status === null) return res.status(404).json({ error: 'no such scan' });
    if (ACTIVE.includes(status)) return res.status(409).json({ error: 'wait for the scan to finish first' });
    if (triage.busyWith(id)) return res.status(409).json({ error: 'AI triage of this scan is already under way' });
    if (!triage.enqueue(id)) return res.status(409).json({ error: 'this scan has no findings to triage' });
    res.status(202).json(getScan(db, id));
  });

  app.get('/api/audit', (req, res) => res.json(listEvents(db)));

  app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

  app.use((err, req, res, next) => {
    if (err instanceof ScopeError) return res.status(400).json({ error: err.message });
    if (err instanceof QueueFullError) return res.status(429).json({ error: err.message });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid JSON' });
    console.error(err);
    res.status(500).json({ error: 'internal error' });
  });

  return app;
}
