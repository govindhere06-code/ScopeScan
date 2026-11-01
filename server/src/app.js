import express from 'express';
import { addTarget, isAllowed, listTargets, removeTarget } from './allowlist.js';
import { listEvents, logEvent } from './audit.js';
import { ScopeError } from './scope.js';
import { requireLocalHost, requireSameSite } from './security.js';
import { runFfufScan } from './tools/ffuf.js';
import { runNmapScan } from './tools/nmap.js';
import { runNucleiScan } from './tools/nuclei.js';

const DEFAULT_SCANNERS = { nmap: runNmapScan, ffuf: runFfufScan, nuclei: runNucleiScan };
// Quickest first, so the slow nuclei scan doesn't hold up the other results.
const TOOL_ORDER = ['nmap', 'ffuf', 'nuclei'];

function parseTools(input) {
  if (!Array.isArray(input) || input.length === 0) throw new ScopeError(`pick at least one tool: ${TOOL_ORDER.join(', ')}`);
  for (const tool of input) {
    if (!TOOL_ORDER.includes(tool)) throw new ScopeError(`unknown tool: ${String(tool).slice(0, 40)}`);
  }
  return TOOL_ORDER.filter((tool) => input.includes(tool));
}

// `scanners` is swappable so tests can check the gate without launching real scans.
export function createApp({ db, allowedOrigins, scanners = DEFAULT_SCANNERS }) {
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

  // Runs the chosen tools one after another and holds the request open until all finish
  // (a full nuclei scan alone takes about 15 minutes). Ticket 4 replaces this with background jobs.
  app.post('/api/scans', async (req, res) => {
    const tools = parseTools(req.body?.tools);
    const scope = isAllowed(db, req.body?.target);
    if (!scope.allowed) return res.status(403).json({ error: `refused: ${scope.reason}` });
    // One at a time: two parallel scans are enough to knock Juice Shop over.
    if (scanRunning) return res.status(409).json({ error: 'a scan is already running; wait for it to finish' });

    scanRunning = true;
    const { target, ports } = scope;
    const controller = new AbortController();
    // Closing the page closes the connection; don't leave a scanner running unattended.
    res.on('close', () => {
      if (!res.writableFinished) controller.abort();
    });
    const results = [];
    try {
      for (const tool of tools) {
        if (controller.signal.aborted) break;
        const audit = { action: `scan_${tool}`, input: target.url, host: target.host, port: target.port };
        logEvent(db, { ...audit, decision: 'started' });
        const result = await scanners[tool]({ target, ports }, { signal: controller.signal });
        const blocked = result.scope ? `, ${result.scope.blockedRequests} off-scope requests blocked` : '';
        const summary = `${result.findings.length} findings${blocked}`;
        logEvent(db, {
          ...audit,
          decision: result.status,
          reason: result.error ? `${result.error} (${summary})` : summary,
        });
        results.push({ tool, ...result });
      }
      if (!controller.signal.aborted) res.json({ target, ports, results });
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
