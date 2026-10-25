import express from 'express';
import { addTarget, isAllowed, listTargets, removeTarget } from './allowlist.js';
import { listEvents } from './audit.js';
import { ScopeError } from './scope.js';
import { requireLocalHost, requireSameSite } from './security.js';

export function createApp({ db, allowedOrigins }) {
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

  // Asks the gate directly. Scans (Ticket 2 onwards) will call isAllowed() the same way.
  app.post('/api/scope/check', (req, res) => {
    const result = isAllowed(db, req.body?.target);
    res.status(result.allowed ? 200 : 403).json(result);
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
