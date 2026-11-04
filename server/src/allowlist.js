import { logEvent } from './audit.js';
import { ScopeError, checkScope, parseHostEntry, parsePorts, parseTarget } from './scope.js';

const MAX_NOTE_LENGTH = 200;

export function listTargets(db) {
  return db.prepare('SELECT id, host, ports, note, created_at AS createdAt FROM allowlist ORDER BY host').all();
}

function getTarget(db, id) {
  return db.prepare('SELECT id, host, ports, note, created_at AS createdAt FROM allowlist WHERE id = ?').get(id);
}

export function addTarget(db, { host, ports, note = '' }) {
  const parsed = parseHostEntry(host);
  let portSpec = ports;
  if (parsed.port !== null) {
    if (String(ports ?? '').trim() !== '') {
      throw new ScopeError('give the port either in the host field or the ports field, not both');
    }
    portSpec = String(parsed.port);
  }
  const normalizedPorts = parsePorts(portSpec);
  if (typeof note !== 'string') throw new ScopeError('note must be text');

  if (db.prepare('SELECT 1 FROM allowlist WHERE host = ?').get(parsed.host)) {
    throw new ScopeError(`${parsed.host} is already on the allowlist; remove it first to change its ports`);
  }
  const info = db
    .prepare('INSERT INTO allowlist (host, ports, note) VALUES (?, ?, ?)')
    .run(parsed.host, normalizedPorts, note.trim().slice(0, MAX_NOTE_LENGTH));

  logEvent(db, {
    action: 'allowlist_add',
    input: host,
    host: parsed.host,
    decision: 'added',
    reason: `ports: ${normalizedPorts}`,
  });
  return getTarget(db, info.lastInsertRowid);
}

export function removeTarget(db, id) {
  const entry = getTarget(db, id);
  if (!entry) return false;
  db.prepare('DELETE FROM allowlist WHERE id = ?').run(id);
  logEvent(db, {
    action: 'allowlist_remove',
    host: entry.host,
    decision: 'removed',
    reason: `ports: ${entry.ports}`,
  });
  return true;
}

// The gate every scan must pass through. Never throws for bad input: anything that
// can't be parsed is simply denied. Every decision, allowed or denied, is logged, and the
// result carries that log entry's id (auditId). Pass `scanId` when re-checking a queued scan.
export function isAllowed(db, input, { scanId = null } = {}) {
  let result;
  try {
    const target = parseTarget(input);
    result = { ...checkScope(target, listTargets(db)), target };
  } catch (err) {
    if (!(err instanceof ScopeError)) throw err;
    result = { allowed: false, reason: err.message, target: null };
  }
  const auditId = logEvent(db, {
    action: 'scope_check',
    input,
    host: result.target?.host ?? null,
    port: result.target?.port ?? null,
    decision: result.allowed ? 'allowed' : 'denied',
    reason: result.reason,
    scanId,
  });
  return { ...result, auditId };
}
