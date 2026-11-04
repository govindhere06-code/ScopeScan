// Append-only record of every allowlist change and every scope decision.

const MAX_INPUT_LENGTH = 500;

// Returns the new row's id.
export function logEvent(db, { action, input = null, host = null, port = null, decision, reason = null, scanId = null }) {
  const info = db
    .prepare('INSERT INTO audit_log (action, input, host, port, decision, reason, scan_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(action, input == null ? null : String(input).slice(0, MAX_INPUT_LENGTH), host, port, decision, reason, scanId);
  return Number(info.lastInsertRowid);
}

// Everything the audit log holds about one scan, oldest first: the scope check that let it be
// queued, then every event tagged with it. Scans from before events were tagged are matched by
// the "scan #N" their reasons start with.
export function scanEvents(db, scanId, scopeAuditId = null) {
  return db
    .prepare(
      `SELECT id, ts, action, input, host, port, decision, reason FROM audit_log
       WHERE id = ? OR scan_id = ? OR (scan_id IS NULL AND (reason = ? OR reason LIKE ?))
       ORDER BY id`,
    )
    .all(scopeAuditId, scanId, `scan #${scanId}`, `scan #${scanId}:%`);
}

export function listEvents(db, limit = 100) {
  return db
    .prepare('SELECT id, ts, action, input, host, port, decision, reason FROM audit_log ORDER BY id DESC LIMIT ?')
    .all(limit);
}
