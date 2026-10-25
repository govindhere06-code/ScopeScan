// Append-only record of every allowlist change and every scope decision.

const MAX_INPUT_LENGTH = 500;

export function logEvent(db, { action, input = null, host = null, port = null, decision, reason = null }) {
  db.prepare(
    'INSERT INTO audit_log (action, input, host, port, decision, reason) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(
    action,
    input == null ? null : String(input).slice(0, MAX_INPUT_LENGTH),
    host,
    port,
    decision,
    reason,
  );
}

export function listEvents(db, limit = 100) {
  return db
    .prepare('SELECT id, ts, action, input, host, port, decision, reason FROM audit_log ORDER BY id DESC LIMIT ?')
    .all(limit);
}
