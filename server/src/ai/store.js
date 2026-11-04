import { OWASP_EDITION, OWASP_TOP_10 } from './owasp.js';

// Saved AI triage: per scan (status) and per finding (the model's opinion).

const now = () => new Date().toISOString();
const OWASP_NAMES = Object.fromEntries(OWASP_TOP_10.map((c) => [c.id, c.name]));

// Starts over: any earlier opinions on this scan's findings are dropped, the findings stay.
export function queueTriage(db, scanId, model) {
  db.transaction(() => {
    db.prepare('DELETE FROM finding_triage WHERE scan_id = ?').run(scanId);
    db.prepare(
      "INSERT OR REPLACE INTO scan_triage (scan_id, status, model, queued_at) VALUES (?, 'queued', ?, ?)",
    ).run(scanId, model, now());
  })();
}

export function nextQueuedTriage(db) {
  return db.prepare("SELECT scan_id FROM scan_triage WHERE status = 'queued' ORDER BY queued_at LIMIT 1").get()?.scan_id ?? null;
}

export function triageStatus(db, scanId) {
  return db.prepare('SELECT status FROM scan_triage WHERE scan_id = ?').get(scanId)?.status ?? null;
}

export function markTriageRunning(db, scanId) {
  db.prepare("UPDATE scan_triage SET status = 'running', started_at = ? WHERE scan_id = ?").run(now(), scanId);
}

export function finishTriage(db, scanId, status, error = null) {
  db.prepare('UPDATE scan_triage SET status = ?, error = ?, finished_at = ? WHERE scan_id = ?').run(
    status,
    error,
    now(),
    scanId,
  );
}

// For server start: triage only talks to the local model, so an interrupted one can simply
// run again.
export function interruptedTriage(db) {
  const ids = db
    .prepare("SELECT scan_id FROM scan_triage WHERE status IN ('queued', 'running') ORDER BY queued_at")
    .all()
    .map((r) => r.scan_id);
  db.prepare("UPDATE scan_triage SET status = 'queued' WHERE status = 'running'").run();
  return ids;
}

export function scanFindings(db, scanId) {
  return db
    .prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY id')
    .all(scanId)
    .map((f) => ({ ...f, raw: JSON.parse(f.raw) }));
}

export function saveFindingTriage(db, findingId, scanId, result, model, durationMs) {
  const m = result.model ?? {};
  const bool = (v) => (v === undefined ? null : v ? 1 : 0);
  db.prepare(
    `INSERT OR REPLACE INTO finding_triage (
       finding_id, scan_id, status, error, model_false_positive, false_positive_reason, model_severity,
       severity_reason, explanation, fix, owasp, cwe, injection_suspected, false_positive, severity,
       model, duration_ms, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    findingId,
    scanId,
    result.status,
    result.error ?? null,
    bool(m.falsePositive),
    m.falsePositiveReason ?? null,
    m.severity ?? null,
    m.severityReason ?? null,
    m.explanation ?? null,
    m.fix ?? null,
    m.owasp ?? null,
    m.cwe ?? null,
    result.injectionSuspected ? 1 : 0,
    bool(result.applied?.falsePositive),
    result.applied?.severity ?? null,
    model,
    durationMs,
    now(),
  );
}

// { status, model, error, done, total } for a scan that has been sent to the model, else null.
export function scanTriageSummary(db, scanId) {
  const t = db.prepare('SELECT * FROM scan_triage WHERE scan_id = ?').get(scanId);
  if (!t) return null;
  const counts = db
    .prepare(
      `SELECT COUNT(*) AS done,
              SUM(status = 'failed') AS failed,
              SUM(false_positive = 1) AS flagged,
              SUM(injection_suspected = 1) AS injections
       FROM finding_triage WHERE scan_id = ?`,
    )
    .get(scanId);
  const total = db.prepare('SELECT COUNT(*) AS n FROM findings WHERE scan_id = ?').get(scanId).n;
  return {
    status: t.status,
    model: t.model,
    error: t.error,
    done: counts.done,
    failed: counts.failed ?? 0,
    flagged: counts.flagged ?? 0,
    injections: counts.injections ?? 0,
    total,
    startedAt: t.started_at,
    finishedAt: t.finished_at,
  };
}

// finding id -> the opinion, in the shape the page shows.
export function findingTriageByFinding(db, scanId) {
  const rows = db.prepare('SELECT * FROM finding_triage WHERE scan_id = ?').all(scanId);
  return new Map(
    rows.map((r) => [
      r.finding_id,
      r.status === 'failed'
        ? { status: 'failed', error: r.error, model: r.model }
        : {
            status: 'done',
            model: r.model,
            falsePositive: r.false_positive === 1,
            severity: r.severity,
            injectionSuspected: r.injection_suspected === 1,
            modelSaid: { falsePositive: r.model_false_positive === 1, severity: r.model_severity },
            falsePositiveReason: r.false_positive_reason,
            severityReason: r.severity_reason,
            explanation: r.explanation,
            fix: r.fix,
            owasp: r.owasp === 'none' ? null : { id: `${r.owasp}:${OWASP_EDITION}`, name: OWASP_NAMES[r.owasp] },
            cwe: r.cwe || null,
          },
    ]),
  );
}
