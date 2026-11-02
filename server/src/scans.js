// Scan history: every scan, each tool's run and every finding, kept in the database.

export const ACTIVE = ['queued', 'running'];
const now = () => new Date().toISOString();

// `target` is the canonical target the scope gate approved; `tools` is already in run order.
export function createScan(db, { target, tools }) {
  return db.transaction(() => {
    const { lastInsertRowid: id } = db
      .prepare("INSERT INTO scans (target, host, port, status, created_at) VALUES (?, ?, ?, 'queued', ?)")
      .run(target.url, target.host, target.port, now());
    const addTool = db.prepare("INSERT INTO scan_tools (scan_id, position, tool, status) VALUES (?, ?, ?, 'queued')");
    tools.forEach((tool, i) => addTool.run(id, i, tool));
    return Number(id);
  })();
}

// Oldest first: the order the queue runs them in.
export function queuedScans(db) {
  return db.prepare("SELECT id, target, host, port FROM scans WHERE status = 'queued' ORDER BY id").all();
}

export function countQueued(db) {
  return db.prepare("SELECT COUNT(*) AS n FROM scans WHERE status = 'queued'").get().n;
}

export function scanStatus(db, id) {
  return db.prepare('SELECT status FROM scans WHERE id = ?').get(id)?.status ?? null;
}

export function toolsOf(db, scanId) {
  return db
    .prepare('SELECT tool FROM scan_tools WHERE scan_id = ? ORDER BY position')
    .all(scanId)
    .map((r) => r.tool);
}

export function markScanRunning(db, id, ports) {
  db.prepare("UPDATE scans SET status = 'running', ports = ?, started_at = ? WHERE id = ?").run(ports, now(), id);
}

export function markToolRunning(db, scanId, tool) {
  db.prepare("UPDATE scan_tools SET status = 'running', started_at = ? WHERE scan_id = ? AND tool = ?").run(
    now(),
    scanId,
    tool,
  );
}

export function saveToolResult(db, scanId, tool, result) {
  db.transaction(() => {
    db.prepare(
      `UPDATE scan_tools SET status = ?, version = ?, error = ?, log = ?, scope = ?, finished_at = ?, duration_ms = ?
       WHERE scan_id = ? AND tool = ?`,
    ).run(
      result.status,
      result.version ?? null,
      result.error ?? null,
      result.log ?? null,
      result.scope ? JSON.stringify(result.scope) : null,
      now(),
      result.durationMs ?? null,
      scanId,
      tool,
    );
    const add = db.prepare(
      `INSERT INTO findings (scan_id, tool, type, severity, title, location, detail, ref, raw)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const f of result.findings) {
      add.run(scanId, f.tool, f.type, f.severity, f.title, f.location, f.detail, f.ref, JSON.stringify(f.raw ?? null));
    }
  })();
}

// Ends a scan. Tools that never got to run are marked skipped; one caught mid-run takes the
// scan's own status (it was stopped, it didn't finish).
export function finishScan(db, id, status, error = null) {
  db.transaction(() => {
    db.prepare('UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ?').run(status, error, now(), id);
    db.prepare("UPDATE scan_tools SET status = 'skipped' WHERE scan_id = ? AND status = 'queued'").run(id);
    db.prepare("UPDATE scan_tools SET status = ?, finished_at = ? WHERE scan_id = ? AND status = 'running'").run(
      status,
      now(),
      id,
    );
  })();
}

// For server start: nothing can still be running in a process that just started.
export function failInterrupted(db) {
  const stale = db.prepare("SELECT id, status FROM scans WHERE status IN ('queued', 'running')").all();
  for (const { id, status } of stale) {
    const error =
      status === 'running'
        ? 'the server stopped while this scan was running'
        : 'the server stopped before this scan started';
    finishScan(db, id, 'failed', error);
  }
  return stale;
}

function scanRow(r) {
  return {
    id: r.id,
    target: r.target,
    host: r.host,
    port: r.port,
    ports: r.ports,
    status: r.status,
    error: r.error,
    createdAt: r.created_at,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
  };
}

export function listScans(db, limit = 50) {
  const tools = db.prepare('SELECT tool, status FROM scan_tools WHERE scan_id = ? ORDER BY position');
  const severities = db.prepare('SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity');
  return db
    .prepare('SELECT * FROM scans ORDER BY id DESC LIMIT ?')
    .all(limit)
    .map((r) => {
      const counts = Object.fromEntries(severities.all(r.id).map((s) => [s.severity, s.n]));
      const findingCount = Object.values(counts).reduce((a, b) => a + b, 0);
      return { ...scanRow(r), tools: tools.all(r.id), findingCount, severityCounts: counts };
    });
}

// The whole scan: each tool's result with its findings, in the shape the tools return them.
export function getScan(db, id) {
  const r = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
  if (!r) return null;
  const findings = db.prepare('SELECT * FROM findings WHERE scan_id = ? AND tool = ? ORDER BY id');
  const results = db
    .prepare('SELECT * FROM scan_tools WHERE scan_id = ? ORDER BY position')
    .all(id)
    .map((t) => ({
      tool: t.tool,
      status: t.status,
      version: t.version,
      error: t.error,
      log: t.log,
      scope: t.scope ? JSON.parse(t.scope) : null,
      startedAt: t.started_at,
      finishedAt: t.finished_at,
      durationMs: t.duration_ms,
      findings: findings.all(id, t.tool).map((f) => ({
        id: f.id,
        tool: f.tool,
        type: f.type,
        severity: f.severity,
        title: f.title,
        location: f.location,
        detail: f.detail,
        ref: f.ref,
        raw: JSON.parse(f.raw),
      })),
    }));
  return { ...scanRow(r), results };
}
