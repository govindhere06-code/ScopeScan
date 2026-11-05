// "Did this get fixed?": a scan's findings set against an earlier scan of the same target.
// Only tools that completed in both scans are compared: a tool that failed, timed out or didn't
// run can't show that something went away.
import { ACTIVE, getScan } from './scans.js';
import { ScopeError } from './scope.js';

// What makes two findings "the same" across scans: the tool, what it checked and where. Values
// that change between runs (response sizes, extracted versions) don't count.
export function fingerprint(f) {
  const matcher = f.tool === 'nuclei' ? (f.raw?.['matcher-name'] ?? '') : '';
  return [f.tool, f.type, f.ref ?? '', matcher, f.location ?? ''].join('|');
}

const completedTools = (scan) => new Set(scan.results.filter((r) => r.status === 'done').map((r) => r.tool));

// The newest earlier finished scan of the same host and port that shares a completed tool.
function previousScan(db, scan) {
  const earlier = db
    .prepare('SELECT id FROM scans WHERE host = ? AND port = ? AND id < ? ORDER BY id DESC')
    .all(scan.host, scan.port, scan.id);
  const done = completedTools(scan);
  for (const { id } of earlier) {
    const candidate = getScan(db, id);
    if (ACTIVE.includes(candidate.status)) continue;
    if ([...completedTools(candidate)].some((tool) => done.has(tool))) return candidate;
  }
  return null;
}

// Compares scan `id` with scan `withId`, or with the previous comparable scan of the same target.
// Returns null for an unknown scan; `previous` is null when there is nothing to compare with.
export function compareScans(db, id, withId = null) {
  const scan = getScan(db, id);
  if (!scan) return null;
  let previous = null;
  if (withId !== null) {
    previous = getScan(db, withId);
    if (!previous) throw new ScopeError(`no scan #${withId} to compare with`);
    if (previous.id === scan.id) throw new ScopeError('a scan cannot be compared with itself');
    if (previous.host !== scan.host || previous.port !== scan.port) {
      throw new ScopeError(`scan #${withId} is of a different target`);
    }
  } else {
    previous = previousScan(db, scan);
  }
  if (!previous || ACTIVE.includes(scan.status) || ACTIVE.includes(previous.status)) {
    return { previous: previous && summary(previous), compared: [], notCompared: [], newIds: [], gone: [], unchanged: 0 };
  }

  const nowDone = completedTools(scan);
  const thenDone = completedTools(previous);
  const compared = [...nowDone].filter((tool) => thenDone.has(tool));
  const notCompared = [...new Set([...scan.results, ...previous.results].map((r) => r.tool))]
    .filter((tool) => !compared.includes(tool))
    .map((tool) => ({
      tool,
      reason: !nowDone.has(tool)
        ? `did not complete in scan #${scan.id}`
        : `did not complete in scan #${previous.id}`,
    }));

  const findingsOf = (s) => s.results.filter((r) => compared.includes(r.tool)).flatMap((r) => r.findings);
  const now = findingsOf(scan);
  const then = findingsOf(previous);
  const thenKeys = new Set(then.map(fingerprint));
  const nowKeys = new Set(now.map(fingerprint));

  return {
    previous: summary(previous),
    compared,
    notCompared,
    newIds: now.filter((f) => !thenKeys.has(fingerprint(f))).map((f) => f.id),
    // Found last time, not this time. Kept whole, so the page and report can say what it was.
    gone: then
      .filter((f) => !nowKeys.has(fingerprint(f)))
      .map((f) => ({
        id: f.id,
        tool: f.tool,
        title: f.title,
        location: f.location,
        detail: f.detail,
        severity: f.triage?.status === 'done' ? f.triage.severity : f.severity,
        toolSeverity: f.severity,
        flagged: f.triage?.status === 'done' && f.triage.falsePositive,
        matcher: f.tool === 'nuclei' ? (f.raw?.['matcher-name'] ?? null) : null,
      })),
    unchanged: now.filter((f) => thenKeys.has(fingerprint(f))).length,
  };
}

function summary(scan) {
  return { id: scan.id, status: scan.status, startedAt: scan.startedAt, finishedAt: scan.finishedAt };
}
