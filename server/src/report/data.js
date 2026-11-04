// Everything the PDF report shows, gathered from the database in one place, so the HTML
// template (html.js) only lays it out and never decides anything.
import path from 'node:path';
import { similarResponses } from '../ai/triage.js';
import { scanEvents } from '../audit.js';
import { getScan } from '../scans.js';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const MAX_VALUE = 300;
const MAX_LISTED = 8;

const clip = (value, max = MAX_VALUE) => {
  if (value == null || value === '') return null;
  const s = String(value).trim();
  return s.length > max ? `${s.slice(0, max)}…` : s;
};

const aiDone = (f) => f.triage?.status === 'done';
const severityOf = (f) => (aiDone(f) ? f.triage.severity : f.severity);
const isFlagged = (f) => aiDone(f) && f.triage.falsePositive;

// The same order as the page: likely false positives last, then most severe first and, between
// equals, the one the tool itself rated higher.
function byRank(a, b) {
  return (
    isFlagged(a) - isFlagged(b) ||
    SEVERITY_ORDER.indexOf(severityOf(a)) - SEVERITY_ORDER.indexOf(severityOf(b)) ||
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    a.id - b.id
  );
}

// One nuclei template can match several times on the same page (one per missing header, one per
// detected technology); the matcher name is what tells those findings apart.
function headingOf(f) {
  const matcher = f.tool === 'nuclei' ? clip(f.raw?.['matcher-name'], 60) : null;
  return matcher ? `${f.title}: ${matcher}` : f.title;
}

// The tool's evidence for one finding, as labelled rows. Raw response bodies are left out:
// they are long, and the target controls them.
function evidenceRows(f, all) {
  const raw = f.raw ?? {};
  const rows = [];
  const add = (label, value) => {
    const v = Array.isArray(value) ? clip(value.slice(0, MAX_LISTED).join(', ')) : clip(value);
    if (v) rows.push([label, v]);
  };
  if (f.tool === 'nuclei') {
    add('Template', raw['template-id']);
    add('Matched', raw['matcher-name']);
    add('Extracted', raw['extracted-results']);
    add('Tags', raw.info?.tags);
    add("Template's CWE", (raw.info?.classification?.['cwe-id'] ?? []).map((c) => String(c).toUpperCase()));
  } else if (f.tool === 'ffuf') {
    add('HTTP status', raw.status);
    add('Response size', raw.length == null ? null : `${raw.length} bytes`);
    add('Content type', raw['content-type']);
    add('Redirects to', raw.redirectlocation);
    const similar = similarResponses(f, all);
    if (similar.length) add('Same response as', [`${similar.length} other paths: ${similar.slice(0, MAX_LISTED).join(', ')}`]);
  } else if (f.tool === 'nmap') {
    add('Port', raw.port);
    add('Service', raw.service);
    add('Product', [raw.product, raw.version].filter(Boolean).join(' '));
    add('Identified by', raw.method === 'probed' ? 'probing the service' : 'a guess from the port number');
    add('Confidence', raw.confidence == null ? null : `${raw.confidence} of 10`);
  }
  return rows;
}

// Paths on this computer (the wordlist, the tool's location) say nothing useful in a report
// and reveal the user name, so only the file name is kept.
function displayCommand(command) {
  if (!command) return null;
  const isPath = (a) => /^([a-z]:[\\/]|\/)/i.test(a);
  return command.map((a, i) => (i === 0 || isPath(a) ? path.win32.basename(path.posix.basename(a)) : a));
}

export function reportData(db, id, { now = new Date() } = {}) {
  const scan = getScan(db, id);
  if (!scan) return null;
  const all = scan.results.flatMap((r) => r.findings);
  const ranked = [...all].sort(byRank);

  const findings = ranked.map((f, i) => ({
    ...f,
    number: `F-${String(i + 1).padStart(2, '0')}`,
    heading: headingOf(f),
    // Short form for tables: every web finding is on the scan's target.
    where: f.location?.startsWith(scan.target) ? f.location.slice(scan.target.length) || '/' : f.location,
    severityApplied: severityOf(f),
    flagged: isFlagged(f),
    description: clip(f.raw?.info?.description, 600),
    remediation: clip(f.raw?.info?.remediation, 600),
    references: (f.raw?.info?.reference ?? []).slice(0, 4).map((r) => clip(r, 120)),
    evidence: evidenceRows(f, all),
  }));

  const counts = SEVERITY_ORDER.map((severity) => ({
    severity,
    tool: all.filter((f) => f.severity === severity).length,
    applied: findings.filter((f) => !f.flagged && f.severityApplied === severity).length,
  })).filter((c) => c.tool || c.applied);

  return {
    generatedAt: now.toISOString(),
    scan,
    tools: scan.results.map((r) => ({
      tool: r.tool,
      status: r.status,
      version: r.version,
      error: r.error,
      startedAt: r.startedAt,
      finishedAt: r.finishedAt,
      durationMs: r.durationMs,
      findingCount: r.findings.length,
      scope: r.scope,
      command: displayCommand(r.command),
    })),
    findings,
    counts,
    flaggedCount: findings.filter((f) => f.flagged).length,
    triage: scan.triage,
    authorization: {
      entry: scan.allowlistEntry,
      ports: scan.ports,
      events: scanEvents(db, id, scan.scopeAuditId),
    },
  };
}
