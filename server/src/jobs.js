import { isAllowed } from './allowlist.js';
import { logEvent } from './audit.js';
import { killOrphans, trackProcess } from './processes.js';
import * as scans from './scans.js';
import { runFfufScan } from './tools/ffuf.js';
import { runNmapScan } from './tools/nmap.js';
import { runNucleiScan } from './tools/nuclei.js';

const DEFAULT_SCANNERS = { nmap: runNmapScan, ffuf: runFfufScan, nuclei: runNucleiScan };
export const DEFAULT_TIMEOUT_MS = 60 * 60_000;
// Two parallel scans are already enough to knock Juice Shop over, so never more than this.
export const MAX_CONCURRENCY = 2;
const MAX_QUEUED = 20;

// Why a scan was stopped (the abort reason) and what that makes its status.
const STOPPED_STATUS = { timeout: 'timed_out', cancelled: 'cancelled', shutdown: 'failed' };

export class QueueFullError extends Error {}

function formatLimit(ms) {
  return ms >= 60_000 ? `${+(ms / 60_000).toFixed(1)} minutes` : `${+(ms / 1000).toFixed(1)} seconds`;
}

// Scans run in the background, in the order they were requested. The queue itself is the
// `scans` table (status 'queued'), so the history always shows exactly what is waiting.
export function createScanQueue({
  db,
  scanners = DEFAULT_SCANNERS,
  concurrency = 1,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxQueued = MAX_QUEUED,
}) {
  const limit = Math.min(Math.max(1, Math.trunc(concurrency) || 1), MAX_CONCURRENCY);
  const running = new Map(); // scan id -> { controller, key }

  const stopMessage = (reason) =>
    ({
      timeout: `stopped at the time limit of ${formatLimit(timeoutMs)}`,
      cancelled: 'cancelled',
      shutdown: 'the server was stopped during this scan',
    })[reason];

  function enqueue({ target, tools }) {
    if (scans.countQueued(db) >= maxQueued) {
      throw new QueueFullError(`${maxQueued} scans are already waiting; let some finish first`);
    }
    const id = scans.createScan(db, { target, tools });
    logEvent(db, {
      action: 'scan_queued',
      input: target.url,
      host: target.host,
      port: target.port,
      decision: 'queued',
      reason: `scan #${id}: ${tools.join(', ')}`,
    });
    pump();
    return scans.getScan(db, id);
  }

  function pump() {
    for (const scan of scans.queuedScans(db)) {
      if (running.size >= limit) return;
      if (running.has(scan.id)) continue;
      const key = `${scan.host}:${scan.port}`;
      // Two scans of the same target at once would only make it fall over; this one waits.
      if ([...running.values()].some((r) => r.key === key)) continue;
      const controller = new AbortController();
      running.set(scan.id, { controller, key });
      execute(scan, controller)
        .catch((err) => {
          console.error(err);
          scans.finishScan(db, scan.id, 'failed', `internal error: ${err.message}`);
        })
        .finally(() => {
          running.delete(scan.id);
          pump();
        });
    }
  }

  async function execute(scan, controller) {
    const { signal } = controller;
    const audit = { input: scan.target, host: scan.host, port: scan.port };

    // Checked again now, not just when queued: the entry may have been removed or narrowed
    // while this scan waited.
    const scope = isAllowed(db, scan.target);
    if (!scope.allowed) {
      scans.finishScan(db, scan.id, 'failed', `refused when it was about to start: ${scope.reason}`);
      logEvent(db, { ...audit, action: 'scan_refused', decision: 'denied', reason: `scan #${scan.id}: ${scope.reason}` });
      return;
    }
    const { target, ports } = scope;
    scans.markScanRunning(db, scan.id, ports);
    logEvent(db, { ...audit, action: 'scan_started', decision: 'started', reason: `scan #${scan.id}` });

    const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
    const onSpawn = (proc) => trackProcess(db, scan.id, proc);
    let failed = false;
    try {
      for (const tool of scans.toolsOf(db, scan.id)) {
        if (signal.aborted) break;
        scans.markToolRunning(db, scan.id, tool);
        const toolAudit = { ...audit, action: `scan_${tool}` };
        logEvent(db, { ...toolAudit, decision: 'started', reason: `scan #${scan.id}` });
        let result;
        try {
          result = await scanners[tool]({ target, ports }, { signal, onSpawn });
        } catch (err) {
          result = { status: 'failed', error: `${tool} could not run: ${err.message}`, findings: [], log: '' };
        }
        // Whatever the tool made of being killed, the reason it was killed is what counts.
        if (signal.aborted) {
          result = { ...result, status: STOPPED_STATUS[signal.reason], error: stopMessage(signal.reason) };
        }
        scans.saveToolResult(db, scan.id, tool, result);
        failed ||= result.status === 'failed';

        const blocked = result.scope ? `, ${result.scope.blockedRequests} off-scope requests blocked` : '';
        const summary = `scan #${scan.id}: ${result.findings.length} findings${blocked}`;
        logEvent(db, {
          ...toolAudit,
          decision: result.status,
          reason: result.error ? `${summary} (${result.error})` : summary,
        });
      }
    } finally {
      clearTimeout(timer);
    }

    let status = failed ? 'failed' : 'done';
    let error = failed ? 'one or more tools failed; see their results' : null;
    if (signal.aborted) {
      status = STOPPED_STATUS[signal.reason];
      error = stopMessage(signal.reason);
    }
    scans.finishScan(db, scan.id, status, error);
    logEvent(db, {
      ...audit,
      action: 'scan_finished',
      decision: status,
      reason: `scan #${scan.id}${error ? `: ${error}` : ''}`,
    });
  }

  // Returns 'cancelled' (it never started), 'stopping' (its tool is being killed),
  // 'finished' (too late) or null (no such scan).
  function cancel(id) {
    const status = scans.scanStatus(db, id);
    if (status === null) return null;
    const job = running.get(id);
    if (job) {
      job.controller.abort('cancelled');
      return 'stopping';
    }
    if (status !== 'queued') return 'finished';
    scans.finishScan(db, id, 'cancelled', 'cancelled before it started');
    const { host, port, target } = scans.getScan(db, id);
    logEvent(db, { action: 'scan_finished', input: target, host, port, decision: 'cancelled', reason: `scan #${id}` });
    return 'cancelled';
  }

  // For the server shutting down: kill every running tool and record why, synchronously,
  // because the process is about to exit.
  function shutdown() {
    for (const [id, { controller }] of running) {
      controller.abort('shutdown');
      scans.finishScan(db, id, 'failed', stopMessage('shutdown'));
    }
    running.clear();
  }

  return { enqueue, cancel, shutdown, limit, timeoutMs };
}

// Run once at server start, before any new scan: whatever was running belonged to a
// server that is gone.
export async function recoverScans(db) {
  const killed = await killOrphans(db);
  for (const p of killed) {
    logEvent(db, { action: 'orphan_killed', decision: 'killed', reason: `${p.name} (pid ${p.pid}) from scan #${p.scan_id}` });
  }
  const stale = scans.failInterrupted(db);
  for (const s of stale) {
    logEvent(db, { action: 'scan_finished', decision: 'failed', reason: `scan #${s.id}: interrupted by a server restart` });
  }
  return { killed, stale };
}
