import { logEvent } from '../audit.js';
import { AiUnavailableError } from './ollama.js';
import * as store from './store.js';
import { triageFinding } from './triage.js';

// Sends finished scans to the local model, one scan and one finding at a time (the GPU can
// only do one thing at a time anyway). Independent of the scan queue: a scan is done when its
// tools are done; triage adds opinions afterwards and can be re-run.
export function createTriageQueue({ db, chat }) {
  let running = null; // { scanId, controller }

  function audit(scanId, decision, reason) {
    logEvent(db, { action: 'ai_triage', decision, reason: `scan #${scanId}${reason ? `: ${reason}` : ''}`, scanId });
  }

  // Returns false if the scan has no findings to triage.
  function enqueue(scanId) {
    if (store.scanFindings(db, scanId).length === 0) return false;
    if (running?.scanId === scanId) running.controller.abort();
    store.queueTriage(db, scanId, chat.model);
    audit(scanId, 'queued', chat.model);
    pump();
    return true;
  }

  // For server start: picks up where an interrupted run left off.
  function resume() {
    for (const scanId of store.interruptedTriage(db)) audit(scanId, 'queued', 'resumed after a server restart');
    pump();
  }

  function pump() {
    if (running) return;
    const scanId = store.nextQueuedTriage(db);
    if (scanId === null) return;
    const controller = new AbortController();
    running = { scanId, controller };
    execute(scanId, controller.signal)
      .catch((err) => {
        console.error(err);
        store.finishTriage(db, scanId, 'failed', `internal error: ${err.message}`);
        audit(scanId, 'failed', err.message);
      })
      .finally(() => {
        running = null;
        pump();
      });
  }

  async function execute(scanId, signal) {
    store.markTriageRunning(db, scanId);
    audit(scanId, 'started');
    const findings = store.scanFindings(db, scanId);
    const counts = { flagged: 0, changed: 0, injections: 0, failed: 0 };
    for (const finding of findings) {
      if (signal.aborted) return; // re-queued; the new run takes over
      const started = Date.now();
      let result;
      try {
        result = await triageFinding(finding, { chat, signal, scanFindings: findings });
      } catch (err) {
        if (signal.aborted) return;
        if (!(err instanceof AiUnavailableError)) throw err;
        // Nothing more can be done without the model; what's triaged so far is kept.
        store.finishTriage(db, scanId, 'failed', err.message);
        audit(scanId, 'failed', err.message);
        return;
      }
      if (signal.aborted) return;
      store.saveFindingTriage(db, finding.id, scanId, result, chat.model, Date.now() - started);
      if (result.status === 'failed') counts.failed += 1;
      else {
        if (result.applied.falsePositive) counts.flagged += 1;
        if (result.applied.severity !== finding.severity) counts.changed += 1;
        if (result.injectionSuspected) counts.injections += 1;
      }
    }
    const error = counts.failed ? `${counts.failed} of ${findings.length} findings got no usable answer` : null;
    store.finishTriage(db, scanId, 'done', error);
    audit(
      scanId,
      'done',
      `${findings.length} findings, ${counts.flagged} flagged as likely false positives, ` +
        `${counts.changed} severity changes, ${counts.injections} possible prompt injections` +
        (error ? `, ${error}` : ''),
    );
  }

  function busyWith(scanId) {
    const status = store.triageStatus(db, scanId);
    return status === 'queued' || status === 'running';
  }

  function shutdown() {
    running?.controller.abort();
  }

  return { enqueue, resume, busyWith, shutdown, model: chat.model };
}
