import { spawn } from 'node:child_process';

const ANSI_RE = /\x1b\[[0-9;]*m/g;
const LOG_TAIL_LINES = 40;
// A process that ignores the polite kill gets the forceful one after this long.
const FORCE_KILL_AFTER_MS = 5_000;

// Runs a binary without a shell and collects its output. Aborting the signal kills it.
// Arguments are passed as an array, so nothing in them is ever interpreted by a shell.
// `onSpawn({ pid, bin })` is told about the process once it starts and may return a function
// that is called when it exits; the job queue uses this to record which processes it owns.
export function run(bin, args, { signal, onSpawn } = {}) {
  if (signal?.aborted) return Promise.resolve({ code: null, stdout: '', stderr: '', aborted: true });
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    let aborted = false;
    let forceKill = null;
    let untrack = null;
    const onAbort = () => {
      aborted = true;
      child.kill();
      forceKill = setTimeout(() => child.kill('SIGKILL'), FORCE_KILL_AFTER_MS);
    };
    const cleanUp = () => {
      signal?.removeEventListener('abort', onAbort);
      clearTimeout(forceKill);
      untrack?.();
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    child.once('spawn', () => {
      const forget = onSpawn?.({ pid: child.pid, bin });
      if (typeof forget === 'function') untrack = forget;
    });
    child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
    child.on('error', (err) => {
      cleanUp();
      reject(err);
    });
    child.on('close', (code) => {
      cleanUp();
      resolve({ code, stdout, stderr: stderr.replace(ANSI_RE, ''), aborted });
    });
  });
}

// The last lines of a tool's own log, so a failed scan can be explained without re-running it.
export function logTail(text) {
  return text.trim().split('\n').slice(-LOG_TAIL_LINES).join('\n');
}

// The result shape every tool returns when its binary can't be started at all.
export function notFound(tool, envVar, started) {
  return {
    status: 'failed',
    error: `${tool} was not found: put it on PATH or set ${envVar} in server/.env`,
    findings: [],
    log: '',
    version: null,
    durationMs: Date.now() - started,
  };
}
