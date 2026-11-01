import { spawn } from 'node:child_process';

const ANSI_RE = /\x1b\[[0-9;]*m/g;
const LOG_TAIL_LINES = 40;

// Runs a binary without a shell and collects its output. Aborting the signal kills it.
// Arguments are passed as an array, so nothing in them is ever interpreted by a shell.
export function run(bin, args, { signal } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    let aborted = false;
    const onAbort = () => {
      aborted = true;
      child.kill();
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
    child.on('error', (err) => {
      signal?.removeEventListener('abort', onAbort);
      reject(err);
    });
    child.on('close', (code) => {
      signal?.removeEventListener('abort', onAbort);
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
