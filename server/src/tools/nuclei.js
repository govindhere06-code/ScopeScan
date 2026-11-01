import { spawn } from 'node:child_process';
import { startScopeProxy } from '../scopeProxy.js';

// Every flag here was checked against `nuclei -h` (v3.11.1).
const SCAN_FLAGS = [
  '-jsonl', // one finding per line on stdout; logs go to stderr
  // HTTP templates only. tcp/javascript/ssl/dns templates open their own connections to
  // other ports and protocols, which the scope proxy can't see or stop.
  '-pt', 'http',
  '-ni', // no Interactsh: out-of-band checks send traffic to a public server
  '-dr', // don't follow redirects, which could lead off the allowlisted host
  '-duc', // no update check, so templates can't change between runs
  '-nc', // no colour codes in the log lines we parse
  // Gentle enough that Juice Shop doesn't run out of memory (full speed crashes it).
  '-rl', '25',
  '-c', '5',
  '-timeout', '15',
];

const SKIPPED_RE = /Skipped (\S+) from target list as found unresponsive/g;
const ANSI_RE = /\x1b\[[0-9;]*m/g;
const LOG_TAIL_LINES = 40;

export function nucleiBinary() {
  return process.env.NUCLEI_PATH || 'nuclei';
}

// The URL is its own array element right after -u, so it can never be read as a flag,
// and nothing goes through a shell. All traffic goes through the scope proxy.
export function buildScanArgs(url, proxyUrl) {
  return ['-u', url, '-proxy', proxyUrl, ...SCAN_FLAGS];
}

// Runs a binary without a shell and collects its output. Aborting the signal kills it.
function run(bin, args, { signal } = {}) {
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

export function parseFindings(stdout) {
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line))
    .map((raw) => ({
      templateId: raw['template-id'],
      name: raw.info?.name ?? raw['template-id'],
      severity: raw.info?.severity ?? 'unknown',
      matcherName: raw['matcher-name'] ?? null,
      matchedAt: raw['matched-at'] ?? raw.host,
      extracted: raw['extracted-results'] ?? [],
      raw,
    }));
}

// "0 findings" only counts as a clean result if nuclei actually scanned the target.
// Only a skip of *our* target matters: blocked off-scope ports get skipped too, harmlessly.
export function interpretRun({ code, stdout, stderr, aborted }, target) {
  const findings = parseFindings(stdout);
  const skipped = [...stderr.matchAll(SKIPPED_RE)].map((m) => m[1]);
  let error = null;
  if (aborted) error = 'scan was cancelled';
  else if (skipped.includes(`${target.host}:${target.port}`)) {
    error = 'the target stopped responding and nuclei skipped it, so these results are incomplete';
  } else if (code !== 0) error = `nuclei exited with code ${code}`;
  // nuclei's own log, so a failed scan can be explained without re-running it.
  const log = stderr.trim().split('\n').slice(-LOG_TAIL_LINES).join('\n');
  return { status: error ? 'failed' : 'done', error, findings, log };
}

async function getVersions(signal) {
  const bin = nucleiBinary();
  const [engine, templates] = await Promise.all([
    run(bin, ['-version', '-duc'], { signal }),
    run(bin, ['-tv', '-duc'], { signal }),
  ]);
  return {
    nuclei: (engine.stdout + engine.stderr).match(/Engine Version: (v[\w.-]+)/)?.[1] ?? 'unknown',
    templates: (templates.stdout + templates.stderr).match(/templates version: (v[\w.-]+)/)?.[1] ?? 'unknown',
  };
}

// `target` is the canonical target returned by isAllowed(): { url, host, port }.
export async function runNucleiScan(target, { signal } = {}) {
  const started = Date.now();
  const proxy = await startScopeProxy(target);
  try {
    const versions = await getVersions(signal);
    const result = interpretRun(await run(nucleiBinary(), buildScanArgs(target.url, proxy.url), { signal }), target);
    return { ...result, versions, scope: proxy.stats(), durationMs: Date.now() - started };
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    return {
      status: 'failed',
      error: 'nuclei was not found: put it on PATH or set NUCLEI_PATH in server/.env',
      findings: [],
      log: '',
      versions: null,
      scope: proxy.stats(),
      durationMs: Date.now() - started,
    };
  } finally {
    await proxy.close();
  }
}
