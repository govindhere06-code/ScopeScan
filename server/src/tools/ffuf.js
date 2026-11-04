import { startScopeProxy } from '../scopeProxy.js';
import { finding } from './findings.js';
import { logTail, notFound, run } from './run.js';

// Every flag here was checked against `ffuf -h` (v2.3.0).
const SCAN_FLAGS = [
  '-json', // one result per line on stdout
  // Learn what "not found" looks like first. Many apps (Juice Shop included) answer every
  // path with 200 and the same page, which would otherwise make every word a "hit".
  '-ac',
  '-noninteractive',
  // Same gentle limits as nuclei, so the target stays up.
  '-t', '5',
  '-rate', '25',
];

// More than this share of requests to the target failing means the results can't be trusted.
const MAX_ERROR_RATE = 0.1;

export function ffufBinary() {
  return process.env.FFUF_PATH || 'ffuf';
}

// The wordlist comes from server config, never from the request.
export function ffufWordlist() {
  return process.env.FFUF_WORDLIST || null;
}

// Fuzz one directory level below the target URL, ignoring any query string.
export function fuzzUrl(url) {
  const u = new URL(url);
  return `${u.origin}${u.pathname.replace(/\/+$/, '')}/FUZZ`;
}

export function buildScanArgs(url, wordlist, proxyUrl) {
  return ['-u', fuzzUrl(url), '-w', wordlist, '-x', proxyUrl, ...SCAN_FLAGS];
}

export function parseFindings(stdout) {
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line))
    .map((raw) => {
      const path = new URL(raw.url).pathname;
      const redirect = raw.redirectlocation ? ` → ${raw.redirectlocation}` : '';
      return finding({
        tool: 'ffuf',
        type: 'path',
        severity: 'info',
        title: `${raw.status} ${path}`,
        location: raw.url,
        detail: `${raw.length} bytes, ${raw['content-type'] || 'no content type'}${redirect}`,
        ref: path,
        raw,
      });
    });
}

// ffuf exits 0 even when every request failed, so the proxy's counts decide.
export function interpretRun({ code, stdout, stderr, aborted }, scope) {
  const findings = parseFindings(stdout);
  let error = null;
  if (aborted) error = 'scan was cancelled';
  else if (code !== 0) error = `ffuf exited with code ${code}`;
  else if (scope.allowedRequests === 0) error = 'ffuf sent no requests to the target';
  else if (scope.upstreamErrors / scope.allowedRequests > MAX_ERROR_RATE) {
    error = `${scope.upstreamErrors} of ${scope.allowedRequests} requests to the target failed, so these results are incomplete`;
  }
  return { status: error ? 'failed' : 'done', error, findings, log: logTail(stderr) };
}

async function getVersion(options) {
  const { stdout, stderr } = await run(ffufBinary(), ['-V'], options);
  return (stdout + stderr).match(/version: ([\w.-]+)/)?.[1] ?? 'unknown';
}

export async function runFfufScan({ target }, options = {}) {
  const started = Date.now();
  const wordlist = ffufWordlist();
  if (!wordlist) {
    return {
      status: 'failed',
      error: 'no wordlist configured: set FFUF_WORDLIST in server/.env',
      findings: [],
      log: '',
      version: null,
      durationMs: 0,
    };
  }
  const proxy = await startScopeProxy(target);
  try {
    const version = await getVersion(options);
    const command = [ffufBinary(), ...buildScanArgs(target.url, wordlist, proxy.url)];
    const output = await run(command[0], command.slice(1), options);
    const scope = proxy.stats();
    return { ...interpretRun(output, scope), version, command, scope, durationMs: Date.now() - started };
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    return { ...notFound('ffuf', 'FFUF_PATH', started), scope: proxy.stats() };
  } finally {
    await proxy.close();
  }
}
