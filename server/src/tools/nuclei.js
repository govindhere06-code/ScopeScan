import { startScopeProxy } from '../scopeProxy.js';
import { finding } from './findings.js';
import { logTail, notFound, run } from './run.js';

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

export function nucleiBinary() {
  return process.env.NUCLEI_PATH || 'nuclei';
}

// The URL is its own array element right after -u, so it can never be read as a flag.
// All traffic goes through the scope proxy.
export function buildScanArgs(url, proxyUrl) {
  return ['-u', url, '-proxy', proxyUrl, ...SCAN_FLAGS];
}

export function parseFindings(stdout) {
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line))
    .map((raw) => {
      const extracted = raw['extracted-results'] ?? [];
      const evidence = [raw['matcher-name'], ...extracted].filter(Boolean).join(', ');
      return finding({
        tool: 'nuclei',
        type: 'template-match',
        severity: raw.info?.severity ?? 'unknown',
        title: raw.info?.name ?? raw['template-id'],
        location: raw['matched-at'] ?? raw.host,
        detail: evidence || null,
        ref: raw['template-id'],
        raw,
      });
    });
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
  return { status: error ? 'failed' : 'done', error, findings, log: logTail(stderr) };
}

async function getVersion(options) {
  const bin = nucleiBinary();
  const [engine, templates] = await Promise.all([
    run(bin, ['-version', '-duc'], options),
    run(bin, ['-tv', '-duc'], options),
  ]);
  const engineVersion = (engine.stdout + engine.stderr).match(/Engine Version: (v[\w.-]+)/)?.[1] ?? 'unknown';
  const templatesVersion = (templates.stdout + templates.stderr).match(/templates version: (v[\w.-]+)/)?.[1] ?? 'unknown';
  return `${engineVersion}, templates ${templatesVersion}`;
}

// `target` is the canonical target returned by isAllowed(): { url, host, port }.
// `options` ({ signal, onSpawn }) goes to every process this starts; see run().
export async function runNucleiScan({ target }, options = {}) {
  const started = Date.now();
  const proxy = await startScopeProxy(target);
  try {
    const version = await getVersion(options);
    const command = [nucleiBinary(), ...buildScanArgs(target.url, proxy.url)];
    const result = interpretRun(await run(command[0], command.slice(1), options), target);
    return { ...result, version, command, scope: proxy.stats(), durationMs: Date.now() - started };
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    return { ...notFound('nuclei', 'NUCLEI_PATH', started), scope: proxy.stats() };
  } finally {
    await proxy.close();
  }
}
