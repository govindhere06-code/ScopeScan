import { ALL_PORTS } from '../scope.js';
import { finding } from './findings.js';
import { logTail, notFound, run } from './run.js';

// nmap opens raw TCP connections, so it can't go through the scope proxy.
// Its scope is enforced by its arguments instead. Flags checked against nmap 7.992.
const SCAN_FLAGS = [
  '-sT', // plain TCP connect scan: no raw packets, no admin rights needed
  '-sV', // ask each open port what it's running
  '-Pn', // no host-discovery ping; go straight to the listed ports
  '-n', // no reverse-DNS lookups, so no queries go to outside DNS servers
  '-oX', '-', // XML report on stdout
];

// For an entry that grants every port, scan nmap's 1000 most common ones rather than all 65535.
const TOP_PORTS = '1000';

export function nmapBinary() {
  return process.env.NMAP_PATH || 'nmap';
}

// `ports` is the allowlist entry's port list ("3000,8080" or "*"), never user input.
export function buildScanArgs(host, ports) {
  const portArgs = ports === ALL_PORTS ? ['--top-ports', TOP_PORTS] : ['-p', ports];
  const ipv6 = host.startsWith('[');
  return [...SCAN_FLAGS, ...(ipv6 ? ['-6'] : []), ...portArgs, ipv6 ? host.slice(1, -1) : host];
}

function attributes(tag) {
  return Object.fromEntries([...tag.matchAll(/([\w-]+)="([^"]*)"/g)].map((m) => [m[1], decodeXml(m[2])]));
}

function decodeXml(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&amp;/g, '&');
}

// nmap's XML is regular enough to read with patterns; no XML library needed.
export function parsePorts(xml) {
  return [...xml.matchAll(/<port [^>]*>[\s\S]*?<\/port>/g)].map(([block]) => {
    const port = attributes(block.match(/<port [^>]*>/)[0]);
    const state = attributes(block.match(/<state [^>]*>/)?.[0] ?? '');
    const service = attributes(block.match(/<service [^>]*>/)?.[0] ?? '');
    const cpe = [...block.matchAll(/<cpe>([^<]*)<\/cpe>/g)].map((m) => m[1]);
    return {
      port: Number(port.portid),
      protocol: port.protocol,
      state: state.state,
      reason: state.reason,
      service: service.name ?? null,
      product: service.product ?? null,
      version: service.version ?? null,
      extrainfo: service.extrainfo ?? null,
      // "probed" = nmap talked to the service and recognised it; "table" = a guess from the port number.
      method: service.method ?? null,
      confidence: service.conf ? Number(service.conf) : null,
      cpe,
    };
  });
}

export function parseFindings(xml, host) {
  return parsePorts(xml)
    .filter((p) => p.state === 'open')
    .map((p) => {
      const guessed = p.method !== 'probed';
      const name = p.service ? `${p.service}${guessed ? '?' : ''}` : 'unknown service';
      const product = [p.product, p.version, p.extrainfo].filter(Boolean).join(' ');
      const confidence = p.confidence === null ? '' : `confidence ${p.confidence}/10`;
      const how = guessed ? 'guessed from the port number' : 'identified by probing';
      return finding({
        tool: 'nmap',
        type: 'open-port',
        severity: 'info',
        title: `${p.port}/${p.protocol} open: ${product || name}`,
        location: `${host}:${p.port}`,
        detail: [name, confidence && `${how}, ${confidence}`, ...p.cpe].filter(Boolean).join(' · '),
        ref: p.service,
        raw: p,
      });
    });
}

export function interpretRun({ code, stdout, stderr, aborted }, host) {
  let error = null;
  if (aborted) error = 'scan was cancelled';
  else if (code !== 0) error = `nmap exited with code ${code}`;
  else if (!/<finished [^>]*exit="success"/.test(stdout)) error = 'nmap did not report a successful finish';
  const findings = error ? [] : parseFindings(stdout, host);
  return { status: error ? 'failed' : 'done', error, findings, log: logTail(stderr) };
}

async function getVersion(options) {
  const { stdout } = await run(nmapBinary(), ['--version'], options);
  return stdout.match(/Nmap version ([\w.-]+)/)?.[1] ?? 'unknown';
}

// `ports` comes from the allowlist entry that authorized this host.
export async function runNmapScan({ target, ports }, options = {}) {
  const started = Date.now();
  try {
    const version = await getVersion(options);
    const output = await run(nmapBinary(), buildScanArgs(target.host, ports), options);
    return { ...interpretRun(output, target.host), version, durationMs: Date.now() - started };
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    return notFound('nmap', 'NMAP_PATH', started);
  }
}
