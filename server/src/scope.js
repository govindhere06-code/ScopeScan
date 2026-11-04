// Pure scope logic: turning user input into a canonical target and matching it
// against allowlist entries. No database access here, so every rule is unit-testable.

// Every spelling of "this machine" is stored and compared as 127.0.0.1.
// (Not "localhost": on Windows it can resolve to ::1, which Docker isn't bound to.)
export const LOOPBACK = '127.0.0.1';
const LOOPBACK_ALIASES = new Set(['localhost', '127.0.0.1', '[::1]']);

export const ALL_PORTS = '*';
const DEFAULT_PORTS = { 'http:': 80, 'https:': 443 };
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;
const IPV6_RE = /^\[[0-9a-f:.]+\]$/;
const MAX_INPUT_LENGTH = 2048;

// Thrown for anything the user typed wrong; the API turns it into a 400 or a denial.
export class ScopeError extends Error {}

function checkRawInput(input) {
  if (typeof input !== 'string') throw new ScopeError('target must be a string');
  const value = input.trim();
  if (value === '') throw new ScopeError('target is empty');
  if (value.length > MAX_INPUT_LENGTH) throw new ScopeError('target is too long');
  // A target like "-iL file" would be read as a flag by nmap and friends.
  if (value.startsWith('-')) throw new ScopeError('target must not start with "-"');
  if (/[\s\x00-\x1f\x7f]/.test(value)) {
    throw new ScopeError('target must not contain spaces or control characters');
  }
  return value;
}

function parseUrl(value) {
  // "localhost:3000" has no scheme; without this, URL would read "localhost:" as one.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw new ScopeError('target is not a valid host or URL');
  }
  if (!Object.hasOwn(DEFAULT_PORTS, url.protocol)) {
    throw new ScopeError(`scheme "${url.protocol}" is not allowed (http or https only)`);
  }
  if (url.username || url.password) {
    throw new ScopeError('target must not contain a username or password');
  }
  return url;
}

// URL has already lowercased the host, decoded %-escapes and normalized IPv4 forms
// like 127.1 or 2130706433 to 127.0.0.1. What's left: trailing dots and loopback aliases.
function canonicalHost(hostname) {
  const host = hostname.replace(/\.+$/, '');
  if (LOOPBACK_ALIASES.has(host)) return LOOPBACK;
  if (!HOSTNAME_RE.test(host) && !IPV6_RE.test(host)) {
    throw new ScopeError(`"${hostname}" is not a valid host name`);
  }
  return host;
}

// A scan target: "localhost:3000", "http://localhost:3000/login", etc.
export function parseTarget(input) {
  const url = parseUrl(checkRawInput(input));
  const host = canonicalHost(url.hostname);
  const port = url.port ? Number(url.port) : DEFAULT_PORTS[url.protocol];
  const scheme = url.protocol.slice(0, -1);
  // No trailing "/" for the root: templates build paths as {{BaseURL}}/path, and
  // "http://host:3000/" would make them request "//path" instead.
  const pathname = url.pathname === '/' ? '' : url.pathname;
  return { scheme, host, port, url: `${scheme}://${host}:${port}${pathname}${url.search}` };
}

// The host field of an allowlist entry: "localhost", or "localhost:3000" as a shortcut.
export function parseHostEntry(input) {
  const url = parseUrl(checkRawInput(input));
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new ScopeError('enter a host (and optional port), not a URL with a path');
  }
  return { host: canonicalHost(url.hostname), port: url.port ? Number(url.port) : null };
}

// "3000", "8080, 3000" or "*". Returns a sorted, de-duplicated list, or "*".
// "All ports" must be asked for explicitly; an empty field is an error, not a wildcard.
export function parsePorts(input) {
  const value = String(input ?? '').trim();
  if (value === ALL_PORTS) return ALL_PORTS;
  if (value === '') {
    throw new ScopeError('list the ports in scope (e.g. 3000,8080) or enter * for all ports');
  }
  const ports = value.split(',').map((p) => p.trim());
  for (const p of ports) {
    if (!/^\d{1,5}$/.test(p) || Number(p) < 1 || Number(p) > 65535) {
      throw new ScopeError(`"${p}" is not a valid port`);
    }
  }
  return [...new Set(ports.map(Number))].sort((a, b) => a - b).join(',');
}

// Default deny: allowed only if the exact canonical host is listed and the port is in scope.
export function checkScope(target, entries) {
  const entry = entries.find((e) => e.host === target.host);
  if (!entry) {
    return { allowed: false, reason: `${target.host} is not on the allowlist` };
  }
  if (entry.ports !== ALL_PORTS && !entry.ports.split(',').map(Number).includes(target.port)) {
    return {
      allowed: false,
      reason: `port ${target.port} is not in scope for ${target.host} (allowed: ${entry.ports})`,
    };
  }
  return { allowed: true, reason: `matches allowlist entry #${entry.id}`, entryId: entry.id, ports: entry.ports, entry };
}
