import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildScanArgs, interpretRun, parseFindings } from '../src/tools/nuclei.js';

const TARGET = { url: 'http://127.0.0.1:3000', host: '127.0.0.1', port: 3000 };

const FINDING = JSON.stringify({
  'template-id': 'prometheus-metrics',
  info: { name: 'Prometheus Metrics - Detect', severity: 'medium' },
  'matched-at': 'http://127.0.0.1:3000/metrics',
});
const INFO = JSON.stringify({
  'template-id': 'http-missing-security-headers',
  info: { name: 'HTTP Missing Security Headers', severity: 'info' },
  'matcher-name': 'content-security-policy',
  'matched-at': 'http://127.0.0.1:3000',
});

describe('nuclei: buildScanArgs', () => {
  const args = buildScanArgs('http://127.0.0.1:3000', 'http://127.0.0.1:50000');

  it('passes the URL as its own argument right after -u', () => {
    assert.equal(args[0], '-u');
    assert.equal(args[1], 'http://127.0.0.1:3000');
  });

  it('sends all traffic through the scope proxy', () => {
    assert.equal(args[args.indexOf('-proxy') + 1], 'http://127.0.0.1:50000');
  });

  it('runs HTTP templates only', () => {
    assert.equal(args[args.indexOf('-pt') + 1], 'http');
  });

  for (const flag of ['-jsonl', '-ni', '-dr', '-duc']) {
    it(`includes ${flag}`, () => assert.ok(args.includes(flag)));
  }
});

describe('nuclei: parseFindings', () => {
  it('converts each line into the shared finding shape', () => {
    const [medium, info] = parseFindings(`${FINDING}\n\n${INFO}\n`);
    assert.deepEqual(
      { tool: medium.tool, type: medium.type, severity: medium.severity, ref: medium.ref, location: medium.location },
      { tool: 'nuclei', type: 'template-match', severity: 'medium', ref: 'prometheus-metrics', location: 'http://127.0.0.1:3000/metrics' },
    );
    assert.equal(medium.title, 'Prometheus Metrics - Detect');
    assert.equal(info.detail, 'content-security-policy');
    assert.equal(info.raw['template-id'], 'http-missing-security-headers');
  });
});

describe('nuclei: an empty result is only clean if the scan really ran', () => {
  const ok = { code: 0, stdout: FINDING, stderr: '[INF] Scan completed in 20m', aborted: false };

  it('a normal run is done', () => {
    const r = interpretRun(ok, TARGET);
    assert.equal(r.status, 'done');
    assert.equal(r.findings.length, 1);
  });

  it('0 findings from a crashed target is a failure, not a clean result', () => {
    const stderr = '[INF] Skipped 127.0.0.1:3000 from target list as found unresponsive 30 times\n[INF] Scan completed in 1m. 0 matches found.';
    const r = interpretRun({ code: 0, stdout: '', stderr, aborted: false }, TARGET);
    assert.equal(r.status, 'failed');
    assert.match(r.error, /stopped responding/);
    assert.match(r.log, /unresponsive 30 times/);
  });

  it('keeps the findings collected before the target went down', () => {
    const stderr = '[INF] Skipped 127.0.0.1:3000 from target list as found unresponsive permanently';
    const r = interpretRun({ code: 0, stdout: FINDING, stderr, aborted: false }, TARGET);
    assert.equal(r.status, 'failed');
    assert.equal(r.findings.length, 1);
  });

  it('ignores skips of other ports (blocked by the scope proxy)', () => {
    const stderr = [
      '[INF] Skipped 127.0.0.1:4040 from target list as found unresponsive permanently: cause="port closed or filtered"',
      '[INF] Skipped 127.0.0.1:30000 from target list as found unresponsive permanently',
      '[INF] Scan completed in 12m. 1 matches found.',
    ].join('\n');
    assert.equal(interpretRun({ ...ok, stderr }, TARGET).status, 'done');
  });

  it('a non-zero exit code is a failure', () => {
    assert.equal(interpretRun({ code: 1, stdout: '', stderr: '', aborted: false }, TARGET).status, 'failed');
  });

  it('a cancelled scan is a failure', () => {
    assert.equal(interpretRun({ code: null, stdout: '', stderr: '', aborted: true }, TARGET).status, 'failed');
  });
});
