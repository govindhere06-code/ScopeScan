import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildScanArgs, fuzzUrl, interpretRun, parseFindings } from '../src/tools/ffuf.js';

// Real `ffuf -json` lines from the lab. Note FUZZ is base64 ("ZnRw" = "ftp"), so ScopeScan reads `url`.
const FTP = JSON.stringify({
  input: { FFUFHASH: 'NWY3NzYx', FUZZ: 'ZnRw' },
  status: 200,
  length: 11317,
  'content-type': 'text/html; charset=utf-8',
  redirectlocation: '',
  url: 'http://127.0.0.1:3000/ftp',
});
const ASSETS = JSON.stringify({
  input: { FUZZ: 'YXNzZXRz' },
  status: 301,
  length: 156,
  'content-type': 'text/html; charset=UTF-8',
  redirectlocation: '/assets/',
  url: 'http://127.0.0.1:3000/assets',
});

describe('ffuf: buildScanArgs', () => {
  const args = buildScanArgs('http://127.0.0.1:3000', 'C:\\tools\\wordlists\\common.txt', 'http://127.0.0.1:50000');

  it('fuzzes one level below the target', () => {
    assert.equal(args[args.indexOf('-u') + 1], 'http://127.0.0.1:3000/FUZZ');
  });

  it('sends all traffic through the scope proxy', () => {
    assert.equal(args[args.indexOf('-x') + 1], 'http://127.0.0.1:50000');
  });

  it('auto-calibrates so soft 404s are filtered', () => assert.ok(args.includes('-ac')));

  it('never follows redirects', () => assert.ok(!args.includes('-r')));
});

describe('ffuf: fuzzUrl', () => {
  it('root', () => assert.equal(fuzzUrl('http://127.0.0.1:3000'), 'http://127.0.0.1:3000/FUZZ'));
  it('a sub-path, without a doubled slash', () => assert.equal(fuzzUrl('http://127.0.0.1:3000/api/'), 'http://127.0.0.1:3000/api/FUZZ'));
  it('drops a query string', () => assert.equal(fuzzUrl('http://127.0.0.1:3000/app?x=1'), 'http://127.0.0.1:3000/app/FUZZ'));
});

describe('ffuf: parseFindings', () => {
  it('converts each line into the shared finding shape', () => {
    const [ftp, assets] = parseFindings(`${FTP}\n${ASSETS}\n`);
    assert.equal(ftp.tool, 'ffuf');
    assert.equal(ftp.title, '200 /ftp');
    assert.equal(ftp.location, 'http://127.0.0.1:3000/ftp');
    assert.match(ftp.detail, /11317 bytes/);
    assert.match(assets.detail, /→ \/assets\//);
  });
});

describe('ffuf: interpretRun (ffuf exits 0 even against a dead target)', () => {
  const ok = { code: 0, stdout: FTP, stderr: '', aborted: false };

  it('a healthy run is done', () => {
    assert.equal(interpretRun(ok, { allowedRequests: 4760, upstreamErrors: 0 }).status, 'done');
  });

  it('a few failed requests are tolerated', () => {
    assert.equal(interpretRun(ok, { allowedRequests: 4760, upstreamErrors: 12 }).status, 'done');
  });

  it('a dead target is a failure, even though ffuf exited 0', () => {
    const r = interpretRun({ ...ok, stdout: '' }, { allowedRequests: 4760, upstreamErrors: 4760 });
    assert.equal(r.status, 'failed');
    assert.match(r.error, /4760 of 4760 requests to the target failed/);
  });

  it('no requests at all is a failure', () => {
    assert.equal(interpretRun({ ...ok, stdout: '' }, { allowedRequests: 0, upstreamErrors: 0 }).status, 'failed');
  });
});
