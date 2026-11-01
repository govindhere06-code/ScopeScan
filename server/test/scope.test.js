import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ScopeError, checkScope, parseHostEntry, parsePorts, parseTarget } from '../src/scope.js';

describe('parseTarget: different spellings of the same target are the same', () => {
  const cases = [
    ['localhost:3000', '127.0.0.1', 3000],
    ['http://localhost:3000', '127.0.0.1', 3000],
    ['HTTP://LOCALHOST:3000/', '127.0.0.1', 3000],
    ['  localhost:3000  ', '127.0.0.1', 3000],
    ['localhost.:3000', '127.0.0.1', 3000],
    ['http://127.0.0.1:3000/login?next=/', '127.0.0.1', 3000],
    ['http://[::1]:3000', '127.0.0.1', 3000],
    ['http://127.1:3000', '127.0.0.1', 3000],
    ['http://2130706433:3000', '127.0.0.1', 3000],
    ['http://0x7f.0.0.1:3000', '127.0.0.1', 3000],
    ['http://local%68ost:3000', '127.0.0.1', 3000],
    ['localhost', '127.0.0.1', 80],
    ['https://localhost', '127.0.0.1', 443],
    ['Example.TEST.:8443', 'example.test', 8443],
  ];
  for (const [input, host, port] of cases) {
    it(JSON.stringify(input), () => {
      const t = parseTarget(input);
      assert.equal(t.host, host);
      assert.equal(t.port, port);
    });
  }
});

describe('parseTarget: canonical URL', () => {
  const cases = [
    ['localhost:3000', 'http://127.0.0.1:3000'],
    ['http://localhost:3000/', 'http://127.0.0.1:3000'],
    ['http://localhost:3000/login?next=/', 'http://127.0.0.1:3000/login?next=/'],
  ];
  for (const [input, url] of cases) {
    it(`${input} -> ${url}`, () => assert.equal(parseTarget(input).url, url));
  }
});

describe('parseTarget: rejects bad or dangerous input', () => {
  const cases = [
    '',
    '   ',
    '-iL',
    '-iL targets.txt',
    '--script=evil',
    'local host:3000',
    'localhost:3000\nevil.test',
    'localhost\t:3000',
    'http://user:pass@localhost:3000',
    'http://admin@localhost:3000',
    'ftp://localhost',
    'file:///etc/passwd',
    'javascript:alert(1)',
    'localhost:99999',
    'localhost:abc',
    'http://exa_mple.test',
    'x'.repeat(3000),
    42,
    null,
    undefined,
  ];
  for (const input of cases) {
    it(JSON.stringify(input)?.slice(0, 40) ?? String(input), () => {
      assert.throws(() => parseTarget(input), ScopeError);
    });
  }
});

describe('checkScope: default deny', () => {
  const entries = [
    { id: 1, host: '127.0.0.1', ports: '3000,8080' },
    { id: 2, host: 'example.test', ports: '*' },
  ];
  const cases = [
    ['localhost:3000', true],
    ['127.0.0.1:8080', true],
    ['[::1]:3000', true],
    ['localhost:22', false],
    ['localhost', false], // port 80 isn't listed
    ['127.0.0.2:3000', false], // a different loopback address is a different host
    ['example.test:12345', true], // "*" was explicitly granted
    ['evil.test:3000', false],
    ['localhost.evil.test:3000', false], // listed name as a prefix
    ['example.test.evil.test', false], // listed name as a subdomain of another host
    ['sub.example.test', false], // subdomains aren't covered by their parent
  ];
  for (const [input, allowed] of cases) {
    it(`${input} -> ${allowed ? 'allowed' : 'denied'}`, () => {
      assert.equal(checkScope(parseTarget(input), entries).allowed, allowed);
    });
  }

  it('an empty allowlist denies everything', () => {
    assert.equal(checkScope(parseTarget('localhost:3000'), []).allowed, false);
  });
});

describe('parsePorts', () => {
  it('normalizes a list', () => assert.equal(parsePorts('8080, 3000,3000'), '3000,8080'));
  it('accepts an explicit *', () => assert.equal(parsePorts('*'), '*'));
  for (const bad of ['', '  ', '0', '65536', 'abc', '3000-3010', '3000,', '-1', '80 443']) {
    it(`rejects ${JSON.stringify(bad)}`, () => assert.throws(() => parsePorts(bad), ScopeError));
  }
});

describe('parseHostEntry', () => {
  it('host only', () => assert.deepEqual(parseHostEntry('localhost'), { host: '127.0.0.1', port: null }));
  it('host with port', () => assert.deepEqual(parseHostEntry('localhost:3000'), { host: '127.0.0.1', port: 3000 }));
  it('rejects a path', () => assert.throws(() => parseHostEntry('http://localhost:3000/admin'), ScopeError));
  it('rejects a flag', () => assert.throws(() => parseHostEntry('-oN'), ScopeError));
});
