import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildScanArgs, interpretRun, parseFindings, parsePorts } from '../src/tools/nmap.js';

// Trimmed from a real `nmap -sT -sV -Pn -p 3000,8080 127.0.0.1 -oX -` run against the lab.
const XML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -n -p 3000,8080 -oX - 127.0.0.1" version="7.992">
<host><status state="up" reason="user-set"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="3000"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ppp" servicefp="SF-Port3000-TCP:V=7.992%r(GetRequest,28B7,&quot;HTTP/1\\.1\\x20200&quot;)" method="table" conf="3"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Apache httpd" version="2.4.25" extrainfo="(Debian)" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.25</cpe></service></port>
<port protocol="tcp" portid="9999"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="abyss" method="table" conf="3"/></port>
</ports>
</host>
<runstats><finished time="1793545748" elapsed="11.45" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`;

describe('nmap: buildScanArgs', () => {
  it('scans only the allowlist entry\'s ports, with the host last', () => {
    const args = buildScanArgs('127.0.0.1', '3000,8080');
    assert.equal(args[args.indexOf('-p') + 1], '3000,8080');
    assert.equal(args.at(-1), '127.0.0.1');
    assert.ok(!args.includes('--top-ports'));
  });

  it('never looks up DNS and never pings', () => {
    const args = buildScanArgs('127.0.0.1', '3000');
    for (const flag of ['-n', '-Pn', '-sT', '-sV']) assert.ok(args.includes(flag), flag);
  });

  it('an entry granting all ports scans the top 1000, not 65535', () => {
    const args = buildScanArgs('example.test', '*');
    assert.equal(args[args.indexOf('--top-ports') + 1], '1000');
    assert.ok(!args.includes('-p'));
  });

  it('IPv6 hosts get -6 and no brackets', () => {
    const args = buildScanArgs('[2001:db8::1]', '443');
    assert.ok(args.includes('-6'));
    assert.equal(args.at(-1), '2001:db8::1');
  });
});

describe('nmap: parsing the XML report', () => {
  it('reads every port with its state, service and confidence', () => {
    const ports = parsePorts(XML);
    assert.equal(ports.length, 3);
    assert.deepEqual(
      { port: ports[1].port, product: ports[1].product, version: ports[1].version, method: ports[1].method, confidence: ports[1].confidence },
      { port: 8080, product: 'Apache httpd', version: '2.4.25', method: 'probed', confidence: 10 },
    );
    assert.deepEqual(ports[1].cpe, ['cpe:/a:apache:http_server:2.4.25']);
    assert.equal(ports[2].state, 'closed');
  });

  it('reports open ports only', () => {
    const findings = parseFindings(XML, '127.0.0.1');
    assert.deepEqual(findings.map((f) => f.location), ['127.0.0.1:3000', '127.0.0.1:8080']);
  });

  it('marks a service guessed from the port number as a guess', () => {
    const [guess, probed] = parseFindings(XML, '127.0.0.1');
    assert.equal(guess.title, '3000/tcp open: ppp?');
    assert.match(guess.detail, /guessed from the port number, confidence 3\/10/);
    assert.equal(probed.title, '8080/tcp open: Apache httpd 2.4.25 (Debian)');
    assert.match(probed.detail, /identified by probing, confidence 10\/10/);
  });
});

describe('nmap: interpretRun', () => {
  const ok = { code: 0, stdout: XML, stderr: '', aborted: false };

  it('a finished run is done', () => assert.equal(interpretRun(ok, '127.0.0.1').status, 'done'));

  it('a report without a successful finish is a failure', () => {
    const cut = XML.replace(/<runstats>[\s\S]*<\/runstats>/, '');
    assert.equal(interpretRun({ ...ok, stdout: cut }, '127.0.0.1').status, 'failed');
  });

  it('a non-zero exit code is a failure', () => {
    assert.equal(interpretRun({ ...ok, code: 1 }, '127.0.0.1').status, 'failed');
  });
});
