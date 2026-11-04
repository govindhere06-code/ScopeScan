import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { describe, it } from 'node:test';
import { openDb } from '../src/db.js';
import { recoverScans } from '../src/jobs.js';
import { trackProcess } from '../src/processes.js';
import { createScan, getScan, markScanRunning, markToolRunning } from '../src/scans.js';

const target = { url: 'http://127.0.0.1:3000', host: '127.0.0.1', port: 3000 };

// A process that would run for a minute, standing in for a scanner left behind by a crash.
function longProcess() {
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60_000)'], { windowsHide: true });
  const exited = new Promise((resolve) => child.once('exit', resolve));
  return new Promise((resolve) => child.once('spawn', () => resolve({ child, exited })));
}

describe('server start after a crash', () => {
  it('marks scans that were running or waiting as failed', async () => {
    const db = openDb(':memory:');
    const running = createScan(db, { target, tools: ['nmap', 'ffuf'] });
    markScanRunning(db, running, { id: 1, host: '127.0.0.1', ports: '3000' });
    markToolRunning(db, running, 'nmap');
    const waiting = createScan(db, { target, tools: ['nuclei'] });

    const { stale } = await recoverScans(db);
    assert.equal(stale.length, 2);

    const a = getScan(db, running);
    assert.equal(a.status, 'failed');
    assert.equal(a.error, 'the server stopped while this scan was running');
    assert.deepEqual(a.results.map((r) => r.status), ['failed', 'skipped']);
    const b = getScan(db, waiting);
    assert.equal(b.status, 'failed');
    assert.equal(b.error, 'the server stopped before this scan started');
  });

  it('kills a scanner process the last run left behind', async () => {
    const db = openDb(':memory:');
    const { child, exited } = await longProcess();
    trackProcess(db, 1, { pid: child.pid, bin: process.execPath });

    const { killed } = await recoverScans(db);
    assert.deepEqual(killed.map((p) => p.pid), [child.pid]);
    await exited;
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_processes').get().n, 0);
  });

  it('leaves a process alone if its PID now belongs to a different program', async () => {
    const db = openDb(':memory:');
    // This test's own PID, recorded as if it had been nuclei.
    trackProcess(db, 1, { pid: process.pid, bin: 'C:\\tools\\nuclei.exe' });
    const { killed } = await recoverScans(db);
    assert.deepEqual(killed, []);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_processes').get().n, 0);
  });

  it('ignores a PID that no longer exists', async () => {
    const db = openDb(':memory:');
    const { child, exited } = await longProcess();
    child.kill();
    await exited;
    trackProcess(db, 1, { pid: child.pid, bin: process.execPath });
    assert.deepEqual((await recoverScans(db)).killed, []);
  });
});
