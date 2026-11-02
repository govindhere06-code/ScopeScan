import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { programName } from '../src/processes.js';
import { run } from '../src/tools/run.js';

const node = process.execPath;

describe('run()', () => {
  it('collects output and the exit code', async () => {
    const result = await run(node, ['-e', 'console.log("out"); console.error("err"); process.exit(3)']);
    assert.deepEqual(result, { code: 3, stdout: 'out\n', stderr: 'err\n', aborted: false });
  });

  it('kills the process when the signal is aborted', async () => {
    const controller = new AbortController();
    const started = Date.now();
    const pending = run(node, ['-e', 'setTimeout(() => {}, 60_000)'], {
      signal: controller.signal,
      onSpawn: () => setTimeout(() => controller.abort('timeout'), 50),
    });
    const result = await pending;
    assert.equal(result.aborted, true);
    assert.ok(Date.now() - started < 10_000);
  });

  it('starts nothing when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort('cancelled');
    let spawned = false;
    const result = await run(node, ['-e', ''], { signal: controller.signal, onSpawn: () => (spawned = true) });
    assert.equal(result.aborted, true);
    assert.equal(spawned, false);
  });

  it('reports the process to onSpawn and calls back when it exits', async () => {
    const seen = [];
    await run(node, ['-e', ''], {
      onSpawn: ({ pid, bin }) => {
        seen.push(['spawn', typeof pid, bin]);
        return () => seen.push(['exit']);
      },
    });
    assert.deepEqual(seen, [['spawn', 'number', node], ['exit']]);
  });
});

describe('programName()', () => {
  it('compares executables by name alone', () => {
    assert.equal(programName('C:\\tools\\nuclei.exe'), 'nuclei');
    assert.equal(programName('NMAP.EXE'), 'nmap');
    assert.equal(programName('/usr/bin/ffuf'), 'ffuf');
  });
});
