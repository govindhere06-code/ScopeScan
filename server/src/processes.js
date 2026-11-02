import { execFile } from 'node:child_process';
import path from 'node:path';

// Records which scanner processes are running, so that after a crash the next server start
// can find and kill any it left behind.

export function programName(file) {
  return path.basename(file).replace(/\.exe$/i, '').toLowerCase();
}

// Returns the function that forgets the process again, for run()'s onSpawn hook.
export function trackProcess(db, scanId, { pid, bin }) {
  db.prepare('INSERT OR REPLACE INTO scan_processes (pid, scan_id, name, started_at) VALUES (?, ?, ?, ?)').run(
    pid,
    scanId,
    programName(bin),
    new Date().toISOString(),
  );
  return () => db.prepare('DELETE FROM scan_processes WHERE pid = ?').run(pid);
}

// What program a PID belongs to right now, or null if no process has that PID.
function runningProgram(pid) {
  const [cmd, args] =
    process.platform === 'win32'
      ? ['tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH']]
      : ['ps', ['-p', String(pid), '-o', 'comm=']];
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true }, (err, stdout) => {
      if (process.platform !== 'win32') return resolve(err ? null : stdout.trim() || null);
      // "nuclei.exe","1234",... — or an INFO line when nothing matches.
      const [name, rowPid] = stdout.trim().split('","').map((s) => s.replace(/"/g, ''));
      resolve(!err && Number(rowPid) === pid ? name : null);
    });
  });
}

// Kills the processes a previous server run left behind. A PID is only killed if it still
// belongs to the same program: after a reboot the number may belong to something else.
export async function killOrphans(db) {
  const rows = db.prepare('SELECT pid, scan_id, name FROM scan_processes').all();
  const killed = [];
  for (const row of rows) {
    const program = await runningProgram(row.pid);
    if (program && programName(program) === row.name) {
      try {
        process.kill(row.pid);
        killed.push(row);
      } catch {
        // Already gone.
      }
    }
  }
  db.prepare('DELETE FROM scan_processes').run();
  return killed;
}
