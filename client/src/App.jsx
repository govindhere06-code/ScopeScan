import { useCallback, useEffect, useState } from 'react';
import { api } from './api.js';

const LOOPBACK = '127.0.0.1';
const displayHost = (host) => (host === LOOPBACK ? `${host} (localhost)` : host);
const displayPorts = (ports) => (ports === '*' ? 'all ports' : ports.replaceAll(',', ', '));

// How often the page asks for progress while a scan is queued or running.
const POLL_MS = 2000;

export default function App() {
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [audit, setAudit] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loadError, setLoadError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [t, s, a] = await Promise.all([api.listTargets(), api.listScans(), api.listAudit()]);
      setTargets(t);
      setScans(s);
      setAudit(a);
      setLoadError(null);
    } catch (err) {
      setLoadError(`Can't reach the ScopeScan API — is the server running? (${err.message})`);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const anyActive = scans.some((s) => isActive(s.status));
  useEffect(() => {
    if (!anyActive) return undefined;
    const timer = setInterval(refresh, POLL_MS);
    return () => clearInterval(timer);
  }, [anyActive, refresh]);

  const selected = scans.find((s) => s.id === selectedScan);

  return (
    <main>
      <header>
        <h1>ScopeScan</h1>
        <p className="lede">
          Only targets on this allowlist can ever be scanned. Everything else is refused and logged.
        </p>
      </header>

      {loadError && <p className="banner error">{loadError}</p>}

      <section>
        <h2>Scope allowlist</h2>
        <AddTargetForm onAdded={refresh} />
        <TargetTable targets={targets} onRemoved={refresh} />
      </section>

      <section>
        <h2>Check a target</h2>
        <ScopeChecker onChecked={refresh} />
      </section>

      <section>
        <h2>Scan</h2>
        <ScanForm
          targets={targets}
          onStarted={(scan) => {
            if (scan) setSelectedScan(scan.id);
            refresh();
          }}
        />
      </section>

      <section>
        <h2>Scan history</h2>
        <ScanHistory scans={scans} selectedId={selectedScan} onSelect={setSelectedScan} />
        {selected && <ScanDetail summary={selected} onChanged={refresh} />}
      </section>

      <section>
        <h2>Audit log</h2>
        <AuditLog events={audit} />
      </section>
    </main>
  );
}

function AddTargetForm({ onAdded }) {
  const [host, setHost] = useState('');
  const [ports, setPorts] = useState('');
  const [note, setNote] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    if (ports.trim() === '*' && !window.confirm(`Allow scanning ALL ports on ${host}?`)) return;
    setBusy(true);
    setError(null);
    try {
      await api.addTarget({ host, ports, note });
      setHost('');
      setPorts('');
      setNote('');
      onAdded();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="row" onSubmit={submit}>
      <label>
        Host
        <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="localhost or localhost:3000" required />
      </label>
      <label>
        Ports
        <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="3000,8080 or *" />
      </label>
      <label className="grow">
        Note
        <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Juice Shop (my lab)" />
      </label>
      <button type="submit" disabled={busy}>Add to allowlist</button>
      {error && <p className="form-error">{error}</p>}
    </form>
  );
}

function TargetTable({ targets, onRemoved }) {
  const [error, setError] = useState(null);

  async function remove(target) {
    if (!window.confirm(`Remove ${target.host} from the allowlist?`)) return;
    try {
      await api.removeTarget(target.id);
      setError(null);
      onRemoved();
    } catch (err) {
      setError(err.message);
    }
  }

  if (targets.length === 0) {
    return <p className="empty">The allowlist is empty, so every scan will be refused.</p>;
  }

  return (
    <>
      {error && <p className="form-error">{error}</p>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Ports in scope</th>
              <th>Note</th>
              <th>Added</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id}>
                <td className="mono">{displayHost(t.host)}</td>
                <td className="mono">{displayPorts(t.ports)}</td>
                <td>{t.note}</td>
                <td>{new Date(t.createdAt).toLocaleString()}</td>
                <td>
                  <button className="link danger" onClick={() => remove(t)}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function ScopeChecker({ onChecked }) {
  const [target, setTarget] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    try {
      setResult(await api.checkScope(target));
      onChecked();
    } catch (err) {
      setResult(null);
      setError(err.message);
    }
  }

  return (
    <>
      <form className="row" onSubmit={submit}>
        <label className="grow">
          Target
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="http://localhost:3000" required />
        </label>
        <button type="submit">Check</button>
      </form>
      {error && <p className="form-error">{error}</p>}
      {result && (
        <p className={`banner ${result.allowed ? 'ok' : 'error'}`}>
          <strong>{result.allowed ? 'Allowed' : 'Refused'}</strong> — {result.reason}
          {result.target && <span className="mono"> ({result.target.url})</span>}
        </p>
      )}
    </>
  );
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const TOOLS = [
  { id: 'nmap', label: 'nmap', hint: 'open ports and services (seconds)' },
  { id: 'ffuf', label: 'ffuf', hint: 'hidden paths (about 3 minutes)' },
  { id: 'nuclei', label: 'Nuclei', hint: 'known issues (about 15 minutes)' },
];
const ACTIVE = ['queued', 'running'];
const isActive = (status) => ACTIVE.includes(status);

function formatDuration(ms) {
  if (ms == null || Number.isNaN(ms)) return '—';
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

function elapsed(startedAt, finishedAt, now) {
  if (!startedAt) return null;
  return (finishedAt ? Date.parse(finishedAt) : now) - Date.parse(startedAt);
}

function bySeverityThenTool(a, b) {
  return (
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    TOOLS.findIndex((t) => t.id === a.tool) - TOOLS.findIndex((t) => t.id === b.tool)
  );
}

// Re-renders every second while `ticking`, for live "running for …" times.
function useNow(ticking) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!ticking) return undefined;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [ticking]);
  return now;
}

function StatusPill({ status }) {
  return <span className={`pill ${status}`}>{status.replace('_', ' ')}</span>;
}

function ScanForm({ targets, onStarted }) {
  const [target, setTarget] = useState('');
  const [tools, setTools] = useState(['nmap', 'ffuf']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  function toggleTool(id) {
    setTools((current) => (current.includes(id) ? current.filter((t) => t !== id) : [...current, id]));
  }

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onStarted(await api.startScan(target, tools));
    } catch (err) {
      setError(err.message);
      onStarted(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <form className="row" onSubmit={submit}>
        <label className="grow">
          Target
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="http://localhost:3000"
            list="allowlisted-targets"
            required
          />
          <datalist id="allowlisted-targets">
            {targets
              .filter((t) => t.ports !== '*')
              .flatMap((t) => t.ports.split(',').map((p) => `http://${t.host}:${p}`))
              .map((url) => (
                <option key={url} value={url} />
              ))}
          </datalist>
        </label>
        <fieldset className="tools">
          <legend>Tools</legend>
          {TOOLS.map((t) => (
            <label key={t.id} className="check" title={t.hint}>
              <input type="checkbox" checked={tools.includes(t.id)} onChange={() => toggleTool(t.id)} />
              {t.label}
            </label>
          ))}
        </fieldset>
        <button type="submit" disabled={busy || tools.length === 0}>
          Start scan
        </button>
        {error && <p className="form-error">{error}</p>}
      </form>
      <p className="meta">
        Scans run on the server in the background, one at a time, and are saved to the history below. You can close
        this page and come back. The tools in a scan run in order: nmap takes seconds, ffuf about 3 minutes, Nuclei
        about 15.
      </p>
    </>
  );
}

function ScanHistory({ scans, selectedId, onSelect }) {
  const now = useNow(scans.some((s) => s.status === 'running'));
  if (scans.length === 0) return <p className="empty">No scans yet.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Target</th>
            <th>Tools</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Requested</th>
            <th>Took</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => {
            const notable = SEVERITY_ORDER.slice(0, 4)
              .filter((sev) => s.severityCounts[sev])
              .map((sev) => `${s.severityCounts[sev]} ${sev}`);
            return (
              <tr
                key={s.id}
                className={`clickable ${selectedId === s.id ? 'selected' : ''}`}
                onClick={() => onSelect(selectedId === s.id ? null : s.id)}
              >
                <td>{s.id}</td>
                <td className="mono">{s.target}</td>
                <td>{s.tools.map((t) => t.tool).join(', ')}</td>
                <td>
                  <StatusPill status={s.status} />
                </td>
                <td>
                  {s.findingCount}
                  {notable.length > 0 && <span className="meta"> ({notable.join(', ')})</span>}
                </td>
                <td>{new Date(s.createdAt).toLocaleString()}</td>
                <td>{s.status === 'queued' ? 'waiting' : formatDuration(elapsed(s.startedAt, s.finishedAt, now))}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// `summary` is the scan's row from the history list. The list is polled while scans run, and
// the full scan is fetched again whenever its row shows progress.
function ScanDetail({ summary, onChanged }) {
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const active = isActive(summary.status);
  const now = useNow(active);
  const progress = [summary.id, summary.status, summary.findingCount, ...summary.tools.map((t) => t.status)].join();

  useEffect(() => {
    let current = true;
    api
      .getScan(summary.id)
      .then((s) => {
        if (!current) return;
        setScan(s);
        setError(null);
      })
      .catch((err) => current && setError(err.message));
    return () => {
      current = false;
    };
  }, [progress]); // eslint-disable-line react-hooks/exhaustive-deps

  async function cancel() {
    if (!window.confirm(`Cancel scan #${summary.id}? A running tool is killed; what it found so far is kept.`)) return;
    try {
      await api.cancelScan(summary.id);
      onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  if (error) return <p className="banner error">{error}</p>;
  if (!scan || scan.id !== summary.id) return <p className="empty">Loading scan #{summary.id}…</p>;

  const took = elapsed(scan.startedAt, scan.finishedAt, now);
  const stopped = scan.status === 'timed_out' || scan.status === 'cancelled';
  return (
    <div className="scan-detail">
      <div className="row scan-head">
        <h3>Scan #{scan.id}</h3>
        <StatusPill status={scan.status} />
        <span className="meta">
          <span className="mono">{scan.target}</span>
          {scan.ports && (
            <>
              {' '}
              · ports in scope: <span className="mono">{scan.ports === '*' ? 'all' : scan.ports}</span>
            </>
          )}
          {took !== null && (
            <>
              {' '}
              · {scan.finishedAt ? 'took' : 'running for'} {formatDuration(took)}
            </>
          )}
        </span>
        {active && (
          <button type="button" className="link danger" onClick={cancel}>
            Cancel scan
          </button>
        )}
      </div>
      {scan.status === 'queued' && <p className="banner">Waiting for the scan before it to finish.</p>}
      {scan.error && <p className={`banner ${stopped ? 'warn' : 'error'}`}>{scan.error}</p>}
      <div className="tool-results">
        {scan.results.map((r) => (
          <ToolResult key={r.tool} result={r} now={now} />
        ))}
      </div>
      <FindingsTable key={scan.id} results={scan.results} />
    </div>
  );
}

function FindingsTable({ results }) {
  const [selected, setSelected] = useState(null);
  const [toolFilter, setToolFilter] = useState('all');

  const allFindings = results.flatMap((r) => r.findings).sort(bySeverityThenTool);
  if (allFindings.length === 0) return null;
  const findings = toolFilter === 'all' ? allFindings : allFindings.filter((f) => f.tool === toolFilter);
  const open = findings.find((f) => f.id === selected);

  return (
    <>
      <div className="row filter">
        <span className="meta">Show:</span>
        {['all', ...results.filter((r) => r.findings.length).map((r) => r.tool)].map((t) => (
          <button
            key={t}
            type="button"
            className={`chip ${toolFilter === t ? 'active' : ''}`}
            onClick={() => {
              setToolFilter(t);
              setSelected(null);
            }}
          >
            {t === 'all' ? `all (${allFindings.length})` : `${t} (${allFindings.filter((f) => f.tool === t).length})`}
          </button>
        ))}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Tool</th>
              <th>Finding</th>
              <th>Location</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr
                key={f.id}
                className={`clickable ${selected === f.id ? 'selected' : ''}`}
                onClick={() => setSelected(selected === f.id ? null : f.id)}
              >
                <td>
                  <span className={`pill sev-${f.severity}`}>{f.severity}</span>
                </td>
                <td className="mono">{f.tool}</td>
                <td>{f.title}</td>
                <td className="mono">{f.location}</td>
                <td className="detail">{f.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {open && (
        <>
          <p className="meta">
            Raw {open.tool} output for {open.title} (click the row again to close):
          </p>
          <pre className="raw">{JSON.stringify(open.raw, null, 2)}</pre>
        </>
      )}
    </>
  );
}

function ToolResult({ result, now }) {
  if (result.status === 'queued' || result.status === 'skipped' || result.status === 'running') {
    const note = {
      queued: 'waits for the tools before it',
      skipped: 'did not run',
      running: `running for ${formatDuration(elapsed(result.startedAt, null, now))}`,
    }[result.status];
    return (
      <div className={`tool-result ${result.status === 'running' ? 'running' : 'pending'}`}>
        <p className="tool-head">
          <strong>{result.tool}</strong> <StatusPill status={result.status} /> <span className="meta">{note}</span>
        </p>
      </div>
    );
  }

  const tone = { done: 'ok', failed: 'error' }[result.status] ?? 'stopped';
  const counts = SEVERITY_ORDER.map((s) => [s, result.findings.filter((f) => f.severity === s).length]).filter(
    ([, n]) => n,
  );
  return (
    <div className={`tool-result ${tone}`}>
      <p className="tool-head">
        <strong>{result.tool}</strong> <StatusPill status={result.status} />{' '}
        <span className="meta">
          {result.findings.length} findings
          {counts.length > 0 && <> ({counts.map(([s, n]) => `${n} ${s}`).join(', ')})</>} ·{' '}
          {formatDuration(result.durationMs ?? elapsed(result.startedAt, result.finishedAt, now))}
          {result.version && <> · {result.version}</>}
        </span>
      </p>
      {result.error && <p className="form-error">{result.error}</p>}
      {result.scope && (
        <details className="log">
          <summary>
            Scope proxy: {result.scope.allowedRequests} requests allowed, {result.scope.blockedRequests} off-scope
            requests blocked
          </summary>
          {result.scope.blocked.length > 0 ? (
            <pre className="raw">{result.scope.blocked.map((b) => `${b.address}  ×${b.count}`).join('\n')}</pre>
          ) : (
            <p className="empty">Nothing tried to leave the allowed host and port.</p>
          )}
          {result.scope.targetTimeouts > 0 && (
            <>
              <p className="meta">
                {result.scope.targetTimeouts} requests went unanswered for 30 seconds and were cut off:
              </p>
              <pre className="raw">{result.scope.timedOut.map((t) => `${t.request}  ×${t.count}`).join('\n')}</pre>
            </>
          )}
        </details>
      )}
      {result.log && (
        <details className="log">
          <summary>{result.tool} log</summary>
          <pre className="raw">{result.log}</pre>
        </details>
      )}
    </div>
  );
}

function AuditLog({ events }) {
  if (events.length === 0) return <p className="empty">Nothing logged yet.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Input</th>
            <th>Decision</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td>{new Date(e.ts).toLocaleString()}</td>
              <td className="mono">{e.action}</td>
              <td className="mono">{e.input ?? e.host}</td>
              <td>
                <span className={`pill ${e.decision}`}>{e.decision}</span>
              </td>
              <td>{e.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
