import { useCallback, useEffect, useState } from 'react';
import { api } from './api.js';

const LOOPBACK = '127.0.0.1';
const displayHost = (host) => (host === LOOPBACK ? `${host} (localhost)` : host);
const displayPorts = (ports) => (ports === '*' ? 'all ports' : ports.replaceAll(',', ', '));

export default function App() {
  const [targets, setTargets] = useState([]);
  const [audit, setAudit] = useState([]);
  const [loadError, setLoadError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [t, a] = await Promise.all([api.listTargets(), api.listAudit()]);
      setTargets(t);
      setAudit(a);
      setLoadError(null);
    } catch (err) {
      setLoadError(`Can't reach the ScopeScan API — is the server running? (${err.message})`);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

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
        <ScanPanel targets={targets} onFinished={refresh} />
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

function formatDuration(ms) {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

function bySeverityThenTool(a, b) {
  return (
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    TOOLS.findIndex((t) => t.id === a.tool) - TOOLS.findIndex((t) => t.id === b.tool)
  );
}

function ScanPanel({ targets, onFinished }) {
  const [target, setTarget] = useState('');
  const [tools, setTools] = useState(['nmap', 'ffuf']);
  const [running, setRunning] = useState(false);
  const [startedAt, setStartedAt] = useState(null);
  const [now, setNow] = useState(Date.now());
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [toolFilter, setToolFilter] = useState('all');

  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [running]);

  function toggleTool(id) {
    setTools((current) => (current.includes(id) ? current.filter((t) => t !== id) : [...current, id]));
  }

  async function submit(e) {
    e.preventDefault();
    setRunning(true);
    setStartedAt(Date.now());
    setNow(Date.now());
    setResult(null);
    setError(null);
    setSelected(null);
    setToolFilter('all');
    onFinished();
    try {
      setResult(await api.runScan(target, tools));
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
      onFinished();
    }
  }

  const allFindings = result ? result.results.flatMap((r) => r.findings).sort(bySeverityThenTool) : [];
  const findings = toolFilter === 'all' ? allFindings : allFindings.filter((f) => f.tool === toolFilter);

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
            disabled={running}
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
        <fieldset className="tools" disabled={running}>
          <legend>Tools</legend>
          {TOOLS.map((t) => (
            <label key={t.id} className="check" title={t.hint}>
              <input type="checkbox" checked={tools.includes(t.id)} onChange={() => toggleTool(t.id)} />
              {t.label}
            </label>
          ))}
        </fieldset>
        <button type="submit" disabled={running || tools.length === 0}>
          {running ? 'Scanning…' : 'Run scan'}
        </button>
      </form>

      {running && (
        <p className="banner">
          Scanning for {formatDuration(now - startedAt)}. Tools run one at a time: nmap takes seconds, ffuf about 3
          minutes, Nuclei about 15. Keep this tab open: closing it cancels the scan.
        </p>
      )}
      {error && <p className="banner error">{error}</p>}

      {result && (
        <>
          <p className="meta">
            <span className="mono">{result.target.url}</span> · ports in scope:{' '}
            <span className="mono">{result.ports === '*' ? 'all' : result.ports}</span>
          </p>
          <div className="tool-results">
            {result.results.map((r) => (
              <ToolResult key={r.tool} result={r} />
            ))}
          </div>

          {allFindings.length > 0 && (
            <>
              <div className="row filter">
                <span className="meta">Show:</span>
                {['all', ...result.results.map((r) => r.tool)].map((t) => (
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
                    {findings.map((f, i) => (
                      <tr
                        key={i}
                        className={`clickable ${selected === i ? 'selected' : ''}`}
                        onClick={() => setSelected(selected === i ? null : i)}
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
              {selected !== null && findings[selected] && (
                <>
                  <p className="meta">
                    Raw {findings[selected].tool} output for {findings[selected].title} (click the row again to close):
                  </p>
                  <pre className="raw">{JSON.stringify(findings[selected].raw, null, 2)}</pre>
                </>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}

function ToolResult({ result }) {
  const ok = result.status === 'done';
  const counts = SEVERITY_ORDER.map((s) => [s, result.findings.filter((f) => f.severity === s).length]).filter(
    ([, n]) => n,
  );
  return (
    <div className={`tool-result ${ok ? 'ok' : 'error'}`}>
      <p className="tool-head">
        <strong>{result.tool}</strong> <span className={`pill ${result.status}`}>{result.status}</span>{' '}
        <span className="meta">
          {result.findings.length} findings
          {counts.length > 0 && <> ({counts.map(([s, n]) => `${n} ${s}`).join(', ')})</>} ·{' '}
          {formatDuration(result.durationMs)}
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
