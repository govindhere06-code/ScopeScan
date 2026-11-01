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
        <h2>Nuclei scan</h2>
        <NucleiScan targets={targets} onFinished={refresh} />
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
const bySeverity = (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

function formatDuration(ms) {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

function NucleiScan({ targets, onFinished }) {
  const [target, setTarget] = useState('');
  const [running, setRunning] = useState(false);
  const [startedAt, setStartedAt] = useState(null);
  const [now, setNow] = useState(Date.now());
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [running]);

  async function submit(e) {
    e.preventDefault();
    setRunning(true);
    setStartedAt(Date.now());
    setNow(Date.now());
    setResult(null);
    setError(null);
    setSelected(null);
    onFinished();
    try {
      setResult(await api.runNuclei(target));
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
      onFinished();
    }
  }

  const findings = result ? [...result.findings].sort(bySeverity) : [];
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]).filter(([, n]) => n);

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
        <button type="submit" disabled={running}>{running ? 'Scanning…' : 'Run Nuclei'}</button>
      </form>

      {running && (
        <p className="banner">
          Scanning for {formatDuration(now - startedAt)}. A full scan takes 15–25 minutes. Keep this tab
          open: closing it cancels the scan.
        </p>
      )}
      {error && <p className="banner error">{error}</p>}

      {result && (
        <>
          <p className={`banner ${result.status === 'done' ? 'ok' : 'error'}`}>
            <strong>{result.status === 'done' ? 'Scan complete' : 'Scan failed'}</strong>
            {result.error && <> — {result.error}</>}
          </p>
          <p className="meta">
            <span className="mono">{result.target.url}</span> · {findings.length} findings
            {counts.length > 0 && <> ({counts.map(([s, n]) => `${n} ${s}`).join(', ')})</>} ·{' '}
            {formatDuration(result.durationMs)}
            {result.versions && (
              <>
                {' '}· nuclei {result.versions.nuclei}, templates {result.versions.templates}
              </>
            )}
          </p>
          {findings.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Template</th>
                    <th>Name</th>
                    <th>Matcher</th>
                    <th>Matched at</th>
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
                      <td className="mono">{f.templateId}</td>
                      <td>{f.name}</td>
                      <td className="mono">{f.matcherName}</td>
                      <td className="mono">{f.matchedAt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {result.scope && (
            <details className="log">
              <summary>
                Scope proxy: {result.scope.allowedRequests} requests allowed,{' '}
                {result.scope.blockedRequests} off-scope requests blocked
              </summary>
              {result.scope.blocked.length > 0 ? (
                <pre className="raw">
                  {result.scope.blocked.map((b) => `${b.address}  ×${b.count}`).join('\n')}
                </pre>
              ) : (
                <p className="empty">Nothing tried to leave the allowed host and port.</p>
              )}
            </details>
          )}
          {result.log && (
            <details className="log">
              <summary>nuclei log</summary>
              <pre className="raw">{result.log}</pre>
            </details>
          )}
          {selected !== null && (
            <>
              <p className="meta">Raw nuclei output for {findings[selected].templateId} (click the row again to close):</p>
              <pre className="raw">{JSON.stringify(findings[selected].raw, null, 2)}</pre>
            </>
          )}
        </>
      )}
    </>
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
