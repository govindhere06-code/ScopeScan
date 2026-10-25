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
