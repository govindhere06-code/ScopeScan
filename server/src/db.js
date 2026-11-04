import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS allowlist (
    id         INTEGER PRIMARY KEY,
    host       TEXT NOT NULL UNIQUE,
    ports      TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY,
    ts       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    action   TEXT NOT NULL,
    input    TEXT,
    host     TEXT,
    port     INTEGER,
    decision TEXT NOT NULL,
    reason   TEXT
  );

  -- One row per scan request. status: queued -> running -> done | failed | timed_out | cancelled
  CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    target      TEXT NOT NULL,     -- canonical URL, as approved by the scope gate
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    ports       TEXT,              -- the allowlist entry's port scope when the scan started
    status      TEXT NOT NULL,
    error       TEXT,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT
  );

  -- One row per tool in a scan, created up front so the page can show what's still to come.
  -- status: queued -> running -> done | failed | timed_out | cancelled, or skipped
  CREATE TABLE IF NOT EXISTS scan_tools (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    status      TEXT NOT NULL,
    version     TEXT,
    error       TEXT,
    log         TEXT,
    scope       TEXT,              -- scope proxy counts, as JSON
    started_at  TEXT,
    finished_at TEXT,
    duration_ms INTEGER,
    UNIQUE (scan_id, tool)
  );

  CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY,
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool     TEXT NOT NULL,
    type     TEXT NOT NULL,
    severity TEXT NOT NULL,
    title    TEXT NOT NULL,
    location TEXT,
    detail   TEXT,
    ref      TEXT,
    raw      TEXT NOT NULL         -- the tool's original record, as JSON
  );
  CREATE INDEX IF NOT EXISTS findings_by_scan ON findings (scan_id);

  -- AI triage of a scan. status: queued -> running -> done | failed
  CREATE TABLE IF NOT EXISTS scan_triage (
    scan_id     INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    status      TEXT NOT NULL,
    model       TEXT NOT NULL,
    error       TEXT,
    queued_at   TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT
  );

  -- The model's opinion of one finding, kept next to it: the finding itself is never changed
  -- or removed. model_* columns are what the model said; false_positive and severity are what
  -- ScopeScan applies (the same, unless the finding's data looked like a prompt injection).
  CREATE TABLE IF NOT EXISTS finding_triage (
    finding_id            INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    scan_id               INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    status                TEXT NOT NULL,   -- done | failed
    error                 TEXT,
    model_false_positive  INTEGER,
    false_positive_reason TEXT,
    model_severity        TEXT,
    severity_reason       TEXT,
    explanation           TEXT,
    fix                   TEXT,
    owasp                 TEXT,
    cwe                   TEXT,
    injection_suspected   INTEGER NOT NULL DEFAULT 0,
    false_positive        INTEGER,
    severity              TEXT,
    model                 TEXT NOT NULL,
    duration_ms           INTEGER,
    created_at            TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS finding_triage_by_scan ON finding_triage (scan_id);

  -- Scanner processes that are running right now. If the server dies, these are the
  -- processes it may have left behind; the next start checks for them and kills them.
  CREATE TABLE IF NOT EXISTS scan_processes (
    pid        INTEGER PRIMARY KEY,
    scan_id    INTEGER NOT NULL,
    name       TEXT NOT NULL,      -- executable name, checked before killing (PIDs get reused)
    started_at TEXT NOT NULL
  );
`;

// Outside OneDrive on purpose: syncing a SQLite file while it's being written can corrupt it.
export function defaultDbPath() {
  const base = process.env.LOCALAPPDATA || path.join(os.homedir(), '.local', 'share');
  return path.join(base, 'ScopeScan', 'scopescan.db');
}

export function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  return db;
}
