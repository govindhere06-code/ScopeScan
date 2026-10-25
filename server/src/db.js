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
  db.exec(SCHEMA);
  return db;
}
