import { createApp } from './app.js';
import { defaultDbPath, openDb } from './db.js';

// Hard-coded on purpose: ScopeScan must never be reachable from the network (no 0.0.0.0).
const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT ?? 4000);
const dbPath = process.env.DB_PATH || defaultDbPath();
const allowedOrigins = (process.env.CLIENT_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const db = openDb(dbPath);
createApp({ db, allowedOrigins }).listen(PORT, HOST, () => {
  console.log(`ScopeScan API listening on http://${HOST}:${PORT}`);
  console.log(`Database: ${dbPath}`);
});
