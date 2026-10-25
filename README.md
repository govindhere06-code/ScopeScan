# ScopeScan

A web platform that runs open-source security scanners (Nuclei, nmap, ffuf) against targets **you are authorized to test**, normalizes their results, and uses a local LLM to triage and explain the findings.

> **Status:** early development — the scope allowlist is built and tested; no scanners are wired in yet. See [Roadmap](#roadmap).

## Authorized targets only

ScopeScan refuses to scan any target that is not on an allowlist you control. This is enforced in the backend and every scan passes through it; there is no way to turn it off.

Scanning systems you don't own or don't have written permission to test is illegal in most countries (in India, under the IT Act 2000). Development and testing use only deliberately vulnerable apps running locally ([OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) and [DVWA](https://github.com/digininja/DVWA)).

## Planned features

- **Scope allowlist** — default deny; targets are host + port scope, stored in canonical form, with an audit log of every decision
- **Tool orchestration** — Nuclei, nmap and ffuf run as child processes and their output is normalized into one finding format
- **Background scans and history** — scans run as queued jobs; past results are kept for comparison
- **AI triage** — a local model (Ollama) flags likely false positives, explains findings and suggests fixes; scan data never leaves the machine
- **PDF reports** — scope, methodology, findings, severity, evidence and remediation

## Roadmap

- [x] **0 · Lab setup** — Docker, Juice Shop, DVWA, nmap, nuclei, ffuf
- [x] **1 · Project skeleton + scope allowlist**
- [ ] **2 · Nuclei integration**
- [ ] **3 · nmap and ffuf behind a shared interface**
- [ ] **4 · Scan history + background jobs**
- [ ] **5 · AI triage layer (local LLM)**
- [ ] **6 · Report generation + polish**

## Tech stack

| Layer | Choice |
|---|---|
| Backend | Node.js, Express |
| Database | SQLite |
| Frontend | React |
| Scanners | Nuclei, nmap, ffuf |
| AI | Ollama (llama3.1:8b), running locally |
| Practice targets | OWASP Juice Shop, DVWA (Docker, bound to 127.0.0.1) |

## Lab setup

The practice apps are deliberately vulnerable. Bind them to `127.0.0.1` so nobody else on your network can reach them, and never expose them to the internet.

```
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker run -d --name dvwa -p 127.0.0.1:8080:80 vulnerables/web-dvwa
```

Juice Shop runs at http://localhost:3000 and DVWA at http://localhost:8080 (log in as `admin` / `password`, then click **Create / Reset Database**).

## Running ScopeScan

Requires Node.js 22 or newer.

```
npm --prefix server install
npm --prefix client install

npm run server    # API on http://127.0.0.1:4000
npm run client    # web page on http://127.0.0.1:5173 (in a second terminal)
npm test          # scope and security tests
```

Optional settings go in `server/.env` (see `server/.env.example`). By default the database is stored in `%LOCALAPPDATA%\ScopeScan\scopescan.db`.

## How the scope gate works

- **Default deny.** A target is allowed only if its exact host is on the allowlist and its port is in that entry's scope. "All ports" has to be granted explicitly with `*`.
- **One canonical form.** `localhost`, `127.0.0.1`, `[::1]`, `127.1`, `2130706433`, `LOCALHOST.` and `local%68ost` are all the same host, so a different spelling can't slip past the check.
- **Rejected outright:** credentials in the URL, non-http(s) schemes, spaces or control characters, and anything starting with `-` (which a scanner would read as a command-line flag).
- **Audit log.** Every allowlist change and every decision, allowed or denied, is recorded.
- **The server only obeys its own page.** It listens on `127.0.0.1` only. Requests that change anything must come from the ScopeScan page's origin, carry an `X-ScopeScan` header and be JSON, which blocks CSRF from other websites. Requests with a foreign `Host` header are refused, which blocks DNS rebinding.
