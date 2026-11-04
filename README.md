# ScopeScan

A web platform that runs open-source security scanners (Nuclei, nmap, ffuf) against targets **you are authorized to test**, normalizes their results, and uses a local LLM to triage and explain the findings.

> **Status:** all six roadmap tickets are done — scope allowlist, nmap/ffuf/Nuclei scanning, background scans, scan history, local AI triage and one-click PDF reports work end to end. See [Roadmap](#roadmap).

## Authorized targets only

ScopeScan refuses to scan any target that is not on an allowlist you control. This is enforced in the backend and every scan passes through it; there is no way to turn it off.

Scanning systems you don't own or don't have written permission to test is illegal in most countries (in India, under the IT Act 2000). Development and testing use only deliberately vulnerable apps running locally ([OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) and [DVWA](https://github.com/digininja/DVWA)).

## Features

- **Scope allowlist** — default deny; targets are host + port scope, stored in canonical form, with an audit log of every decision
- **Tool orchestration** — Nuclei, nmap and ffuf run as child processes and their output is normalized into one finding format
- **Background scans and history** — scans run as queued jobs; every scan and its results are kept
- **AI triage** — a local model (Ollama) flags likely false positives, explains findings and suggests fixes; scan data never leaves the machine
- **PDF reports** — one click: executive summary, scope and authorization record, methodology with tool versions and commands, findings with evidence and fixes, AI-written text marked as such

## Roadmap

- [x] **0 · Lab setup** — Docker, Juice Shop, DVWA, nmap, nuclei, ffuf
- [x] **1 · Project skeleton + scope allowlist**
- [x] **2 · Nuclei integration**
- [x] **3 · nmap and ffuf behind a shared interface**
- [x] **4 · Scan history + background jobs**
- [x] **5 · AI triage layer (local LLM)**
- [x] **6 · Report generation + polish**

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
npm test          # scope, security, job, triage and report tests
npm run eval      # score the AI triage against the labelled eval set (needs Ollama)
```

Optional settings go in `server/.env` (see `server/.env.example`). By default the database is stored in `%LOCALAPPDATA%\ScopeScan\scopescan.db`.

Scanning needs the tools themselves: [nmap](https://nmap.org), [ffuf](https://github.com/ffuf/ffuf) and [Nuclei](https://github.com/projectdiscovery/nuclei), on your `PATH` or set in `server/.env`. ffuf also needs a wordlist (`FFUF_WORDLIST`). Against Juice Shop, nmap takes seconds, ffuf about 3 minutes and Nuclei about 15; ScopeScan rate-limits the web scanners so the target doesn't fall over.

Scans run in the background on the server, so you can start one and close the page. `SCAN_TIMEOUT_MINUTES` (default 60) and `SCAN_CONCURRENCY` (default 1, at most 2) in `server/.env` control the time limit and how many scans run at once.

Every tool's output is converted into one finding format (`tool`, `type`, `severity`, `title`, `location`, `detail`, `ref`, plus the tool's raw record), so the rest of ScopeScan doesn't need to know which tool found what.

## How scans run

- **In the background.** Starting a scan only queues it, and the request answers at once. The page polls for progress, and every scan is saved with its target, the allowlist entry's port scope at the time, each tool's version, status, log and findings, and start and end times.
- **One at a time.** By default one scan runs and the rest wait in order. Even with two allowed, the same target is never scanned twice at once.
- **The allowlist is checked twice:** when the scan is requested and again when it starts, in case the entry was removed or narrowed while the scan waited.
- **Status:** queued → running → done, failed, timed out or cancelled. A scan that runs past the time limit has its tool killed and is marked timed out, and a cancelled one is killed the same way. Whatever a killed tool had already found is kept, labelled with the reason it stopped.
- **No orphaned scanners.** Every scanner process is recorded while it runs. Ctrl+C kills them with the server; after a crash, the next start kills any that are still running (only if the process ID still belongs to the same program) and marks the interrupted scans failed.

## How AI triage works

After a scan finishes, each finding is sent to a local model ([Ollama](https://ollama.com), `llama3.1:8b` by default) for a second opinion: is it a likely false positive, what severity it deserves, a plain-English explanation, a fix, and an OWASP Top 10 (2025) category and CWE. Install Ollama, run `ollama pull llama3.1:8b`, and ScopeScan uses it automatically; `AI_TRIAGE=off` in `server/.env` turns it off.

- **Scan data stays on this machine.** The model URL must point at this computer; anything else stops the server from starting.
- **It never removes anything.** A likely false positive is flagged and listed last, with the reason. The finding and the tool's original output stay as they were, next to the model's opinion.
- **Anchored to the tool.** The model starts from the scanner's severity, and a different severity is only accepted with a stated reason.
- **Scan output is treated as hostile.** It reaches the model fenced off as untrusted data, without full response bodies, and the reply must match a strict JSON schema (one retry, then the finding is marked "no AI answer"). The model can still be talked round: in testing, one planted "ignore previous instructions" line was enough. So if a finding's data contains instruction-like text, the model's verdict is not applied, and the finding is flagged as a possible prompt injection for a person to check.
- **Measured.** `npm run eval` runs the model over a labelled set of real findings from the lab (kept out of git, in `lab/`) and reports how often it agrees on false positives and severity, including findings with planted injections. First measurement with `llama3.1:8b` on 41 Juice Shop findings: false-positive calls agree 90% of the time (7 of 9 false positives caught, 2 of 32 real findings wrongly flagged), severity agrees exactly 66% of the time and within one level 76%. Its main weakness is rating missing security headers too high. The model on its own followed 3 of 4 planted instructions; with the guard, none got through. The labels are a first pass still to be reviewed by hand, and the prompt was adjusted on the same set, so treat these numbers as optimistic.

## The PDF report

A finished scan has a **Download PDF report** button. The report is built from the scan's saved data:

1. **Executive summary** — counts by severity (as the tools rated them, and after AI triage), the most important findings, and a plain warning if the scan or a tool did not complete. It is assembled by ScopeScan, not written by the AI.
2. **Scope and authorization** — the allowlist entry that permitted the scan (a copy is kept with the scan, so it survives the entry being removed), how many requests the scope proxy forwarded and blocked, and every audit-log entry for the scan, starting with the scope check that let it be queued.
3. **Methodology** — when it ran, each tool's version (Nuclei's template version too), result, duration and the command line it was run with, and how AI triage works.
4. **Findings** — each with its severity, location, the tool's evidence, and the AI's explanation and fix in a box marked *AI-assisted*. Where the AI changed a severity, the tool's own rating is shown next to it.
5. **Likely false positives** — listed in full with the AI's reason, not hidden.
6. **Limitations** — what an automated scan can't show.

The PDF is printed by Microsoft Edge or Google Chrome in headless mode, so nothing else needs installing; set `REPORT_BROWSER` in `server/.env` to pick one (or `off`). The report page is self-contained and its Content-Security-Policy stops it loading anything or running scripts, and every value from a scan is escaped, since findings carry text the target chose. Making a report is a POST from ScopeScan's own page (another website can't trigger it) and is recorded in the audit log.

## How the scope gate works

- **Default deny.** A target is allowed only if its exact host is on the allowlist and its port is in that entry's scope. "All ports" has to be granted explicitly with `*`.
- **One canonical form.** `localhost`, `127.0.0.1`, `[::1]`, `127.1`, `2130706433`, `LOCALHOST.` and `local%68ost` are all the same host, so a different spelling can't slip past the check.
- **Rejected outright:** credentials in the URL, non-http(s) schemes, spaces or control characters, and anything starting with `-` (which a scanner would read as a command-line flag).
- **Enforced on the wire, not just at the start.** Scanner templates often reach beyond the target on their own. In a full Nuclei scan of a single allowlisted port, templates tried 20+ other ports on the same host (Spark on 4040, port 80, and so on) and internet hosts such as `interact.sh`, `oast.me`, `checkip.amazonaws.com` and `login.microsoftonline.com`. So every scan runs through a scope proxy that only lets the allowlisted host and port through; everything else is dropped and counted in the scan result. Non-HTTP templates, which open their own connections around any proxy, are not run. The proxy also closes connections that go quiet, so a malformed template request can't hang a scan.
- **nmap is scoped by its arguments.** It opens raw connections, so it can't use the proxy. It only gets the ports listed in the allowlist entry (`-p`), never does DNS lookups (`-n`) or pings (`-Pn`), and an entry that grants all ports scans the 1,000 most common ones, not 65,535. Service names nmap merely guessed from the port number are shown as guesses, with nmap's confidence.
- **An empty result has to be earned.** If a scanner gives up on the target (for example because it crashed), the scan is marked failed rather than reported as "no findings". ffuf exits successfully even against a dead target, so for ffuf the proxy's count of unanswered requests decides.
- **Audit log.** Every allowlist change, every decision (allowed or denied) and every scan is recorded.
- **The server only obeys its own page.** It listens on `127.0.0.1` only. Requests that change anything must come from the ScopeScan page's origin, carry an `X-ScopeScan` header and be JSON, which blocks CSRF from other websites. Requests with a foreign `Host` header are refused, which blocks DNS rebinding.
