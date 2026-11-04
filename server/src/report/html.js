// The PDF report as one self-contained HTML page (pdf.js prints it with a headless browser).
// Every value from a scan is escaped: findings carry text the target chose. The page may not
// load anything or run scripts (see the Content-Security-Policy), so even a slip here can't
// make the browser fetch or execute what a target planted.
import { OWASP_EDITION } from '../ai/owasp.js';

const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', unknown: 'Unknown' };

const TOOL_PURPOSE = {
  nmap: 'Port and service discovery: a TCP connect scan of the allowed ports, asking each open port what software it runs.',
  ffuf: 'Content discovery: requests paths from a wordlist and keeps those whose answer does not look like the site’s “not found” page.',
  nuclei: 'Template-based checks for known exposures, misconfigurations and vulnerabilities (HTTP templates only).',
};

const EVENT_LABEL = {
  scope_check: 'Scope check',
  scan_queued: 'Scan queued',
  scan_started: 'Scan started',
  scan_refused: 'Scan refused',
  scan_finished: 'Scan finished',
  scan_nmap: 'nmap',
  scan_ffuf: 'ffuf',
  scan_nuclei: 'nuclei',
  orphan_killed: 'Leftover process killed',
  ai_triage: 'AI triage',
  report_created: 'Report created',
};

function when(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

function day(iso) {
  return iso ? new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';
}

function duration(ms) {
  if (ms == null) return '—';
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  const min = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return min < 60 ? `${min} min ${s} s` : `${Math.floor(min / 60)} h ${min % 60} min`;
}

const span = (from, to) => (from && to ? duration(new Date(to) - new Date(from)) : '—');
const badge = (severity) => `<span class="sev sev-${esc(severity)}">${esc(SEVERITY_LABEL[severity] ?? severity)}</span>`;
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const list = (items) => (items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`);

function severityBar(counts, total) {
  if (!total) return '';
  const parts = counts
    .filter((c) => c.applied)
    .map((c) => `<span class="bar-${esc(c.severity)}" style="flex-grow:${c.applied}"></span>`)
    .join('');
  return `<div class="bar">${parts}</div>`;
}

function cover(r) {
  const { scan, triage } = r;
  const kept = r.findings.length - r.flaggedCount;
  const legend = r.counts
    .filter((c) => c.applied)
    .map((c) => `<li>${badge(c.severity)} <b>${c.applied}</b></li>`)
    .join('');
  return `
<section class="cover">
  <div class="brand">ScopeScan</div>
  <p class="kicker">Automated security assessment</p>
  <h1>${esc(scan.target)}</h1>
  <p class="cover-date">${esc(day(scan.startedAt ?? scan.createdAt))}</p>
  <div class="cover-findings">
    <p class="big">${kept}</p>
    <p class="big-label">${kept === 1 ? 'finding' : 'findings'}${r.flaggedCount ? `, plus ${plural(r.flaggedCount, 'likely false positive')}` : ''}</p>
    ${severityBar(r.counts, kept)}
    <ul class="legend">${legend}</ul>
  </div>
  <table class="cover-meta">
    <tr><th>Scan</th><td>#${scan.id} · ${esc(statusText(scan.status))}</td></tr>
    <tr><th>Tools</th><td>${esc(r.tools.map((t) => t.tool).join(', '))}</td></tr>
    <tr><th>AI triage</th><td>${triage ? `${esc(triage.model)}, run locally (no data left this computer)` : 'not run'}</td></tr>
    <tr><th>Report created</th><td>${esc(when(r.generatedAt))}</td></tr>
  </table>
  <p class="confidential">Confidential. This report describes weaknesses in the system named above. It was produced by
  automated tools against a target on the tester’s allowlist; section 2 holds the authorization record.</p>
</section>`;
}

function statusText(status) {
  return (
    { done: 'completed', failed: 'failed', timed_out: 'stopped at the time limit', cancelled: 'cancelled' }[status] ??
    status
  );
}

function summary(r) {
  const { scan, triage } = r;
  const kept = r.findings.filter((f) => !f.flagged);
  const toolNames = list(r.tools.map((t) => t.tool));
  const countText = list(r.counts.filter((c) => c.applied).map((c) => `${c.applied} ${SEVERITY_LABEL[c.severity].toLowerCase()}`));
  const triaged = triage && triage.done > 0;

  let text = `<p>On ${esc(day(scan.startedAt ?? scan.createdAt))}, ScopeScan ran ${esc(toolNames)} against
    <span class="mono">${esc(scan.target)}</span>. The tools recorded ${plural(r.findings.length, 'finding')}.`;
  if (triaged) {
    const flagged = r.flaggedCount
      ? `${plural(r.flaggedCount, 'was', 'were')} flagged as likely false positives and ${r.flaggedCount === 1 ? 'is' : 'are'} listed in section 5, not removed`
      : 'none was flagged as a likely false positive';
    text += ` After AI-assisted triage, ${plural(kept.length, 'finding remains', 'findings remain')}${countText ? ` (${esc(countText)})` : ''};
      ${flagged}.`;
  } else {
    text += ` The findings were not triaged by the AI, so every severity is the tool’s own${countText ? ` (${esc(countText)})` : ''}.`;
  }
  text += '</p>';

  const warnings = [];
  if (scan.status !== 'done') warnings.push(`The scan did not complete (${esc(statusText(scan.status))}${scan.error ? `: ${esc(scan.error)}` : ''}).`);
  for (const t of r.tools.filter((t) => t.status !== 'done')) {
    warnings.push(`${esc(t.tool)} ${esc(statusText(t.status))}${t.error ? `: ${esc(t.error)}` : ''}.`);
  }
  if (triage && triage.status !== 'done') {
    warnings.push(`AI triage ${triage.status === 'failed' ? `failed${triage.error ? ` (${esc(triage.error)})` : ''}` : 'was still running'}
      when this report was made: ${triage.done} of ${triage.total} findings were looked at.`);
  }
  const incomplete = warnings.length
    ? `<div class="callout warn"><b>Results are incomplete.</b> ${warnings.join(' ')} Missing results are not evidence that the target is safe.</div>`
    : '';

  const top = kept.slice(0, 6);
  const aboveInfo = kept.some((f) => !['info', 'unknown'].includes(f.severityApplied));
  const topTable = top.length
    ? `<h3>Most important findings</h3>
      ${aboveInfo ? '' : '<p class="note">No finding was rated above informational. Informational findings describe the target (its software, pages and exposed files) and are still worth reviewing.</p>'}
      <table class="grid">
        <thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Path</th></tr></thead>
        <tbody>${top
          .map(
            (f) =>
              `<tr><td class="mono nowrap">${f.number}</td><td>${badge(f.severityApplied)}</td><td>${esc(f.heading)}</td><td class="mono wrap">${esc(f.where)}</td></tr>`,
          )
          .join('')}</tbody>
      </table>`
    : '<p>No findings were recorded.</p>';

  const countRows = r.counts
    .map((c) => `<tr><td>${badge(c.severity)}</td><td class="num">${c.tool}</td><td class="num">${triaged ? c.applied : '—'}</td></tr>`)
    .join('');
  const countTable = r.counts.length
    ? `<h3>Findings by severity</h3>
      <table class="grid counts">
        <thead><tr><th>Severity</th><th class="num">As the tools rated them</th><th class="num">After AI triage, excluding likely false positives</th></tr></thead>
        <tbody>${countRows}</tbody>
      </table>`
    : '';

  return `
<section class="page">
  <h2><span>1</span> Executive summary</h2>
  ${text}
  ${incomplete}
  ${topTable}
  ${countTable}
  <p class="note">This summary is assembled from the scan data by ScopeScan; it is not written by the AI.</p>
</section>`;
}

function authorization(r) {
  const { scan, authorization: auth } = r;
  const entry = auth.entry
    ? `<tr><th>Allowlist entry</th><td>#${esc(auth.entry.id)}: <span class="mono">${esc(auth.entry.host)}</span>, ports
        <span class="mono">${esc(auth.entry.ports)}</span>${auth.entry.note ? ` — “${esc(auth.entry.note)}”` : ''}</td></tr>
       <tr><th>Entry added</th><td>${esc(when(auth.entry.createdAt))}</td></tr>`
    : `<tr><th>Allowlist entry</th><td>not recorded for this scan (it predates ScopeScan keeping a copy); the port scope when it
        started was <span class="mono">${esc(auth.ports ?? '—')}</span></td></tr>`;

  const proxied = r.tools.filter((t) => t.scope);
  const proxyText = proxied.length
    ? proxied
        .map((t) => {
          const destinations = t.scope.blocked ?? [];
          const top = destinations.slice(0, 3).map((b) => `<span class="mono">${esc(b.address)}</span> (${b.count})`);
          const others = destinations.length - top.length;
          const where = top.length ? ` — most often ${top.join(', ')}${others ? `, and ${plural(others, 'other destination')}` : ''}` : '';
          return `<li><b>${esc(t.tool)}</b>: ${t.scope.allowedRequests} requests forwarded, ${t.scope.blockedRequests} blocked${where}.</li>`;
        })
        .join('')
    : '';
  const nmap = r.tools.find((t) => t.tool === 'nmap');

  const events = auth.events
    .map(
      (e) => `<tr>
        <td class="nowrap">${esc(when(e.ts))}</td>
        <td class="nowrap">${esc(EVENT_LABEL[e.action] ?? e.action)}</td>
        <td>${esc(e.decision)}</td>
        <td class="wrap">${esc(e.reason ?? '')}</td>
      </tr>`,
    )
    .join('');

  return `
<section class="page">
  <h2><span>2</span> Scope and authorization</h2>
  <p>ScopeScan only scans hosts and ports on its allowlist. The tester controls that list and may only add systems they own or
  have written permission to test. Every request to scan is checked against it, and checked again when the scan starts.</p>
  <table class="facts">
    <tr><th>Target</th><td class="mono">${esc(scan.target)}</td></tr>
    <tr><th>Host and port</th><td class="mono">${esc(scan.host)}:${esc(scan.port)}</td></tr>
    ${entry}
  </table>

  <h3>How the scope was enforced</h3>
  <ul>
    ${proxyText}
    ${nmap ? `<li><b>nmap</b> was limited to port${String(auth.ports).includes(',') ? 's' : ''} <span class="mono">${esc(auth.ports ?? scan.port)}</span> of <span class="mono">${esc(scan.host)}</span>.</li>` : ''}
  </ul>
  ${proxied.length ? '<p class="note">ffuf and nuclei sent all their traffic through ScopeScan’s scope proxy, which forwards a request only if it goes to the allowed host and port. Blocked requests are templates and redirects trying to reach other hosts or ports.</p>' : ''}

  <h3>Audit record</h3>
  <p class="note">Every entry ScopeScan’s audit log holds for this scan, oldest first.</p>
  <table class="grid audit">
    <thead><tr><th>Time</th><th>Event</th><th>Decision</th><th>Detail</th></tr></thead>
    <tbody>${events || '<tr><td colspan="4">No audit entries found.</td></tr>'}</tbody>
  </table>
</section>`;
}

function methodology(r) {
  const { scan, triage } = r;
  const rows = r.tools
    .map(
      (t) => `<tr>
        <td><b>${esc(t.tool)}</b></td>
        <td class="mono">${esc(t.version ?? '—')}</td>
        <td>${esc(statusText(t.status))}</td>
        <td class="nowrap">${esc(when(t.startedAt))}</td>
        <td class="num nowrap">${esc(duration(t.durationMs))}</td>
        <td class="num">${t.findingCount}</td>
      </tr>`,
    )
    .join('');
  const steps = r.tools
    .map(
      (t) => `<li><b>${esc(t.tool)}</b> — ${esc(TOOL_PURPOSE[t.tool] ?? '')}
        ${t.command ? `<pre>${esc(t.command.join(' '))}</pre>` : '<p class="note">Command line not recorded for this scan.</p>'}</li>`,
    )
    .join('');
  const ai = triage
    ? `<h3>AI-assisted triage</h3>
      <p>After the scan, each finding was given to <b>${esc(triage.model)}</b>, a language model running on this computer through
      Ollama; no finding was sent anywhere else. For each one the model gave an opinion on whether it is a false positive, a
      severity with its reason, a plain explanation, a fix, and a category from the OWASP Top 10 (${OWASP_EDITION}).</p>
      <ul>
        <li>The model’s answers are checked against a fixed format; an answer that fails is asked for again once, then recorded as no answer.</li>
        <li>The AI never removes a finding or changes what the tool recorded. Likely false positives are listed separately (section 5).</li>
        <li>Finding data is passed to the model as untrusted text. If it contains wording that reads like instructions to an AI,
        the model’s verdict is not applied and the tool’s rating stands.</li>
      </ul>
      <p>${triage.done} of ${triage.total} findings answered${triage.failed ? `, ${triage.failed} without a usable answer` : ''};
      triage ran ${esc(when(triage.startedAt))} and took ${esc(span(triage.startedAt, triage.finishedAt))}.</p>`
    : '';
  return `
<section class="page">
  <h2><span>3</span> Methodology</h2>
  <table class="facts">
    <tr><th>Requested</th><td>${esc(when(scan.createdAt))}</td></tr>
    <tr><th>Started</th><td>${esc(when(scan.startedAt))}</td></tr>
    <tr><th>Finished</th><td>${esc(when(scan.finishedAt))} (${esc(span(scan.startedAt, scan.finishedAt))})</td></tr>
  </table>
  <h3>Tools</h3>
  <table class="grid">
    <thead><tr><th>Tool</th><th>Version</th><th>Result</th><th>Started</th><th class="num">Time</th><th class="num">Findings</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <ol class="steps">${steps}</ol>
  ${ai}
</section>`;
}

function aiBlock(f) {
  const t = f.triage;
  if (!t) return '';
  if (t.status === 'failed') {
    return `<div class="ai"><p class="ai-label">AI-assisted · ${esc(t.model)}</p><p>The model gave no usable answer for this finding.</p></div>`;
  }
  const changed = t.severity !== f.severity;
  const parts = [];
  if (t.injectionSuspected) {
    parts.push(`<p class="danger"><b>Possible prompt injection.</b> This finding’s data contains text that reads like
      instructions to an AI, so the model’s verdict was not applied (it said: ${t.modelSaid.falsePositive ? 'false positive' : 'real'},
      ${esc(t.modelSaid.severity)}). The target may be trying to mislead automated tools; check this finding by hand.</p>`);
  }
  if (t.falsePositive) parts.push(`<p><b>Why it is likely a false positive:</b> ${esc(t.falsePositiveReason)}</p>`);
  if (changed && t.severityReason) {
    parts.push(`<p><b>Severity ${esc(f.severity)} → ${esc(t.severity)}:</b> ${esc(t.severityReason)}</p>`);
  }
  parts.push(`<p>${esc(t.explanation)}</p>`);
  parts.push(`<p><b>Fix:</b> ${esc(t.fix)}</p>`);
  return `<div class="ai">
    <p class="ai-label">AI-assisted · ${esc(t.model)} · a second opinion, not verified by a person</p>
    ${parts.join('')}
  </div>`;
}

function findingCard(f) {
  const t = f.triage?.status === 'done' ? f.triage : null;
  const severityText = t
    ? t.severity === f.severity
      ? `${badge(f.severityApplied)} <span class="note">the tool and the AI agree</span>`
      : `${badge(f.severityApplied)} <span class="note">the tool rated it ${esc(f.severity)}; ${t.injectionSuspected ? 'the AI’s rating was not applied' : `the AI rated it ${esc(t.severity)}`}</span>`
    : `${badge(f.severity)} <span class="note">the tool’s rating</span>`;
  const evidence = f.evidence.length
    ? `<table class="evidence">${f.evidence.map(([k, v]) => `<tr><th>${esc(k)}</th><td class="wrap">${esc(v)}</td></tr>`).join('')}</table>`
    : '';
  const classification = [
    t?.owasp ? `${esc(t.owasp.id)} ${esc(t.owasp.name)}` : null,
    t?.cwe ? esc(t.cwe) : null,
  ].filter(Boolean);

  return `
<article class="finding${f.flagged ? ' flagged' : ''}">
  <header>
    <span class="num-id">${f.number}</span>
    <h3>${esc(f.heading)}</h3>
  </header>
  <table class="facts">
    <tr><th>Severity</th><td>${severityText}</td></tr>
    <tr><th>Location</th><td class="mono wrap">${esc(f.location)}</td></tr>
    <tr><th>Found by</th><td>${esc(f.tool)}${f.ref ? ` <span class="mono">(${esc(f.ref)})</span>` : ''}</td></tr>
    ${classification.length ? `<tr><th>Category</th><td>${classification.join(' · ')} <span class="note">(AI-assigned)</span></td></tr>` : ''}
  </table>
  ${f.description ? `<p><b>From the tool:</b> ${esc(f.description)}</p>` : !f.evidence.length && f.detail ? `<p><b>From the tool:</b> ${esc(f.detail)}</p>` : ''}
  ${evidence}
  ${aiBlock(f)}
  ${f.remediation ? `<p><b>The template’s remediation advice:</b> ${esc(f.remediation)}</p>` : ''}
  ${f.references.length ? `<p class="note refs">References: ${f.references.map((x) => `<span class="mono">${esc(x)}</span>`).join(' · ')}</p>` : ''}
</article>`;
}

function findingsSection(r) {
  const kept = r.findings.filter((f) => !f.flagged);
  const overview = kept.length
    ? `<table class="grid">
        <thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Tool</th><th>Path</th></tr></thead>
        <tbody>${kept
          .map(
            (f) => `<tr><td class="mono nowrap">${f.number}</td><td>${badge(f.severityApplied)}${
              f.severityApplied !== f.severity ? `<div class="was">tool: ${esc(f.severity)}</div>` : ''
            }</td><td>${esc(f.heading)}</td><td>${esc(f.tool)}</td><td class="mono wrap">${esc(f.where)}</td></tr>`,
          )
          .join('')}</tbody>
      </table>`
    : '<p>No findings.</p>';
  return `
<section class="page">
  <h2><span>4</span> Findings</h2>
  <p>Ordered by severity. Where the AI changed a severity, the tool’s own rating is shown next to it. Text in the
  shaded “AI-assisted” boxes was written by the model and has not been verified by a person. Paths are on
  <span class="mono">${esc(r.scan.target)}</span>.</p>
  ${overview}
  ${kept.map(findingCard).join('')}
</section>`;
}

function falsePositives(r) {
  const flagged = r.findings.filter((f) => f.flagged);
  if (!flagged.length) return '';
  return `
<section class="page">
  <h2><span>5</span> Likely false positives</h2>
  <p>The AI judged these ${flagged.length} findings to be likely false positives. They are kept, with the reason, so a person can
  check the call; ScopeScan never removes a finding.</p>
  ${flagged.map(findingCard).join('')}
</section>`;
}

function limitations(r) {
  const n = r.flaggedCount ? 6 : 5;
  return `
<section class="page-auto">
  <h2><span>${n}</span> Limitations</h2>
  <ul>
    <li>This is an automated scan. No manual testing was done, and areas behind a login were not tested.</li>
    <li>A tool that found nothing has not shown the target to be safe. ffuf only finds paths in its wordlist, and nuclei only
    checks for what its templates describe.</li>
    <li>The tools were deliberately slowed down to keep the target running, and nuclei used HTTP templates only, so checks
    that need other protocols were not run.</li>
    <li>The AI’s opinions, severities and categories are a second opinion to check, not a verdict. It can miss context a
    person would see, such as what an exposed file actually contains.</li>
  </ul>
  <p class="note">Generated by ScopeScan on ${esc(when(r.generatedAt))}.</p>
</section>`;
}

const STYLE = `
@page {
  size: A4;
  margin: 18mm 17mm 20mm;
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 7.5pt 'Segoe UI', sans-serif; color: #6b7280; }
}
@page :first { @bottom-left { content: none; } @bottom-right { content: none; } }
:root { --ink: #161b26; --muted: #5d6576; --rule: #dde1e8; --soft: #f3f5f8; --accent: #2f5bd3; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; color: var(--ink); font: 9.5pt/1.5 'Segoe UI', system-ui, sans-serif; }
.mono, pre { font-family: 'Cascadia Mono', Consolas, monospace; font-size: 8.3pt; }
.wrap { overflow-wrap: anywhere; }
.nowrap { white-space: nowrap; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.note { color: var(--muted); font-size: 8.5pt; }
p { margin: 0 0 7pt; }
ul, ol { margin: 0 0 8pt; padding-left: 15pt; }
li { margin-bottom: 3pt; }
h2 { font-size: 17pt; font-weight: 600; margin: 0 0 12pt; padding-bottom: 6pt; border-bottom: 2px solid var(--ink); }
h2 span { color: var(--accent); margin-right: 6pt; }
h3 { font-size: 11pt; font-weight: 600; margin: 14pt 0 6pt; break-after: avoid; }
.page { break-before: page; }
.page-auto { margin-top: 22pt; break-inside: avoid; }
table { width: 100%; border-collapse: collapse; margin-bottom: 8pt; }
th { text-align: left; font-weight: 600; }
.grid th, .grid td { padding: 4pt 6pt; border-bottom: 1px solid var(--rule); vertical-align: top; }
.grid thead th { font-size: 8pt; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; border-bottom: 1.5px solid var(--ink); }
.grid tr { break-inside: avoid; }
.facts th { width: 27%; padding: 2.5pt 10pt 2.5pt 0; color: var(--muted); font-weight: 500; vertical-align: top; }
.facts td { padding: 2.5pt 0; }
.counts th:first-child { width: 22%; }
.audit td { font-size: 8.3pt; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--soft); border-radius: 4pt; padding: 5pt 7pt; margin: 4pt 0 6pt; }
.sev { display: inline-block; min-width: 46pt; text-align: center; padding: 1pt 6pt; border-radius: 3pt; font-size: 7.5pt; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.sev-critical, .bar-critical { background: #7a1020; color: #fff; }
.sev-high, .bar-high { background: #c62828; color: #fff; }
.sev-medium, .bar-medium { background: #e8870e; color: #fff; }
.sev-low, .bar-low { background: #f2c94c; color: #3d2f00; }
.sev-info, .bar-info { background: #d6e2f5; color: #1f3d7a; }
.sev-unknown, .bar-unknown { background: #e3e5e8; color: #444; }
.was { font-size: 7.5pt; color: var(--muted); margin-top: 1pt; }
.callout { border-radius: 4pt; padding: 7pt 9pt; margin: 8pt 0; }
.callout.warn { background: #fff4e0; border-left: 3pt solid #e8870e; }

.cover { height: 257mm; display: flex; flex-direction: column; }
.brand { font-size: 11pt; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: var(--accent); }
.kicker { margin-top: 70mm; font-size: 11pt; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }
.cover h1 { font-size: 26pt; line-height: 1.15; font-weight: 600; margin: 4pt 0 6pt; overflow-wrap: anywhere; }
.cover-date { font-size: 12pt; color: var(--muted); }
.cover-findings { margin: 20mm 0 12mm; }
.big { font-size: 40pt; font-weight: 600; line-height: 1; margin: 0; }
.big-label { color: var(--muted); margin: 2pt 0 8pt; }
.bar { display: flex; height: 9pt; border-radius: 2pt; overflow: hidden; gap: 1.5pt; width: 100%; }
.bar span { flex-basis: 0; }
.legend { list-style: none; padding: 0; margin: 7pt 0 0; display: flex; flex-wrap: wrap; gap: 4pt 14pt; }
.legend li { margin: 0; }
.cover-meta { width: auto; margin-top: auto; }
.cover-meta th { color: var(--muted); font-weight: 500; padding: 2pt 14pt 2pt 0; }
.cover-meta td { padding: 2pt 0; }
.confidential { margin-top: 10mm; padding-top: 6pt; border-top: 1px solid var(--rule); font-size: 8pt; color: var(--muted); }

.steps { padding-left: 15pt; }
.steps li { margin-bottom: 7pt; }
.finding { margin-top: 16pt; padding-top: 10pt; border-top: 1px solid var(--rule); }
.finding header { display: flex; align-items: baseline; gap: 8pt; margin-bottom: 4pt; break-after: avoid; }
.finding h3 { margin: 0; }
.num-id { font-family: 'Cascadia Mono', Consolas, monospace; font-size: 9pt; color: var(--accent); font-weight: 600; }
.finding .facts { break-inside: avoid; }
.evidence { background: var(--soft); border-radius: 4pt; margin: 4pt 0 8pt; break-inside: avoid; }
.evidence th { width: 27%; padding: 2.5pt 8pt; color: var(--muted); font-weight: 500; vertical-align: top; }
.evidence td { padding: 2.5pt 8pt 2.5pt 0; font-size: 8.5pt; }
.ai { border-left: 3pt solid var(--accent); background: #eef2fc; padding: 6pt 9pt; border-radius: 0 4pt 4pt 0; margin: 4pt 0 8pt; break-inside: avoid; }
.ai p:last-child { margin-bottom: 0; }
.ai-label { font-size: 7.5pt; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; color: var(--accent); margin-bottom: 4pt; }
.danger { color: #a12a2a; }
.flagged h3 { color: var(--muted); }
.refs { overflow-wrap: anywhere; }
`;

export function reportHtml(r) {
  // The footer text goes through CSS, so it is escaped for a CSS string, not HTML.
  const footer = `ScopeScan · scan #${r.scan.id} · ${r.scan.target}`.replace(/["\\\n<]/g, '');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ScopeScan report — scan #${esc(r.scan.id)}</title>
<style>${STYLE}
@page { @bottom-left { content: "${footer}"; font: 7.5pt 'Segoe UI', sans-serif; color: #6b7280; } }
@page :first { @bottom-left { content: none; } }
</style>
</head>
<body>
${cover(r)}
${summary(r)}
${authorization(r)}
${methodology(r)}
${findingsSection(r)}
${falsePositives(r)}
${limitations(r)}
</body>
</html>`;
}
