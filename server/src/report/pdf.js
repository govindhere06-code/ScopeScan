// Turns the report page into a PDF by printing it with a headless Edge or Chrome, which
// Windows already has: no PDF library, no browser download. Checked by hand first (Ticket 6
// gate): page numbers from CSS, and the page's Content-Security-Policy blocks loads and scripts.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { logTail, run } from '../tools/run.js';

const TIMEOUT_MS = 60_000;
const POLL_MS = 100;

function candidates(env, platform) {
  if (platform === 'win32') {
    const roots = [env['ProgramFiles(x86)'], env.ProgramFiles, env.LOCALAPPDATA].filter(Boolean);
    return roots.flatMap((root) => [
      path.win32.join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.win32.join(root, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    ]);
  }
  if (platform === 'darwin') {
    return [
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
    ];
  }
  return ['/usr/bin/microsoft-edge', '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
}

// REPORT_BROWSER picks the browser (or "off"); otherwise the first Edge or Chrome found.
// Returns null when there is none, which turns PDF reports off.
export function findBrowser(env = process.env, { platform = process.platform, exists = fs.existsSync } = {}) {
  const chosen = env.REPORT_BROWSER?.trim();
  if (chosen) return chosen.toLowerCase() === 'off' ? null : chosen;
  return candidates(env, platform).find((file) => exists(file)) ?? null;
}

export class ReportError extends Error {}

// The browser gets its own throwaway profile, so it never touches the user's own and runs even
// while their browser is open. Scripts are blocked by the page's own policy; turning JavaScript
// off with --blink-settings would be neater, but then Edge never prints.
export function browserArgs(htmlFile, pdfFile, profileDir) {
  return [
    '--headless',
    '--disable-gpu',
    '--no-pdf-header-footer',
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-sync',
    '--disable-background-networking',
    '--disable-component-update',
    `--print-to-pdf=${pdfFile}`,
    pathToFileURL(htmlFile).href,
  ];
}

// Edge's launcher hands the work to a second Edge process and exits at once (Chrome waits), so
// the browser exiting doesn't mean the PDF is ready. While a browser runs it holds `lockfile` in
// its profile, so the PDF is ready once it exists and nothing holds the profile any more.
async function printed(pdfFile, profileDir, deadline) {
  const lockfile = path.join(profileDir, 'lockfile');
  while (!fs.existsSync(pdfFile) || fs.existsSync(lockfile)) {
    if (Date.now() > deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
  return true;
}

export async function htmlToPdf(html, { browser, timeoutMs = TIMEOUT_MS } = {}) {
  const deadline = Date.now() + timeoutMs;
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'scopescan-report-'));
  const htmlFile = path.join(dir, 'report.html');
  const pdfFile = path.join(dir, 'report.pdf');
  const profileDir = path.join(dir, 'profile');
  try {
    await fs.promises.writeFile(htmlFile, html, 'utf8');
    let result;
    try {
      result = await run(browser, browserArgs(htmlFile, pdfFile, profileDir), { signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      if (err.code === 'ENOENT') throw new ReportError(`the browser was not found at ${browser}; set REPORT_BROWSER in server/.env`);
      throw err;
    }
    if (result.aborted || !(await printed(pdfFile, profileDir, deadline))) {
      throw new ReportError(`the browser made no PDF within ${timeoutMs / 1000} s ${logTail(result.stderr)}`.trim());
    }
    const pdf = await fs.promises.readFile(pdfFile);
    if (pdf.subarray(0, 5).toString() !== '%PDF-') throw new ReportError('the browser wrote something that is not a PDF');
    return pdf;
  } finally {
    // The browser can hold its profile files for a moment after it exits.
    await fs.promises.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => {});
  }
}
