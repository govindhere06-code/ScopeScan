// OWASP Top 10 (2025 edition), summarized. The whole list goes into every triage prompt:
// it's short enough that the model can pick from it directly, so no vector store is needed.
export const OWASP_EDITION = '2025';

export const OWASP_TOP_10 = [
  { id: 'A01', name: 'Broken Access Control', text: 'Users can reach data or actions they should not: missing authorization checks, exposed files or directories, IDOR, CORS mistakes.' },
  { id: 'A02', name: 'Security Misconfiguration', text: 'Insecure defaults or settings: missing security headers, verbose errors, directory listings, debug or admin endpoints left open, unneeded features enabled.' },
  { id: 'A03', name: 'Software Supply Chain Failures', text: 'Vulnerable, outdated or untrusted components and dependencies, and weaknesses in how software is built and delivered.' },
  { id: 'A04', name: 'Cryptographic Failures', text: 'Sensitive data not protected by cryptography or protected badly: plain HTTP, weak algorithms, exposed secrets or keys.' },
  { id: 'A05', name: 'Injection', text: 'Untrusted input interpreted as code or commands: SQL injection, cross-site scripting (XSS), command injection.' },
  { id: 'A06', name: 'Insecure Design', text: 'Missing or flawed security controls in the design itself, such as no rate limiting or broken business logic.' },
  { id: 'A07', name: 'Authentication Failures', text: 'Weak login and session handling: default or weak passwords, credential stuffing, session fixation, missing MFA.' },
  { id: 'A08', name: 'Software or Data Integrity Failures', text: 'Code or data trusted without checking its integrity: insecure deserialization, unsigned updates.' },
  { id: 'A09', name: 'Security Logging and Alerting Failures', text: 'Attacks are not logged, monitored or alerted on, so they go unnoticed.' },
  { id: 'A10', name: 'Mishandling of Exceptional Conditions', text: 'Errors and unusual conditions handled unsafely: crashes, stack traces shown to users, failing open.' },
];

export const OWASP_IDS = [...OWASP_TOP_10.map((c) => c.id), 'none'];

export function owaspPromptText() {
  return OWASP_TOP_10.map((c) => `${c.id}:${OWASP_EDITION} ${c.name} - ${c.text}`).join('\n');
}
