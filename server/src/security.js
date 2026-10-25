// ScopeScan can run scanners, so it must only take orders from its own page on this machine.

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function reject(res, reason) {
  res.status(403).json({ error: `request rejected: ${reason}` });
}

// Blocks DNS rebinding: a malicious site points its own domain at 127.0.0.1, so the
// browser treats it as same-origin. Its requests still carry that domain in the Host header.
export function requireLocalHost(allowedHostnames) {
  return (req, res, next) => {
    const hostname = (req.headers.host ?? '').replace(/:\d+$/, '').toLowerCase();
    if (allowedHostnames.includes(hostname)) return next();
    reject(res, 'unexpected Host header');
  };
}

// Blocks CSRF: any website you visit can make your browser send requests to localhost.
// State-changing requests must come from an allowed Origin (browsers always send it on
// cross-site requests), carry a custom header and, if they have a body, be JSON.
// Another site can't add the header or send JSON without a CORS preflight, which we never approve.
export function requireSameSite(allowedOrigins) {
  return (req, res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();
    const { origin } = req.headers;
    if (origin !== undefined && !allowedOrigins.includes(origin)) {
      return reject(res, `origin ${origin} is not allowed`);
    }
    if (req.headers['x-scopescan'] !== '1') return reject(res, 'missing X-ScopeScan header');
    if (req.method !== 'DELETE' && !req.is('application/json')) {
      return reject(res, 'body must be application/json');
    }
    next();
  };
}
