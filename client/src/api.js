// Every request carries the X-ScopeScan header; the API rejects changes without it (CSRF guard).
async function request(path, { method = 'GET', body } = {}) {
  const headers = { 'X-ScopeScan': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

function unwrap({ ok, status, data }) {
  if (!ok) throw new Error(data?.error ?? `request failed (HTTP ${status})`);
  return data;
}

export const api = {
  listTargets: () => request('/targets').then(unwrap),
  addTarget: (entry) => request('/targets', { method: 'POST', body: entry }).then(unwrap),
  removeTarget: (id) => request(`/targets/${id}`, { method: 'DELETE' }).then(unwrap),
  listAudit: () => request('/audit').then(unwrap),
  // Queues a scan and returns it at once; progress comes from getScan / listScans.
  startScan: (target, tools) => request('/scans', { method: 'POST', body: { target, tools } }).then(unwrap),
  listScans: () => request('/scans').then(unwrap),
  getScan: (id) => request(`/scans/${id}`).then(unwrap),
  cancelScan: (id) => request(`/scans/${id}/cancel`, { method: 'POST', body: {} }).then(unwrap),
  triageScan: (id) => request(`/scans/${id}/triage`, { method: 'POST', body: {} }).then(unwrap),
  // A denial is a normal answer (HTTP 403), not an error.
  checkScope: async (target) => {
    const res = await request('/scope/check', { method: 'POST', body: { target } });
    if (res.status === 403 && res.data && 'allowed' in res.data) return res.data;
    return unwrap(res);
  },
};
