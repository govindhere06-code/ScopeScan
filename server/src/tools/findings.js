// The one finding shape every tool's output is converted into, so the rest of ScopeScan
// (history, AI triage, reports) never has to know which tool produced what.
//
//   tool      'nuclei' | 'nmap' | 'ffuf'
//   type      what kind of result: 'template-match', 'open-port', 'path'
//   severity  'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'
//   title     one line a person can read
//   location  where it was found (URL, or host:port)
//   detail    the tool's supporting evidence, as short text
//   ref       the tool's identifier for the check (template id, service name, ...)
//   raw       the tool's original record, untouched
export function finding({ tool, type, severity = 'info', title, location, detail = null, ref = null, raw }) {
  return { tool, type, severity, title, location, detail, ref, raw };
}
