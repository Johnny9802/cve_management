export function severityColor(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'text-red-400';
    case 'HIGH': return 'text-orange-400';
    case 'MEDIUM': return 'text-yellow-400';
    case 'LOW': return 'text-blue-400';
    default: return 'text-gray-400';
  }
}

export function severityBg(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-900/40 text-red-300 border border-red-700';
    case 'HIGH': return 'bg-orange-900/40 text-orange-300 border border-orange-700';
    case 'MEDIUM': return 'bg-yellow-900/40 text-yellow-300 border border-yellow-700';
    case 'LOW': return 'bg-blue-900/40 text-blue-300 border border-blue-700';
    default: return 'bg-gray-800 text-gray-400 border border-gray-700';
  }
}

export function priorityLabel(score) {
  if (score >= 80) return { text: 'CRITICAL PRIORITY', cls: 'bg-red-900/50 text-red-300 border-red-700' };
  if (score >= 60) return { text: 'HIGH PRIORITY', cls: 'bg-orange-900/50 text-orange-300 border-orange-700' };
  if (score >= 40) return { text: 'MEDIUM PRIORITY', cls: 'bg-yellow-900/50 text-yellow-300 border-yellow-700' };
  return { text: 'MONITOR', cls: 'bg-blue-900/50 text-blue-300 border-blue-700' };
}

export function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('it-IT', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function fmtScore(n, decimals = 1) {
  if (n == null) return '—';
  return Number(n).toFixed(decimals);
}

// Returns Tailwind classes for the match_confidence badge shown in the CVE table.
// 'uncertain' = keyword search couldn't confirm version affiliation
// 'certain'   = CPE vendor:product matched, version range evaluated
export function confidenceBadge(confidence) {
  if (confidence === 'uncertain') {
    return { label: '~', title: 'Uncertain match — CPE vendor/product could not be confirmed. Review manually.', cls: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700' };
  }
  if (confidence === 'cpe_search') {
    return { label: '✓', title: 'Matched via NVD CPE search (version-range validated by NVD)', cls: 'bg-green-900/40 text-green-300 border border-green-700' };
  }
  // 'certain' — local version range matched
  return { label: '✓', title: 'Version range confirmed by local CPE evaluation', cls: 'bg-green-900/40 text-green-300 border border-green-700' };
}
