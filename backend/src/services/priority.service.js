/**
 * PRIORITY SCORE ENGINE (0–100)
 *
 * Inspired by EPSS Plus, this engine combines multiple signals to produce
 * a single actionable priority score for each CVE.
 *
 * WHY NOT JUST USE CVSS?
 * CVSS measures theoretical severity (impact if exploited), not likelihood.
 * A CVSS 9.8 bug in obscure software nobody runs is less urgent than a
 * CVSS 7.0 bug being actively exploited in the wild.
 *
 * HOW THE SCORE IS BUILT:
 *
 * 1. EPSS (0–40 pts)
 *    Source: FIRST.org machine-learning model
 *    What it means: probability this CVE will be exploited in the next 30 days
 *    Why it matters: best predictor of real-world exploitation
 *    Score contribution: epss_score × 40
 *
 * 2. CVSS Severity (0–25 pts)
 *    Source: NVD / CVSS v3 base score
 *    Bands: CRITICAL=25, HIGH=18, MEDIUM=10, LOW=4
 *    Why it matters: measures technical damage if exploited
 *
 * 3. CISA KEV (0–25 pts)
 *    Source: CISA Known Exploited Vulnerabilities catalogue
 *    What it means: CISA has confirmed active exploitation in the wild
 *    Why it matters: definitive proof of real-world exploitation
 *    Score contribution: flat +25 if present
 *
 * 4. Recency (0–10 pts)
 *    Last 30 days → 10 pts | Last 90 days → 6 pts | Last 365 days → 3 pts
 *    Why it matters: recent CVEs are more likely to have active attacks
 *    before patches are widely deployed
 *
 * INTERPRETATION:
 *   80–100  → CRITICAL PRIORITY — patch or mitigate immediately
 *   60–79   → HIGH PRIORITY — schedule patch this sprint
 *   40–59   → MEDIUM PRIORITY — include in next patching cycle
 *   0–39    → MONITOR — track but lower urgency
 *
 * NOTE: A CVE in CISA KEV automatically scores ≥25, meaning any actively
 * exploited vulnerability will always appear in at least HIGH priority.
 */

function computePriorityScore({ cvssScore, severity, epssScore, inKev, publishedAt }) {
  let score = 0;

  // 1. EPSS contribution (0–40)
  const epss = parseFloat(epssScore) || 0;
  score += Math.round(epss * 40);

  // 2. CVSS severity contribution (0–25)
  const cvss = parseFloat(cvssScore) || 0;
  if (severity === 'CRITICAL' || cvss >= 9.0) score += 25;
  else if (severity === 'HIGH' || cvss >= 7.0) score += 18;
  else if (severity === 'MEDIUM' || cvss >= 4.0) score += 10;
  else if (severity === 'LOW' || cvss > 0) score += 4;

  // 3. CISA KEV (0–25)
  if (inKev) score += 25;

  // 4. Recency (0–10)
  if (publishedAt) {
    const ageMs = Date.now() - new Date(publishedAt).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    if (ageDays <= 30) score += 10;
    else if (ageDays <= 90) score += 6;
    else if (ageDays <= 365) score += 3;
  }

  return Math.min(100, Math.max(0, score));
}

function getPriorityLabel(score) {
  if (score >= 80) return { label: 'CRITICAL PRIORITY', color: 'red' };
  if (score >= 60) return { label: 'HIGH PRIORITY', color: 'orange' };
  if (score >= 40) return { label: 'MEDIUM PRIORITY', color: 'yellow' };
  return { label: 'MONITOR', color: 'blue' };
}

module.exports = { computePriorityScore, getPriorityLabel };
