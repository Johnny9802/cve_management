'use strict';

const db = require('../database/postgres');

const VALID_STATUSES = new Set([
  'open', 'in_review', 'false_positive',
  'accepted_risk', 'planned', 'remediated', 'closed',
]);

// Transitions that require extra fields to be valid
const REQUIRED_FIELDS = {
  accepted_risk: ['risk_acceptance_reason', 'risk_acceptance_expiry'],
  planned:       ['remediation_due_date'],
};

/**
 * Updates the status of a single finding (product_id + cve_id pair).
 * Appends a row to findings_history for every change.
 *
 * @param {string} productId
 * @param {string} cveId
 * @param {object} update - { status, owner, remediation_due_date, remediation_notes,
 *                           risk_acceptance_reason, risk_acceptance_expiry,
 *                           evidence_url, actor, note }
 * @returns {object} updated finding row
 * @throws {Error} with .statusCode if input is invalid or finding not found
 */
async function updateFindingStatus(productId, cveId, update) {
  const { status, actor, note, ...fields } = update;

  if (status && !VALID_STATUSES.has(status)) {
    const err = new Error(`Invalid status "${status}". Valid: ${[...VALID_STATUSES].join(', ')}`);
    err.statusCode = 400;
    throw err;
  }

  if (status && REQUIRED_FIELDS[status]) {
    for (const field of REQUIRED_FIELDS[status]) {
      if (!fields[field] && !update[field]) {
        const err = new Error(`Status "${status}" requires field: ${field}`);
        err.statusCode = 400;
        throw err;
      }
    }
  }

  const { rows } = await db.query(
    'SELECT * FROM product_cves WHERE product_id = $1 AND cve_id = $2',
    [productId, cveId]
  );
  if (!rows.length) {
    const err = new Error('Finding not found');
    err.statusCode = 404;
    throw err;
  }
  const current = rows[0];

  // Build SET clause dynamically from provided fields
  const updatable = [
    'status', 'owner', 'remediation_due_date', 'remediation_notes',
    'risk_acceptance_reason', 'risk_acceptance_expiry', 'evidence_url', 'sla_breached',
  ];
  const setClauses = ['last_seen = NOW()'];
  const params = [];
  let p = 1;

  for (const col of updatable) {
    const val = col === 'status' ? status : fields[col];
    if (val !== undefined && val !== null) {
      setClauses.push(`${col} = $${p++}`);
      params.push(val);
    }
  }
  if (status === 'closed' || status === 'false_positive') {
    setClauses.push(`closed_at = NOW()`);
  }

  params.push(productId, cveId);
  const updateResult = await db.query(
    `UPDATE product_cves SET ${setClauses.join(', ')}
     WHERE product_id = $${p++} AND cve_id = $${p++}
     RETURNING *`,
    params
  );

  // Append audit record if status changed
  if (status && status !== current.status) {
    await db.query(
      `INSERT INTO findings_history (product_id, cve_id, old_status, new_status, actor, note)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [productId, cveId, current.status, status, actor || null, note || null]
    );
  }

  return updateResult.rows[0];
}

/**
 * Returns all status-change history entries for a finding, newest first.
 */
async function getFindingHistory(productId, cveId) {
  const { rows } = await db.query(
    `SELECT * FROM findings_history
     WHERE product_id = $1 AND cve_id = $2
     ORDER BY changed_at DESC`,
    [productId, cveId]
  );
  return rows;
}

/**
 * Returns aggregated finding statistics useful for governance dashboards.
 * Counts by status, SLA breaches, and open KEV findings.
 */
async function getFindingStats() {
  const [byStatus, slaBreached, kevOpen] = await Promise.all([
    db.query(`
      SELECT pc.status, COUNT(*) AS count
      FROM product_cves pc
      GROUP BY pc.status
      ORDER BY pc.status
    `),
    db.query(`
      SELECT COUNT(*) AS count
      FROM product_cves
      WHERE sla_breached = TRUE AND status NOT IN ('remediated','closed','false_positive')
    `),
    db.query(`
      SELECT COUNT(*) AS count
      FROM product_cves pc
      JOIN cves c ON c.cve_id = pc.cve_id
      WHERE c.in_cisa_kev = TRUE
        AND pc.status NOT IN ('remediated','closed','false_positive')
    `),
  ]);

  return {
    by_status: byStatus.rows,
    sla_breached: parseInt(slaBreached.rows[0].count),
    open_kev_findings: parseInt(kevOpen.rows[0].count),
  };
}

/**
 * Returns all open findings ordered by CVE priority score, with governance fields.
 * Used for the remediation backlog view.
 */
async function getOpenFindings({ status, owner, page = 1, limit = 50 } = {}) {
  const conditions = [`pc.status NOT IN ('remediated','closed','false_positive')`];
  const params = [];
  let p = 1;

  if (status) { conditions.push(`pc.status = $${p++}`); params.push(status); }
  if (owner)  { conditions.push(`pc.owner = $${p++}`);  params.push(owner); }

  const offset = (Math.max(1, page) - 1) * Math.min(200, Math.max(1, limit));
  params.push(Math.min(200, Math.max(1, limit)), offset);

  const { rows } = await db.query(`
    SELECT
      pc.product_id, pc.cve_id, pc.status, pc.match_confidence,
      pc.owner, pc.remediation_due_date, pc.first_seen, pc.last_seen,
      pc.sla_breached, pc.risk_acceptance_expiry,
      c.severity, c.cvss_v3_score, c.epss_score, c.priority_score,
      c.in_cisa_kev, c.description,
      p.name AS product_name, p.version AS product_version, p.vendor
    FROM product_cves pc
    JOIN cves     c ON c.cve_id   = pc.cve_id
    JOIN products p ON p.id       = pc.product_id
    WHERE ${conditions.join(' AND ')}
    ORDER BY c.priority_score DESC NULLS LAST, c.in_cisa_kev DESC
    LIMIT $${p++} OFFSET $${p++}
  `, params);

  return rows;
}

module.exports = {
  updateFindingStatus,
  getFindingHistory,
  getFindingStats,
  getOpenFindings,
};
