const db = require('../database/postgres');
const nvd = require('./nvd.service');
const epss = require('./epss.service');
const kev = require('./cisa-kev.service');
const { computePriorityScore } = require('./priority.service');
const { isCveAffectingProduct } = require('./version-matcher.service');
const cache = require('./cache.service');

// Full sync for a single product: fetch CVEs from NVD, filter by version range,
// enrich with EPSS/KEV, and persist.
async function syncProduct(productId) {
  const { rows } = await db.query('SELECT * FROM products WHERE id = $1', [productId]);
  if (!rows.length) throw new Error('Product not found');
  const product = rows[0];

  const keyword = product.cpe_keyword || `${product.name} ${product.version}`;
  const searchedByCpe = nvd.isCpe(keyword);
  console.log(`Syncing: ${product.name} ${product.version} [${searchedByCpe ? 'CPE' : 'keyword'}]`);

  const rawCves = await nvd.searchCves(keyword, { maxResults: 500 });
  if (!rawCves.length) {
    await db.query(
      'UPDATE products SET last_synced_at = NOW(), cve_count = 0, critical_count = 0 WHERE id = $1',
      [productId]
    );
    return { synced: 0, filtered: 0 };
  }

  // ── Version-range filtering ──────────────────────────────────────────────
  // CPE search: NVD already validated version ranges server-side — trust it.
  // Keyword search: NVD returns all CVEs mentioning the name regardless of
  //   version, so we must evaluate the CPE version ranges locally.
  let filteredCves;
  let filteredCount = 0;

  if (searchedByCpe) {
    filteredCves = rawCves.map((c) => ({
      ...c,
      _matchResult: { affected: true, confidence: 'certain', reason: 'cpe_search' },
    }));
  } else {
    filteredCves = [];
    for (const cveData of rawCves) {
      const matchResult = isCveAffectingProduct(product, cveData.affected_cpe);
      if (!matchResult.affected) {
        filteredCount++;
        console.log(`  Filtered ${cveData.cve_id}: ${matchResult.reason}`);
        continue;
      }
      filteredCves.push({ ...cveData, _matchResult: matchResult });
    }
    if (filteredCount > 0) {
      console.log(`  Version filter removed ${filteredCount}/${rawCves.length} CVEs for ${product.name} ${product.version}`);
    }
  }

  if (!filteredCves.length) {
    await db.query(
      'UPDATE products SET last_synced_at = NOW(), cve_count = 0, critical_count = 0 WHERE id = $1',
      [productId]
    );
    return { synced: 0, filtered: filteredCount };
  }

  // ── Enrich with EPSS and CISA KEV ────────────────────────────────────────
  const cveIds = filteredCves.map((c) => c.cve_id);
  const [epssData, kevData] = await Promise.all([
    epss.fetchEpssScores(cveIds),
    kev.enrichWithKev(cveIds),
  ]);

  // ── Upsert CVEs and link to product ──────────────────────────────────────
  for (const cveData of filteredCves) {
    const epssInfo = epssData[cveData.cve_id] || { score: 0, percentile: 0 };
    const kevInfo  = kevData[cveData.cve_id]  || { inKev: false, details: null };

    const priorityScore = computePriorityScore({
      cvssScore:   cveData.cvss_v3_score,
      severity:    cveData.severity,
      epssScore:   epssInfo.score,
      inKev:       kevInfo.inKev,
      publishedAt: cveData.published_at,
    });

    const pubYear = cveData.published_at
      ? new Date(cveData.published_at).getUTCFullYear()
      : null;

    await db.query(`
      INSERT INTO cves (
        cve_id, description, published_at, last_modified_at,
        cvss_v3_score, cvss_v3_vector, cvss_v2_score, severity,
        epss_score, epss_percentile, in_cisa_kev, cisa_kev_date_added, cisa_kev_due_date,
        cve_references, weaknesses, affected_cpe, priority_score, published_year,
        source, epss_updated_at, nvd_synced_at, synced_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW(),NOW(),NOW())
      ON CONFLICT (cve_id) DO UPDATE SET
        description          = EXCLUDED.description,
        last_modified_at     = EXCLUDED.last_modified_at,
        cvss_v3_score        = EXCLUDED.cvss_v3_score,
        cvss_v3_vector       = EXCLUDED.cvss_v3_vector,
        cvss_v2_score        = EXCLUDED.cvss_v2_score,
        severity             = EXCLUDED.severity,
        epss_score           = EXCLUDED.epss_score,
        epss_percentile      = EXCLUDED.epss_percentile,
        in_cisa_kev          = EXCLUDED.in_cisa_kev,
        cisa_kev_date_added  = EXCLUDED.cisa_kev_date_added,
        cisa_kev_due_date    = EXCLUDED.cisa_kev_due_date,
        cve_references       = EXCLUDED.cve_references,
        weaknesses           = EXCLUDED.weaknesses,
        affected_cpe         = EXCLUDED.affected_cpe,
        priority_score       = EXCLUDED.priority_score,
        published_year       = EXCLUDED.published_year,
        source               = CASE WHEN cves.source = 'circl' THEN 'merged' ELSE 'nvd' END,
        epss_updated_at      = NOW(),
        nvd_synced_at        = NOW(),
        synced_at            = NOW()
    `, [
      cveData.cve_id,
      cveData.description,
      cveData.published_at,
      cveData.last_modified_at,
      cveData.cvss_v3_score,
      cveData.cvss_v3_vector,
      cveData.cvss_v2_score,
      cveData.severity,
      epssInfo.score,
      epssInfo.percentile,
      kevInfo.inKev,
      kevInfo.details?.dateAdded || null,
      kevInfo.details?.dueDate   || null,
      JSON.stringify(cveData.references),
      JSON.stringify(cveData.weaknesses),
      JSON.stringify(cveData.affected_cpe),
      priorityScore,
      pubYear,
      'nvd',
    ]);

    // Link product ↔ CVE, recording how confident the match is
    const { confidence, reason } = cveData._matchResult;
    await db.query(`
      INSERT INTO product_cves (product_id, cve_id, match_confidence, match_reason)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (product_id, cve_id) DO UPDATE SET
        match_confidence = EXCLUDED.match_confidence,
        match_reason     = EXCLUDED.match_reason
    `, [productId, cveData.cve_id, confidence, reason.substring(0, 500)]);
  }

  // ── Update product stats ──────────────────────────────────────────────────
  const statsResult = await db.query(`
    SELECT
      COUNT(*) as total,
      COUNT(*) FILTER (WHERE c.severity = 'CRITICAL') as critical
    FROM product_cves pc
    JOIN cves c ON c.cve_id = pc.cve_id
    WHERE pc.product_id = $1
  `, [productId]);

  const stats = statsResult.rows[0];
  await db.query(`
    UPDATE products
    SET last_synced_at = NOW(), cve_count = $1, critical_count = $2, updated_at = NOW()
    WHERE id = $3
  `, [parseInt(stats.total), parseInt(stats.critical), productId]);

  await cache.delPattern('dashboard:*');
  await cache.delPattern(`cves:product:${productId}*`);

  console.log(
    `Sync complete: ${product.name} — ${filteredCves.length} CVEs linked` +
    (filteredCount ? `, ${filteredCount} filtered by version range` : '')
  );
  return { synced: filteredCves.length, filtered: filteredCount };
}

module.exports = { syncProduct };
