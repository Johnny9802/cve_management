const express = require('express');
const router = express.Router();
const db = require('../database/postgres');
const cache = require('../services/cache.service');
const config = require('../config/config');

// GET /api/dashboard — main stats
router.get('/', async (req, res) => {
  try {
    const cacheKey = 'dashboard:stats';
    const cached = await cache.get(cacheKey);
    if (cached) return res.json(cached);

    const [totalCves, severityBreakdown, kevCount, topProducts, recentCves, epssDistrib, priorityBreakdown] = await Promise.all([
      db.query('SELECT COUNT(*) FROM cves'),
      db.query(`
        SELECT severity, COUNT(*) as count
        FROM cves
        GROUP BY severity
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
      `),
      db.query('SELECT COUNT(*) FROM cves WHERE in_cisa_kev = true'),
      db.query(`
        SELECT p.id, p.name, p.version, p.vendor, p.cve_count, p.critical_count, p.last_synced_at
        FROM products p
        ORDER BY p.critical_count DESC, p.cve_count DESC
        LIMIT 10
      `),
      db.query(`
        SELECT cve_id, severity, cvss_v3_score, epss_score, priority_score, published_at, description, in_cisa_kev
        FROM cves
        ORDER BY published_at DESC NULLS LAST
        LIMIT 10
      `),
      db.query(`
        SELECT
          SUM(CASE WHEN epss_score >= 0.5 THEN 1 ELSE 0 END) as high_epss,
          SUM(CASE WHEN epss_score >= 0.1 AND epss_score < 0.5 THEN 1 ELSE 0 END) as medium_epss,
          SUM(CASE WHEN epss_score < 0.1 THEN 1 ELSE 0 END) as low_epss
        FROM cves WHERE epss_score IS NOT NULL
      `),
      db.query(`
        SELECT
          SUM(CASE WHEN priority_score >= 80 THEN 1 ELSE 0 END) as critical_priority,
          SUM(CASE WHEN priority_score >= 60 AND priority_score < 80 THEN 1 ELSE 0 END) as high_priority,
          SUM(CASE WHEN priority_score >= 40 AND priority_score < 60 THEN 1 ELSE 0 END) as medium_priority,
          SUM(CASE WHEN priority_score < 40 THEN 1 ELSE 0 END) as monitor
        FROM cves
      `),
    ]);

    const result = {
      total_cves: parseInt(totalCves.rows[0].count),
      kev_count: parseInt(kevCount.rows[0].count),
      severity: severityBreakdown.rows,
      top_products: topProducts.rows,
      recent_cves: recentCves.rows,
      epss_distribution: epssDistrib.rows[0],
      priority_distribution: priorityBreakdown.rows[0],
      product_count: (await db.query('SELECT COUNT(*) FROM products')).rows[0].count,
    };

    await cache.set(cacheKey, result, config.cache.ttl.dashboard);
    res.json(result);
  } catch (err) {
    console.error('Dashboard error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/dashboard/timeline — CVEs by month for chart
router.get('/timeline', async (req, res) => {
  try {
    const cacheKey = 'dashboard:timeline';
    const cached = await cache.get(cacheKey);
    if (cached) return res.json(cached);

    const { rows } = await db.query(`
      SELECT
        TO_CHAR(published_at, 'YYYY-MM') as month,
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
        COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
        COUNT(*) FILTER (WHERE in_cisa_kev = true) as kev
      FROM cves
      WHERE published_at >= NOW() - INTERVAL '12 months'
      GROUP BY month
      ORDER BY month ASC
    `);

    await cache.set(cacheKey, rows, config.cache.ttl.dashboard);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
