const express = require('express');
const router = express.Router();
const db = require('../database/postgres');
const cache = require('../services/cache.service');
const config = require('../config/config');
const { fetchCveById } = require('../services/nvd.service');
const { fetchEpssScores } = require('../services/epss.service');
const { enrichWithKev } = require('../services/cisa-kev.service');
const { computePriorityScore } = require('../services/priority.service');

// GET /api/cves — paginated list with filters
router.get('/', async (req, res) => {
  try {
    const {
      product_id,
      severity,
      kev,
      min_epss,
      max_epss,
      min_priority,
      keyword,
      year,
      sort = 'priority_score',
      order = 'desc',
      page = 1,
      limit = 50,
    } = req.query;

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(200, Math.max(1, parseInt(limit)));
    const offset = (pageNum - 1) * limitNum;

    const conditions = [];
    const params = [];
    let p = 1;

    if (product_id) {
      conditions.push(`pc.product_id = $${p++}`);
      params.push(product_id);
    }
    if (severity) {
      const severities = severity.split(',').map((s) => s.trim().toUpperCase());
      conditions.push(`c.severity = ANY($${p++})`);
      params.push(severities);
    }
    if (kev === 'true') {
      conditions.push(`c.in_cisa_kev = true`);
    }
    if (min_epss) {
      conditions.push(`c.epss_score >= $${p++}`);
      params.push(parseFloat(min_epss));
    }
    if (max_epss) {
      conditions.push(`c.epss_score <= $${p++}`);
      params.push(parseFloat(max_epss));
    }
    if (min_priority) {
      conditions.push(`c.priority_score >= $${p++}`);
      params.push(parseInt(min_priority));
    }
    if (year) {
      conditions.push(`EXTRACT(YEAR FROM c.published_at) = $${p++}`);
      params.push(parseInt(year));
    }
    if (keyword) {
      conditions.push(`(c.cve_id ILIKE $${p} OR c.description ILIKE $${p})`);
      params.push(`%${keyword}%`);
      p++;
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const joinClause = product_id ? `JOIN product_cves pc ON pc.cve_id = c.cve_id` : 'LEFT JOIN product_cves pc ON pc.cve_id = c.cve_id';

    const validSorts = ['priority_score', 'cvss_v3_score', 'epss_score', 'published_at', 'cve_id'];
    const sortCol = validSorts.includes(sort) ? sort : 'priority_score';
    const sortOrder = order === 'asc' ? 'ASC' : 'DESC';

    // When filtering by product, surface the match confidence from product_cves
    // so the frontend can flag uncertain keyword-matched findings for review.
    const dataQuery = product_id ? `
      SELECT c.*, pc.match_confidence, pc.status AS finding_status, pc.owner
      FROM cves c
      JOIN product_cves pc ON pc.cve_id = c.cve_id
      ${whereClause}
      ORDER BY c.${sortCol} ${sortOrder} NULLS LAST
      LIMIT $${p++} OFFSET $${p++}
    ` : `
      SELECT c.*
      FROM cves c
      ${whereClause}
      ORDER BY c.${sortCol} ${sortOrder} NULLS LAST
      LIMIT $${p++} OFFSET $${p++}
    `;
    params.push(limitNum, offset);

    const countQuery = `
      SELECT COUNT(DISTINCT c.cve_id)
      FROM cves c
      ${product_id ? `JOIN product_cves pc ON pc.cve_id = c.cve_id` : ''}
      ${whereClause}
    `;

    const [dataResult, countResult] = await Promise.all([
      db.query(dataQuery, params),
      db.query(countQuery, params.slice(0, -2)),
    ]);

    res.json({
      data: dataResult.rows,
      total: parseInt(countResult.rows[0].count),
      page: pageNum,
      limit: limitNum,
      pages: Math.ceil(parseInt(countResult.rows[0].count) / limitNum),
    });
  } catch (err) {
    console.error('CVE list error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/cves/export — download all matching CVEs as CSV
router.get('/export', async (req, res) => {
  try {
    const { product_id, severity, kev, min_epss, min_priority, keyword, year } = req.query;

    const conditions = [];
    const params = [];
    let p = 1;

    if (product_id) { conditions.push(`pc.product_id = $${p++}`); params.push(product_id); }
    if (severity) { conditions.push(`c.severity = ANY($${p++})`); params.push(severity.split(',').map(s => s.trim().toUpperCase())); }
    if (kev === 'true') conditions.push(`c.in_cisa_kev = true`);
    if (min_epss) { conditions.push(`c.epss_score >= $${p++}`); params.push(parseFloat(min_epss)); }
    if (min_priority) { conditions.push(`c.priority_score >= $${p++}`); params.push(parseInt(min_priority)); }
    if (year) { conditions.push(`EXTRACT(YEAR FROM c.published_at) = $${p++}`); params.push(parseInt(year)); }
    if (keyword) { conditions.push(`(c.cve_id ILIKE $${p} OR c.description ILIKE $${p})`); params.push(`%${keyword}%`); p++; }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const { rows } = await db.query(`
      SELECT DISTINCT
        c.cve_id, c.severity, c.cvss_v3_score, c.cvss_v2_score,
        c.epss_score, c.epss_percentile, c.in_cisa_kev,
        c.cisa_kev_date_added, c.cisa_kev_due_date,
        c.priority_score, c.published_at, c.last_modified_at,
        c.description, c.weaknesses
      FROM cves c
      ${product_id ? `JOIN product_cves pc ON pc.cve_id = c.cve_id` : ''}
      ${whereClause}
      ORDER BY c.priority_score DESC NULLS LAST
      LIMIT 10000
    `, params);

    const headers = [
      'CVE ID', 'Severità', 'CVSS v3', 'CVSS v2', 'EPSS Score', 'EPSS Percentile',
      'CISA KEV', 'KEV Date Added', 'KEV Due Date',
      'Priority Score', 'Pubblicato', 'Ultima modifica', 'Descrizione', 'CWE'
    ];

    const escape = (v) => {
      if (v == null) return '';
      let s = String(v);
      // Prevent spreadsheet formula injection: Excel/LibreOffice execute cells
      // that begin with =, +, -, @, tab, or carriage-return as formulas.
      if (s.length > 0 && ['=', '+', '-', '@', '\t', '\r'].includes(s[0])) {
        s = "'" + s;
      }
      s = s.replace(/"/g, '""');
      return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s}"` : s;
    };

    const lines = [headers.join(',')];
    for (const r of rows) {
      lines.push([
        r.cve_id,
        r.severity,
        r.cvss_v3_score ?? '',
        r.cvss_v2_score ?? '',
        r.epss_score != null ? (parseFloat(r.epss_score) * 100).toFixed(4) + '%' : '',
        r.epss_percentile != null ? (parseFloat(r.epss_percentile) * 100).toFixed(2) + '%' : '',
        r.in_cisa_kev ? 'SI' : 'NO',
        r.cisa_kev_date_added ?? '',
        r.cisa_kev_due_date ?? '',
        r.priority_score ?? '',
        r.published_at ? new Date(r.published_at).toISOString().split('T')[0] : '',
        r.last_modified_at ? new Date(r.last_modified_at).toISOString().split('T')[0] : '',
        escape(r.description),
        escape(Array.isArray(r.weaknesses) ? r.weaknesses.join('; ') : ''),
      ].join(','));
    }

    const csv = lines.join('\n');
    const filename = `cve-export-${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send('﻿' + csv); // BOM for Excel compatibility
  } catch (err) {
    console.error('CSV export error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/cves/:id — single CVE detail (DB first, fallback to NVD live)
router.get('/:id', async (req, res) => {
  try {
    const cveId = req.params.id.toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(cveId)) return res.status(400).json({ error: 'Formato CVE ID non valido' });

    const cacheKey = `cve:detail:${cveId}`;
    const cached = await cache.get(cacheKey);
    if (cached) return res.json(cached);

    // 1. Try local DB first
    const dbResult = await db.query('SELECT * FROM cves WHERE cve_id = $1', [cveId]);
    let cve = dbResult.rows[0] || null;
    let source = 'db';

    // 2. Fallback to NVD if not in DB (e.g. clicked from live search)
    if (!cve) {
      const nvdData = await fetchCveById(cveId);
      if (!nvdData) return res.status(404).json({ error: `${cveId} non trovato` });

      const [epssData, kevData] = await Promise.all([
        fetchEpssScores([cveId]),
        enrichWithKev([cveId]),
      ]);
      const epss = epssData[cveId] || { score: 0, percentile: 0 };
      const kev  = kevData[cveId]  || { inKev: false, details: null };

      cve = {
        ...nvdData,
        cve_references: nvdData.references || [],
        epss_score: epss.score,
        epss_percentile: epss.percentile,
        in_cisa_kev: kev.inKev,
        cisa_kev_date_added: kev.details?.dateAdded || null,
        cisa_kev_due_date:   kev.details?.dueDate   || null,
        priority_score: computePriorityScore({
          cvssScore: nvdData.cvss_v3_score,
          severity:  nvdData.severity,
          epssScore: epss.score,
          inKev:     kev.inKev,
          publishedAt: nvdData.published_at,
        }),
      };
      source = 'nvd_live';
    }

    // 3. Which local products are affected
    const productsResult = await db.query(`
      SELECT p.id, p.name, p.version, p.vendor
      FROM products p
      JOIN product_cves pc ON pc.product_id = p.id
      WHERE pc.cve_id = $1
    `, [cveId]);

    const result = { ...cve, affected_products: productsResult.rows, source };
    await cache.set(cacheKey, result, config.cache.ttl.cveDetail);
    res.json(result);
  } catch (err) {
    console.error('CVE detail error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
