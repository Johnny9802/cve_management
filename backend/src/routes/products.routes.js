const express = require('express');
const router = express.Router();
const db = require('../database/postgres');
const { enqueueProductSync } = require('../services/sync-worker.service');
const cache = require('../services/cache.service');

// GET /api/products — includes sync_status for UI badges
router.get('/', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT id, name, version, vendor, cpe_keyword,
             last_synced_at, cve_count, critical_count,
             sync_status, sync_started_at, sync_finished_at,
             sync_error, sync_cves_fetched, sync_cves_linked,
             created_at, updated_at
      FROM products
      ORDER BY critical_count DESC, cve_count DESC, name ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/products
router.post('/', async (req, res) => {
  const { name, version, vendor, cpe_keyword } = req.body;
  if (!name || !version) return res.status(400).json({ error: 'name and version are required' });

  try {
    const { rows } = await db.query(`
      INSERT INTO products (name, version, vendor, cpe_keyword)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `, [name.trim(), version.trim(), vendor?.trim() || null, cpe_keyword?.trim() || null]);

    const product = rows[0];
    // Enqueue with high priority (user just added it)
    await enqueueProductSync(product.id, 10);

    res.status(201).json({ ...product, syncing: true });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Product already exists' });
    res.status(500).json({ error: err.message });
  }
});

// POST /api/products/bulk
router.post('/bulk', async (req, res) => {
  const { products } = req.body;
  if (!Array.isArray(products) || products.length === 0) {
    return res.status(400).json({ error: 'products array is required' });
  }
  if (products.length > 500) {
    return res.status(400).json({ error: 'Maximum 500 products per bulk import. Split into smaller batches.' });
  }

  const results = { created: [], skipped: [], errors: [] };

  for (const p of products) {
    if (!p.name || !p.version) { results.errors.push({ ...p, reason: 'missing name or version' }); continue; }
    try {
      const { rows } = await db.query(`
        INSERT INTO products (name, version, vendor, cpe_keyword)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (name, version) DO NOTHING
        RETURNING *
      `, [p.name.trim(), p.version.trim(), p.vendor?.trim() || null, p.cpe_keyword?.trim() || null]);

      if (rows.length) {
        results.created.push(rows[0]);
        // Enqueue at normal priority; worker processes sequentially (safe for NVD rate limits)
        await enqueueProductSync(rows[0].id, 50);
      } else {
        results.skipped.push(p);
      }
    } catch (err) {
      results.errors.push({ ...p, reason: err.message });
    }
  }

  res.json(results);
});

// POST /api/products/resync-all — enqueue every product into the worker queue
router.post('/resync-all', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT id, name, version FROM products ORDER BY name ASC');
    if (!rows.length) return res.json({ message: 'No products to sync', count: 0 });

    let enqueued = 0;
    for (const p of rows) {
      const jobId = await enqueueProductSync(p.id, 100);
      if (jobId) enqueued++;
    }

    res.json({
      message: `Enqueued ${enqueued} product(s) for re-sync. The worker processes them sequentially.`,
      count: enqueued,
      total: rows.length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/products/:id
router.delete('/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM products WHERE id = $1', [req.params.id]);
    await cache.delPattern('dashboard:*');
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/products/:id/sync — queue a manual re-sync (high priority)
router.post('/:id/sync', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT id FROM products WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Product not found' });

    const jobId = await enqueueProductSync(req.params.id, 10);
    res.json({ syncing: true, job_id: jobId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/products/:id/sync-status
router.get('/:id/sync-status', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT p.sync_status, p.sync_started_at, p.sync_finished_at,
             p.sync_error, p.sync_cves_fetched, p.sync_cves_linked,
             p.last_synced_at, p.cve_count, p.critical_count,
             j.id as job_id, j.attempts, j.scheduled_at
      FROM products p
      LEFT JOIN sync_jobs j
        ON j.target_id = p.id AND j.job_type = 'product_sync'
        AND j.status IN ('pending','running')
      WHERE p.id = $1
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Product not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
