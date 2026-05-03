const express = require('express');
const router = express.Router();
const {
  updateFindingStatus,
  getFindingHistory,
  getFindingStats,
  getOpenFindings,
} = require('../services/finding.service');
const cache = require('../services/cache.service');

// GET /api/findings/stats — governance KPI summary
router.get('/stats', async (req, res) => {
  try {
    const stats = await getFindingStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/findings — open remediation backlog
// ?status=open&owner=alice@example.com&page=1&limit=50
router.get('/', async (req, res) => {
  try {
    const { status, owner, page = 1, limit = 50 } = req.query;
    const rows = await getOpenFindings({
      status,
      owner,
      page: parseInt(page),
      limit: parseInt(limit),
    });
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/findings/:productId/:cveId — update finding status / governance fields
// Body: { status, owner, remediation_due_date, remediation_notes,
//         risk_acceptance_reason, risk_acceptance_expiry, evidence_url,
//         actor, note }
router.patch('/:productId/:cveId', async (req, res) => {
  try {
    const { productId, cveId } = req.params;
    const updated = await updateFindingStatus(productId, cveId.toUpperCase(), req.body);
    // Invalidate dashboard cache so stats reflect the change
    await cache.delPattern('dashboard:*');
    res.json(updated);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// GET /api/findings/:productId/:cveId/history — audit trail
router.get('/:productId/:cveId/history', async (req, res) => {
  try {
    const { productId, cveId } = req.params;
    const history = await getFindingHistory(productId, cveId.toUpperCase());
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
