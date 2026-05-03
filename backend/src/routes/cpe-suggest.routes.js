const express = require('express');
const router = express.Router();
const { suggestCpes } = require('../services/cpe-suggest.service');

// GET /api/cpe-suggest?q=windows+10&limit=10
router.get('/', async (req, res) => {
  const { q, limit = 15 } = req.query;
  if (!q || q.trim().length < 2) return res.json([]);
  try {
    const results = await suggestCpes(q, { limit: Math.min(20, parseInt(limit)) });
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
