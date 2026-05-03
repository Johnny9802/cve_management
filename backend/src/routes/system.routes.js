const express = require('express');
const router = express.Router();
const { checkAll, checkOne } = require('../services/status.service');
const { listConfig, setConfig } = require('../services/config.service');

// GET /api/system/status — probe all (or one) external/internal APIs
// ?service=nvd|circl|epss|kev|redis|database  (optional: single probe)
router.get('/status', async (req, res) => {
  try {
    const { service } = req.query;
    if (service) {
      const result = await checkOne(service);
      res.json({ [service]: result, checked_at: new Date().toISOString() });
    } else {
      const status = await checkAll();
      res.json(status);
    }
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// GET /api/system/config — list all config keys (sensitive values masked)
router.get('/config', async (req, res) => {
  try {
    const items = await listConfig();
    res.json({ items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/system/config — update a config key
// Body: { key: string, value: string | null }
router.patch('/config', async (req, res) => {
  const { key, value } = req.body;
  if (!key) return res.status(400).json({ error: '"key" is required' });
  try {
    const result = await setConfig(key, value, 'gui');
    res.json(result);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

module.exports = router;
