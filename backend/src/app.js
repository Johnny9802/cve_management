require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { runMigrations } = require('./database/postgres');
const { loadKev } = require('./services/cisa-kev.service');
const syncWorker = require('./services/sync-worker.service');
const config = require('./config/config');

const app = express();

// CORS: allow only the configured frontend origin, not the entire internet.
// Set ALLOWED_ORIGIN in .env for production. Defaults to localhost dev server.
const allowedOrigin = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';
app.use(cors({
  origin: allowedOrigin,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
}));

// JSON body: 200 KB ceiling — bulk imports should use the /bulk endpoint,
// not raw payloads. 1 MB was too permissive and enabled DoS via large bodies.
app.use(express.json({ limit: '200kb' }));

// Rate limiters applied before route registration so they fire first.
// Live search proxies NVD; excessive calls exhaust the shared API key quota.
const liveLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Troppe richieste NVD. Attendi un momento e riprova.' },
});

// Bulk import spawns one NVD sync per product row — throttle aggressively.
const bulkLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Troppi import ravvicinati. Attendi un minuto.' },
});

app.use('/api/live', liveLimiter);
app.use('/api/products/bulk', bulkLimiter);
app.use('/api/products/resync-all', rateLimit({ windowMs: 300_000, max: 1, message: { error: 'Re-sync già in corso, attendi 5 minuti.' } }));

app.use('/api/system', require('./routes/system.routes'));
app.use('/api/products', require('./routes/products.routes'));
app.use('/api/cves', require('./routes/cve.routes'));
app.use('/api/findings', require('./routes/findings.routes'));
app.use('/api/dashboard', require('./routes/dashboard.routes'));
app.use('/api/live', require('./routes/live.routes'));
app.use('/api/circl', require('./routes/circl.routes'));
app.use('/api/cpe-suggest', require('./routes/cpe-suggest.routes'));

app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

async function start() {
  try {
    await runMigrations();
    console.log('Database migrations complete');

    loadKev().catch((e) => console.error('KEV preload failed:', e.message));
    syncWorker.start();

    app.listen(config.port, () => {
      console.log(`Backend running on port ${config.port}`);
      console.log(`CORS allowed origin: ${allowedOrigin}`);
      if (!process.env.NVD_API_KEY) {
        console.warn('NVD_API_KEY not set — rate limit: 5 req/30s (slower syncs)');
      }
    });
  } catch (err) {
    console.error('Startup error:', err.message);
    process.exit(1);
  }
}

start();
