-- CVE data load management migration.
-- Implements: sync_jobs queue, products sync status, cves source/staleness tracking,
-- published_year generated column, EPSS history, and optimised indexes.
-- Designed from backend-architect + database-architect agent recommendations.

-- ── 1. cves table additions ───────────────────────────────────────────────────

ALTER TABLE cves
  ADD COLUMN IF NOT EXISTS source        TEXT NOT NULL DEFAULT 'nvd',
  ADD COLUMN IF NOT EXISTS epss_updated_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS kev_updated_at    TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS nvd_synced_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS circl_synced_at   TIMESTAMPTZ;

-- published_year: regular column populated at upsert time (no generated column —
-- EXTRACT on TIMESTAMPTZ is timezone-dependent, hence not IMMUTABLE in PG).
ALTER TABLE cves ADD COLUMN IF NOT EXISTS published_year SMALLINT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_cve_source'
  ) THEN
    ALTER TABLE cves ADD CONSTRAINT chk_cve_source
      CHECK (source IN ('nvd','circl','merged','manual'));
  END IF;
END $$;

-- ── 2. products sync status ───────────────────────────────────────────────────

ALTER TABLE products
  ADD COLUMN IF NOT EXISTS sync_status        TEXT NOT NULL DEFAULT 'never',
  ADD COLUMN IF NOT EXISTS sync_started_at    TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sync_finished_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sync_error         TEXT,
  ADD COLUMN IF NOT EXISTS sync_cves_fetched  INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS sync_cves_linked   INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_product_sync_status'
  ) THEN
    ALTER TABLE products ADD CONSTRAINT chk_product_sync_status
      CHECK (sync_status IN ('never','pending','running','done','failed'));
  END IF;
END $$;

-- ── 3. sync_jobs queue ───────────────────────────────────────────────────────
-- DB-backed job queue — no BullMQ needed. Worker uses FOR UPDATE SKIP LOCKED.

CREATE TABLE IF NOT EXISTS sync_jobs (
  id              BIGSERIAL    PRIMARY KEY,
  job_type        TEXT         NOT NULL,   -- 'product_sync' | 'epss_refresh' | 'kev_refresh'
  target_id       UUID,                    -- product id for product_sync
  status          TEXT         NOT NULL DEFAULT 'pending',
  priority        INTEGER      NOT NULL DEFAULT 100,   -- lower = runs sooner
  attempts        INTEGER      NOT NULL DEFAULT 0,
  max_attempts    INTEGER      NOT NULL DEFAULT 3,
  scheduled_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  cves_fetched    INTEGER      DEFAULT 0,
  cves_filtered   INTEGER      DEFAULT 0,
  cves_linked     INTEGER      DEFAULT 0,
  error_message   TEXT,
  locked_by       TEXT,
  locked_until    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  DEFAULT NOW(),
  updated_at      TIMESTAMPTZ  DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_sync_job_status'
  ) THEN
    ALTER TABLE sync_jobs ADD CONSTRAINT chk_sync_job_status
      CHECK (status IN ('pending','running','done','failed','dead'));
  END IF;
END $$;

-- Pickup index: worker claims oldest pending/failed job
CREATE INDEX IF NOT EXISTS idx_sync_jobs_pickup
  ON sync_jobs (status, priority ASC, scheduled_at ASC)
  WHERE status IN ('pending','failed');

-- Prevent duplicate active jobs per product
CREATE UNIQUE INDEX IF NOT EXISTS uq_sync_jobs_active
  ON sync_jobs (job_type, target_id)
  WHERE status IN ('pending','running');

-- ── 4. EPSS history (time-series) ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS epss_history (
  cve_id          TEXT         NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  scored_on       DATE         NOT NULL,
  epss_score      NUMERIC(6,5) NOT NULL,
  epss_percentile NUMERIC(6,5) NOT NULL,
  recorded_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  PRIMARY KEY (cve_id, scored_on)
);

CREATE INDEX IF NOT EXISTS idx_epss_history_latest
  ON epss_history (cve_id, scored_on DESC);

-- ── 5. Performance indexes ────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_cves_severity_published
  ON cves (severity, published_at DESC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_cves_published_year
  ON cves (published_year)
  WHERE published_year IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cves_kev_partial
  ON cves (cisa_kev_date_added DESC)
  WHERE in_cisa_kev = TRUE;

CREATE INDEX IF NOT EXISTS idx_cves_epss_refresh
  ON cves (epss_updated_at NULLS FIRST, priority_score DESC);

CREATE INDEX IF NOT EXISTS idx_cves_source
  ON cves (source);

CREATE INDEX IF NOT EXISTS idx_products_sync_status
  ON products (sync_status, sync_started_at DESC)
  WHERE sync_status IN ('pending','running','failed');

CREATE INDEX IF NOT EXISTS idx_product_cves_cve_status
  ON product_cves (cve_id, status);
