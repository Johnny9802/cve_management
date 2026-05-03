-- Finding lifecycle and governance fields.
--
-- Upgrades product_cves from a simple join table into a full finding entity.
-- Every product↔CVE link is now a "finding" with a trackable lifecycle.
--
-- Status lifecycle:
--   open → in_review → false_positive
--                    → accepted_risk   (requires reason + expiry)
--                    → planned         (requires due date)
--                    → remediated → closed
--
-- Fields added here are intentionally nullable so existing rows are unaffected
-- and no backfill is required.

ALTER TABLE product_cves
  ADD COLUMN IF NOT EXISTS status                TEXT    NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS first_seen            TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS last_seen             TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS owner                 TEXT,
  ADD COLUMN IF NOT EXISTS remediation_due_date  DATE,
  ADD COLUMN IF NOT EXISTS remediation_notes     TEXT,
  ADD COLUMN IF NOT EXISTS risk_acceptance_reason TEXT,
  ADD COLUMN IF NOT EXISTS risk_acceptance_expiry DATE,
  ADD COLUMN IF NOT EXISTS evidence_url          TEXT,
  ADD COLUMN IF NOT EXISTS closed_at             TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_breached          BOOLEAN DEFAULT FALSE;

-- Constrain valid statuses at the DB level so no invalid value can enter.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_finding_status'
  ) THEN
    ALTER TABLE product_cves
      ADD CONSTRAINT chk_finding_status CHECK (
        status IN ('open','in_review','false_positive','accepted_risk','planned','remediated','closed')
      );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_product_cves_status   ON product_cves(status);
CREATE INDEX IF NOT EXISTS idx_product_cves_owner    ON product_cves(owner);
CREATE INDEX IF NOT EXISTS idx_product_cves_due      ON product_cves(remediation_due_date);
CREATE INDEX IF NOT EXISTS idx_product_cves_sla      ON product_cves(sla_breached) WHERE sla_breached = TRUE;

-- Findings history: immutable audit log of every status change.
CREATE TABLE IF NOT EXISTS findings_history (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  product_id    UUID  NOT NULL REFERENCES products(id)  ON DELETE CASCADE,
  cve_id        TEXT  NOT NULL REFERENCES cves(cve_id)  ON DELETE CASCADE,
  changed_at    TIMESTAMPTZ DEFAULT NOW(),
  old_status    TEXT,
  new_status    TEXT NOT NULL,
  actor         TEXT,
  note          TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_history_product ON findings_history(product_id);
CREATE INDEX IF NOT EXISTS idx_findings_history_cve     ON findings_history(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_history_ts      ON findings_history(changed_at DESC);
