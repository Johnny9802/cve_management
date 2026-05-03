-- Add version-range match metadata to the product↔CVE link table.
--
-- match_confidence:
--   'certain'   - CPE vendor:product matched; version range evaluated precisely
--   'uncertain' - no CPE data or vendor:product could not be identified;
--                 CVE included conservatively to avoid false negatives
--   'cpe_search'- product was synced via NVD CPE search (NVD handled matching)
--
-- match_reason: short explanation string from the version matcher, stored
-- for debugging and future manual-review workflows.

ALTER TABLE product_cves
  ADD COLUMN IF NOT EXISTS match_confidence TEXT    DEFAULT 'uncertain',
  ADD COLUMN IF NOT EXISTS match_reason     TEXT;

CREATE INDEX IF NOT EXISTS idx_product_cves_confidence
  ON product_cves(match_confidence);
