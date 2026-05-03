-- Runtime API configuration storage.
-- Allows operators to set API keys from the GUI without redeploying.
-- NOTE: values are stored plaintext for now — encrypt-at-rest (pgcrypto/KMS) is a future TODO.
--       Keep this table access-controlled and never log its contents.

CREATE TABLE IF NOT EXISTS app_config (
  key        TEXT PRIMARY KEY,
  value      TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_app_config_updated_at ON app_config(updated_at DESC);

-- Pre-insert known keys with NULL values so listConfig always shows the full set.
INSERT INTO app_config (key, value) VALUES
  ('NVD_API_KEY',    NULL),
  ('ALLOWED_ORIGIN', NULL)
ON CONFLICT (key) DO NOTHING;
