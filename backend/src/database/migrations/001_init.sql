-- CVE Management Platform - Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Products tracked by the user
CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  vendor TEXT,
  cpe_keyword TEXT,           -- keyword used to search NVD
  last_synced_at TIMESTAMPTZ,
  cve_count INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(name, version)
);

-- CVEs fetched from NVD
CREATE TABLE IF NOT EXISTS cves (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  cve_id TEXT UNIQUE NOT NULL,
  description TEXT,
  published_at TIMESTAMPTZ,
  last_modified_at TIMESTAMPTZ,
  cvss_v3_score NUMERIC(4,1),
  cvss_v3_vector TEXT,
  cvss_v2_score NUMERIC(4,1),
  severity TEXT,              -- CRITICAL, HIGH, MEDIUM, LOW, NONE
  epss_score NUMERIC(10,9),   -- 0.0 to 1.0
  epss_percentile NUMERIC(10,9),
  in_cisa_kev BOOLEAN DEFAULT FALSE,
  cisa_kev_date_added DATE,
  cisa_kev_due_date DATE,
  cve_references JSONB DEFAULT '[]',
  weaknesses JSONB DEFAULT '[]',
  affected_cpe JSONB DEFAULT '[]',
  priority_score INTEGER DEFAULT 0,  -- 0-100 computed score
  synced_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_v3_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(in_cisa_kev);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cves_priority ON cves(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_description_trgm ON cves USING gin(description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cves_id_trgm ON cves USING gin(cve_id gin_trgm_ops);

-- Many-to-many: products <-> cves
CREATE TABLE IF NOT EXISTS product_cves (
  product_id UUID REFERENCES products(id) ON DELETE CASCADE,
  cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
  matched_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (product_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_product_cves_product ON product_cves(product_id);
CREATE INDEX IF NOT EXISTS idx_product_cves_cve ON product_cves(cve_id);
