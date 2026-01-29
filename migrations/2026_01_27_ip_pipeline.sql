BEGIN;

-- IP seed inputs: active assets of type ip/cidr/asn
CREATE OR REPLACE VIEW v_ip_seeds AS
SELECT
  a.platform,
  a.program_external_id,
  a.asset_type,
  a.value,
  a.tags,
  a.note,
  a.status,
  a.first_seen_at,
  a.last_seen_at
FROM assets a
WHERE a.status = 'active'
  AND a.asset_type IN ('ip','cidr','asn');

-- IP discovery queue (new pipeline entry point)
CREATE TABLE IF NOT EXISTS ip_discovery_queue (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'manual',
  program_external_id TEXT NOT NULL,
  seed_type TEXT NOT NULL,
  seed_value TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  tries INT NOT NULL DEFAULT 0,
  last_error TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_ip_discovery_queue UNIQUE (platform, program_external_id, seed_type, seed_value),
  CONSTRAINT chk_ip_discovery_seed_type CHECK (seed_type IN ('ip','cidr','asn'))
);

CREATE INDEX IF NOT EXISTS idx_ip_discovery_queue_status
  ON ip_discovery_queue(status);

CREATE INDEX IF NOT EXISTS idx_ip_discovery_queue_program
  ON ip_discovery_queue(platform, program_external_id);

-- Latest IP assets discovered per program
CREATE TABLE IF NOT EXISTS ip_assets_latest (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'manual',
  program_external_id TEXT NOT NULL,
  ip INET NOT NULL,
  source TEXT NOT NULL,
  asn INT,
  asn_org TEXT,
  rdns TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_ip_assets_latest UNIQUE (platform, program_external_id, ip),
  CONSTRAINT chk_ip_assets_source CHECK (source IN ('seed_ip','cidr','asn','rdns'))
);

CREATE INDEX IF NOT EXISTS idx_ip_assets_latest_program
  ON ip_assets_latest(platform, program_external_id);

CREATE INDEX IF NOT EXISTS idx_ip_assets_latest_asn
  ON ip_assets_latest(asn);

COMMIT;
