BEGIN;

CREATE TABLE IF NOT EXISTS canonical_programs (
  id BIGSERIAL PRIMARY KEY,
  canonical_name TEXT NOT NULL,
  website TEXT,
  tags TEXT[] DEFAULT '{}'::TEXT[],
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(lower(canonical_name))
);

CREATE TABLE IF NOT EXISTS program_identities (
  id BIGSERIAL PRIMARY KEY,
  canonical_id BIGINT NOT NULL REFERENCES canonical_programs(id) ON DELETE CASCADE,
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  handle TEXT,
  name TEXT,
  website TEXT,
  confidence INT NOT NULL DEFAULT 0,
  reasons JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id)
);

CREATE INDEX IF NOT EXISTS idx_program_identities_canonical
  ON program_identities(canonical_id);

CREATE TABLE IF NOT EXISTS program_fingerprints (
  id BIGSERIAL PRIMARY KEY,
  canonical_id BIGINT NOT NULL REFERENCES canonical_programs(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  weight INT NOT NULL DEFAULT 10,
  source TEXT NOT NULL DEFAULT 'derived',
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(canonical_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_program_fingerprints_kind_value
  ON program_fingerprints(kind, value);

CREATE OR REPLACE VIEW v_canonical_overview AS
WITH ident AS (
  SELECT
    pi.canonical_id,
    jsonb_agg(jsonb_build_object(
      'platform', pi.platform,
      'program_external_id', pi.program_external_id,
      'handle', pi.handle,
      'name', pi.name,
      'website', pi.website,
      'confidence', pi.confidence
    ) ORDER BY pi.platform, pi.program_external_id) AS identities
  FROM program_identities pi
  GROUP BY pi.canonical_id
),
domains AS (
  SELECT
    pf.canonical_id,
    jsonb_agg(pf.value ORDER BY pf.value) AS domains
  FROM program_fingerprints pf
  WHERE pf.kind = 'domain'
  GROUP BY pf.canonical_id
),
targets_count AS (
  SELECT
    pi.canonical_id,
    jsonb_agg(jsonb_build_object(
      'platform', pi.platform,
      'program_external_id', pi.program_external_id,
      'targets', COALESCE(tcnt.cnt, 0)
    ) ORDER BY pi.platform, pi.program_external_id) AS targets_by_identity
  FROM program_identities pi
  LEFT JOIN (
    SELECT platform, program_external_id, count(*) AS cnt
    FROM targets
    GROUP BY platform, program_external_id
  ) tcnt ON tcnt.platform = pi.platform AND tcnt.program_external_id = pi.program_external_id
  GROUP BY pi.canonical_id
)
SELECT
  c.id AS canonical_id,
  c.canonical_name,
  c.website,
  c.tags,
  c.first_seen_at,
  c.last_seen_at,
  i.identities,
  d.domains,
  t.targets_by_identity
FROM canonical_programs c
LEFT JOIN ident i ON i.canonical_id = c.id
LEFT JOIN domains d ON d.canonical_id = c.id
LEFT JOIN targets_count t ON t.canonical_id = c.id;

COMMIT;
