CREATE TABLE IF NOT EXISTS programs (
  platform TEXT NOT NULL,
  external_id TEXT NOT NULL,
  handle TEXT,
  name TEXT,
  offers_bounties BOOLEAN,
  raw_json JSONB,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (platform, external_id)
);

CREATE TABLE IF NOT EXISTS scopes (
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  asset_type TEXT,
  identifier TEXT NOT NULL,
  eligible_for_bounty BOOLEAN,
  eligible_for_submission BOOLEAN,
  instruction TEXT,
  raw_json JSONB,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (platform, program_external_id, identifier)
);

CREATE INDEX IF NOT EXISTS idx_scopes_identifier ON scopes(identifier);
CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(platform, program_external_id);
