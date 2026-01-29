BEGIN;

CREATE TABLE IF NOT EXISTS surface_findings (
  id BIGSERIAL PRIMARY KEY,
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  finding_type TEXT NOT NULL,
  url TEXT NOT NULL,
  confidence INT NOT NULL DEFAULT 0,
  reasons JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(target_id, finding_type, url)
);

COMMIT;
