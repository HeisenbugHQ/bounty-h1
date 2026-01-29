BEGIN;

CREATE TABLE IF NOT EXISTS surface_findings (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'hackerone',
  program_external_id TEXT NOT NULL,
  target_id BIGINT REFERENCES targets(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  category TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  confidence INT NOT NULL DEFAULT 50,
  severity INT NOT NULL DEFAULT 10,
  evidence JSONB,
  status TEXT NOT NULL DEFAULT 'new',
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id, url, category, rule_id)
);

ALTER TABLE surface_findings
  ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'hackerone';
ALTER TABLE surface_findings
  ADD COLUMN IF NOT EXISTS program_external_id TEXT NOT NULL DEFAULT '';
ALTER TABLE surface_findings
  ADD COLUMN IF NOT EXISTS category TEXT;
ALTER TABLE surface_findings
  ADD COLUMN IF NOT EXISTS rule_id TEXT;
ALTER TABLE surface_findings
  ADD COLUMN IF NOT EXISTS severity INT NOT NULL DEFAULT 10;
ALTER TABLE surface_findings
  ADD COLUMN IF NOT EXISTS evidence JSONB;
ALTER TABLE surface_findings
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'new';

CREATE UNIQUE INDEX IF NOT EXISTS uq_surface_findings_rule
  ON surface_findings(platform, program_external_id, url, category, rule_id);

CREATE INDEX IF NOT EXISTS idx_surface_findings_program
  ON surface_findings(platform, program_external_id);
CREATE INDEX IF NOT EXISTS idx_surface_findings_status
  ON surface_findings(status);
CREATE INDEX IF NOT EXISTS idx_surface_findings_category
  ON surface_findings(category);
CREATE INDEX IF NOT EXISTS idx_surface_findings_conf
  ON surface_findings(confidence DESC);

CREATE OR REPLACE VIEW v_surface_top AS
SELECT
  p.handle AS program_handle,
  t.host,
  f.url,
  f.category,
  f.confidence,
  f.severity,
  f.status,
  h.status_code,
  h.title,
  h.content_type,
  h.final_url,
  f.last_seen_at
FROM surface_findings f
LEFT JOIN targets t ON t.id=f.target_id
LEFT JOIN programs p ON p.platform=f.platform AND p.external_id=f.program_external_id
LEFT JOIN v_latest_http_by_target h ON h.target_id=t.id;

COMMIT;
