BEGIN;

ALTER TABLE http_observations
  ADD COLUMN IF NOT EXISTS headers_security JSONB,
  ADD COLUMN IF NOT EXISTS headers_cors JSONB,
  ADD COLUMN IF NOT EXISTS headers_infra JSONB,
  ADD COLUMN IF NOT EXISTS set_cookie_names TEXT[],
  ADD COLUMN IF NOT EXISTS set_cookie_flags JSONB;

CREATE OR REPLACE VIEW v_latest_http_by_target AS
SELECT DISTINCT ON (target_id)
  target_id,
  scheme, port, url, final_url,
  status_code, title, server_header,
  content_type, content_length,
  ip, cname, cdn, favicon_mmh3,
  headers_selected,
  headers_security, headers_cors, headers_infra,
  set_cookie_names, set_cookie_flags,
  observed_at
FROM http_observations
ORDER BY target_id, observed_at DESC;

COMMIT;
