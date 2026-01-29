BEGIN;

-- 1) SONAR: 1 riga = 1 host (targets + latest http)
CREATE OR REPLACE VIEW sonar AS
SELECT
  t.id AS id,
  t.platform,
  COALESCE(p.handle, t.program_external_id) AS program,
  t.source_scope_identifier AS subdomain_root,
  t.host,
  t.first_seen_at,
  t.last_seen_at,
  t.http_scanned_at,
  t.port_scanned_at,
  t.enriched_at,
  h.url,
  h.final_url,
  h.status_code,
  h.title,
  h.content_type,
  h.server_header,
  h.ip,
  h.cname,
  h.cdn,
  h.favicon_mmh3,
  h.observed_at AS http_observed_at
FROM targets t
LEFT JOIN programs p
  ON p.platform=t.platform AND p.external_id=t.program_external_id
LEFT JOIN v_latest_http_by_target h
  ON h.target_id=t.id;

-- 2) SONAR_HOST_LATEST: status new/active/old
CREATE OR REPLACE VIEW sonar_host_latest AS
SELECT
  t.id AS id,
  t.platform,
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  t.source_scope_identifier AS subdomain_root,
  t.first_seen_at,
  t.last_seen_at,
  CASE
    WHEN t.first_seen_at >= now() - interval '24 hours' THEN 'new'
    WHEN t.last_seen_at  <  now() - interval '30 days' THEN 'old'
    ELSE 'active'
  END AS status,
  h.url,
  h.final_url,
  h.status_code,
  h.title,
  h.content_type,
  h.content_length,
  h.ip,
  h.cname,
  h.cdn,
  h.server_header,
  h.headers_selected,
  h.observed_at AS http_observed_at
FROM targets t
LEFT JOIN programs p
  ON p.platform=t.platform AND p.external_id=t.program_external_id
LEFT JOIN v_latest_http_by_target h
  ON h.target_id=t.id;

-- 3) SONAR_HTTP_TIMELINE
CREATE OR REPLACE VIEW sonar_http_timeline AS
SELECT
  t.id AS id,
  t.platform,
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  o.url,
  o.final_url,
  o.status_code,
  o.title,
  o.content_type,
  o.content_length,
  o.ip,
  o.cname,
  o.cdn,
  o.server_header,
  o.headers_selected,
  o.observed_at
FROM http_observations o
JOIN targets t ON t.id=o.target_id
LEFT JOIN programs p
  ON p.platform=t.platform AND p.external_id=t.program_external_id;

-- 4) SONAR_PORTS
CREATE OR REPLACE VIEW sonar_ports AS
SELECT
  t.id AS id,
  t.platform,
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  pl.proto,
  pl.port,
  pl.state,
  pl.first_seen_at,
  pl.last_seen_at
FROM ports_latest pl
JOIN targets t ON t.id=pl.target_id
LEFT JOIN programs p
  ON p.platform=t.platform AND p.external_id=t.program_external_id;

-- 5) SONAR_SERVICES
CREATE OR REPLACE VIEW sonar_services AS
SELECT
  t.id AS id,
  t.platform,
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  ns.proto,
  ns.port,
  ns.service_name,
  ns.product,
  ns.version,
  ns.extra_info,
  ns.cpe,
  ns.first_seen_at,
  ns.last_seen_at
FROM nmap_services_latest ns
JOIN targets t ON t.id=ns.target_id
LEFT JOIN programs p
  ON p.platform=t.platform AND p.external_id=t.program_external_id;

-- 6) PROGRAMS_UI
CREATE OR REPLACE VIEW programs_ui AS
SELECT
  platform,
  external_id,
  handle,
  name,
  offers_bounties,
  currency,
  policy,
  first_seen_at,
  last_seen_at
FROM programs;

-- 7) SCOPES_UI (coerente con schema)
CREATE OR REPLACE VIEW scopes_ui AS
SELECT
  s.platform,
  COALESCE(p.handle, s.program_external_id) AS program,
  s.asset_type,
  s.identifier,
  s.eligible_for_bounty,
  s.instruction,
  v.host_base,
  s.first_seen_at,
  s.last_seen_at
FROM scopes s
LEFT JOIN programs p
  ON p.platform=s.platform AND p.external_id=s.program_external_id
LEFT JOIN v_scope_domains v
  ON v.platform=s.platform AND v.program_external_id=s.program_external_id AND v.scope_identifier=s.identifier;

COMMIT;
