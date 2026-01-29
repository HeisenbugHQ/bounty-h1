BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Core: programs/scopes
CREATE TABLE IF NOT EXISTS programs (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL,
  external_id TEXT NOT NULL,
  handle TEXT,
  name TEXT,
  offers_bounties BOOLEAN,
  currency TEXT,
  policy TEXT,
  raw_json JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, external_id)
);

-- Canonical programs (cross-platform dedupe)
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
  kind TEXT NOT NULL,     -- domain|email_domain|website_host|brand
  value TEXT NOT NULL,
  weight INT NOT NULL DEFAULT 10,
  source TEXT NOT NULL DEFAULT 'derived', -- derived|manual|platform
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(canonical_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_program_fingerprints_kind_value
  ON program_fingerprints(kind, value);

CREATE TABLE IF NOT EXISTS scopes (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  asset_type TEXT,
  identifier TEXT NOT NULL,
  eligible_for_bounty BOOLEAN DEFAULT TRUE,
  instruction TEXT,
  raw_json JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id, identifier)
);

-- Assets (manual/import/multi-source input)
CREATE TABLE IF NOT EXISTS assets (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'manual',
  program_external_id TEXT NOT NULL,
  asset_type TEXT NOT NULL,                   -- domain|wildcard|url|ip|cidr|asn|other
  value TEXT NOT NULL,
  tags TEXT[] DEFAULT '{}'::TEXT[],
  note TEXT,
  status TEXT NOT NULL DEFAULT 'active',      -- active|paused|archived
  raw_json JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id, asset_type, value)
);

CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(platform, program_external_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);

-- Targets: unified hostname inventory
CREATE TABLE IF NOT EXISTS targets (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  source_scope_identifier TEXT,
  host TEXT NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  http_scanned_at TIMESTAMPTZ,
  port_scanned_at TIMESTAMPTZ,
  enriched_at TIMESTAMPTZ,
  UNIQUE(platform, program_external_id, host)
);

CREATE INDEX IF NOT EXISTS idx_targets_host ON targets(host);
CREATE INDEX IF NOT EXISTS idx_targets_http_pending ON targets(platform, http_scanned_at) WHERE http_scanned_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_targets_port_pending ON targets(platform, port_scanned_at) WHERE port_scanned_at IS NULL;

-- HTTP observations
CREATE TABLE IF NOT EXISTS http_observations (
  id BIGSERIAL PRIMARY KEY,
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scheme TEXT,
  port INT,
  url TEXT,
  status_code INT,
  title TEXT,
  server_header TEXT,
  tech_json JSONB,

  content_type TEXT,
  content_length BIGINT,
  final_url TEXT,
  redirect_chain TEXT[],
  ip TEXT,
  cname TEXT,
  cdn TEXT,
  favicon_mmh3 TEXT,
  headers_selected JSONB,
  headers_security JSONB,
  headers_cors JSONB,
  headers_infra JSONB,
  set_cookie_names TEXT[],
  set_cookie_flags JSONB,

  observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_http_obs_target ON http_observations(target_id);
CREATE INDEX IF NOT EXISTS idx_http_obs_status ON http_observations(status_code);

-- Latest HTTP view
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

-- Ports latest
CREATE TABLE IF NOT EXISTS ports_latest (
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  proto TEXT NOT NULL DEFAULT 'tcp',
  port INT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open',
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(target_id, proto, port)
);

-- Nmap/services latest
CREATE TABLE IF NOT EXISTS nmap_services_latest (
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  port INT NOT NULL,
  proto TEXT NOT NULL DEFAULT 'tcp',
  service_name TEXT,
  product TEXT,
  version TEXT,
  extra_info TEXT,
  cpe TEXT[],
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(target_id, proto, port)
);

-- TLS certs latest
CREATE TABLE IF NOT EXISTS tls_certs_latest (
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  port INT NOT NULL,
  subject_cn TEXT,
  issuer TEXT,
  not_before TIMESTAMPTZ,
  not_after TIMESTAMPTZ,
  fingerprint_sha256 TEXT,
  san_domains TEXT[],
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(target_id, port)
);

-- Edge/CDN/WAF fingerprint latest
CREATE TABLE IF NOT EXISTS edge_fingerprint_latest (
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  cdn_provider TEXT,
  waf_provider TEXT,
  confidence INT DEFAULT 0,
  raw_json JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(target_id)
);

-- DNS/ASN enrichment latest
CREATE TABLE IF NOT EXISTS dns_asn_latest (
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  a_records INET[],
  aaaa_records INET[],
  cname TEXT,
  asn INT,
  asn_org TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(target_id)
);

-- SAN staging + promotions
CREATE TABLE IF NOT EXISTS san_candidates (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'hackerone',
  program_external_id TEXT NOT NULL,
  san_domain TEXT NOT NULL,
  registrable_domain TEXT,
  source_target_id BIGINT REFERENCES targets(id) ON DELETE SET NULL,
  source_host TEXT,
  source_port INT,
  confidence INT NOT NULL DEFAULT 0,
  reasons JSONB,
  status TEXT NOT NULL DEFAULT 'new', -- new|needs_review|promoted|rejected
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id, san_domain)
);

CREATE INDEX IF NOT EXISTS idx_san_candidates_status ON san_candidates(status);
CREATE INDEX IF NOT EXISTS idx_san_candidates_conf ON san_candidates(confidence);

CREATE TABLE IF NOT EXISTS san_promotions (
  id BIGSERIAL PRIMARY KEY,
  candidate_id BIGINT NOT NULL REFERENCES san_candidates(id) ON DELETE CASCADE,
  promoted_target_id BIGINT REFERENCES targets(id) ON DELETE SET NULL,
  promoted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  note TEXT
);

-- URL/Param mining tables
CREATE TABLE IF NOT EXISTS url_observations (
  id BIGSERIAL PRIMARY KEY,
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  method TEXT,
  source TEXT NOT NULL, -- html|js|crawl|wayback|dir
  meta JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(target_id, url, source)
);

CREATE TABLE IF NOT EXISTS param_observations (
  id BIGSERIAL PRIMARY KEY,
  target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  param_name TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence INT NOT NULL DEFAULT 50,
  meta JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(target_id, url, param_name, source)
);

CREATE INDEX IF NOT EXISTS idx_params_name ON param_observations(param_name);
CREATE INDEX IF NOT EXISTS idx_params_target ON param_observations(target_id);

-- Surface findings (rule-based)
CREATE TABLE IF NOT EXISTS surface_findings (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'hackerone',
  program_external_id TEXT NOT NULL,
  target_id BIGINT REFERENCES targets(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  category TEXT NOT NULL,         -- auth|openapi|graphql|admin|upload|import|reset|invite|webhook|callback|api|storage|other
  rule_id TEXT NOT NULL,          -- e.g. auth:path:/login
  confidence INT NOT NULL DEFAULT 50,  -- 0..100
  severity INT NOT NULL DEFAULT 10,    -- 0..100
  evidence JSONB,
  status TEXT NOT NULL DEFAULT 'new',  -- new|triaged|ignored|confirmed
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id, url, category, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_surface_findings_program
  ON surface_findings(platform, program_external_id);
CREATE INDEX IF NOT EXISTS idx_surface_findings_status
  ON surface_findings(status);
CREATE INDEX IF NOT EXISTS idx_surface_findings_category
  ON surface_findings(category);
CREATE INDEX IF NOT EXISTS idx_surface_findings_conf
  ON surface_findings(confidence DESC);

-- Surface findings UI view
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

-- Surface signals (latest per target)
CREATE TABLE IF NOT EXISTS surface_signals_latest (
  target_id BIGINT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
  has_auth BOOLEAN NOT NULL DEFAULT FALSE,
  has_openapi BOOLEAN NOT NULL DEFAULT FALSE,
  has_upload BOOLEAN NOT NULL DEFAULT FALSE,
  has_admin BOOLEAN NOT NULL DEFAULT FALSE,
  has_graphql BOOLEAN NOT NULL DEFAULT FALSE,
  confidence INT NOT NULL DEFAULT 0,
  reasons JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Subdomain audit
CREATE TABLE IF NOT EXISTS subdomain_discoveries (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'hackerone',
  program_external_id TEXT NOT NULL,
  root_domain TEXT NOT NULL,
  subdomain TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id, subdomain)
);

-- Runs orchestration
CREATE TABLE IF NOT EXISTS runs (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'hackerone',
  program_external_id TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'monitor',
  status TEXT NOT NULL DEFAULT 'running',
  config_json JSONB,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  note TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_program_started ON runs(platform, program_external_id, started_at DESC);

CREATE TABLE IF NOT EXISTS run_steps (
  run_id BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  step_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'running',
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  error TEXT,
  meta JSONB,
  PRIMARY KEY(run_id, step_name)
);

CREATE INDEX IF NOT EXISTS idx_run_steps_status ON run_steps(status);

CREATE TABLE IF NOT EXISTS findings (
  id BIGSERIAL PRIMARY KEY,
  run_id BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  program_external_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity INT NOT NULL DEFAULT 1,
  key TEXT NOT NULL,
  data_json JSONB,
  status TEXT NOT NULL DEFAULT 'open',
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(program_external_id, kind, key)
);

CREATE INDEX IF NOT EXISTS idx_findings_program_kind ON findings(program_external_id, kind);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Scope parsing view (used by SAN correlator / UI)
CREATE OR REPLACE VIEW v_scope_domains AS
WITH raw AS (
  SELECT platform, program_external_id, asset_type, identifier
  FROM scopes
  WHERE identifier IS NOT NULL AND identifier <> ''
),
clean AS (
  SELECT platform, program_external_id, asset_type, identifier AS scope_identifier, lower(identifier) AS ident_l
  FROM raw
)
SELECT
  platform,
  program_external_id,
  scope_identifier,
  asset_type,
  CASE
    WHEN ident_l ~ '^https?://' THEN regexp_replace(regexp_replace(ident_l, '^https?://', ''), '/.*$', '')
    WHEN ident_l LIKE '%*.%' THEN regexp_replace(ident_l, '^.*\*\.', '')
    ELSE regexp_replace(ident_l, '/.*$', '')
  END AS host_base
FROM clean;

-- Useful views
CREATE OR REPLACE VIEW v_top_params AS
SELECT param_name, count(*) AS hits, count(DISTINCT target_id) AS targets
FROM param_observations
GROUP BY param_name
ORDER BY hits DESC;

CREATE OR REPLACE VIEW v_targets_overview AS
SELECT
  t.id,
  t.platform,
  t.program_external_id,
  t.host,
  t.source_scope_identifier,
  t.first_seen_at,
  t.last_seen_at,
  t.http_scanned_at,
  t.port_scanned_at,
  t.enriched_at,
  h.status_code,
  h.title,
  h.content_type,
  h.final_url,
  h.ip,
  h.cname,
  h.cdn,
  h.observed_at AS http_observed_at
FROM targets t
LEFT JOIN v_latest_http_by_target h ON h.target_id=t.id;

-- Canonical overview for Metabase
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

CREATE OR REPLACE VIEW v_assets_overview AS
SELECT
  a.id,
  a.platform,
  a.program_external_id,
  p.handle AS program_handle,
  p.name AS program_name,
  a.asset_type,
  a.value,
  a.status,
  a.tags,
  a.note,
  a.first_seen_at,
  a.last_seen_at
FROM assets a
LEFT JOIN programs p
  ON p.platform=a.platform AND p.external_id=a.program_external_id;

-- Bridge ingest -> DNS pipeline: normalize active domain/wildcard/url assets into DNS seeds.
CREATE OR REPLACE VIEW v_dns_seeds AS
WITH assets_active AS (
  SELECT
    a.id AS asset_id,
    a.platform,
    a.program_external_id,
    a.asset_type,
    lower(trim(a.value)) AS norm_value,
    a.note
  FROM assets a
  WHERE a.status = 'active'
    AND a.asset_type IN ('domain', 'wildcard', 'url')
    AND a.value IS NOT NULL
    AND trim(a.value) <> ''
),
domain_seeds AS (
  SELECT
    platform,
    program_external_id,
    'domain'::TEXT AS seed_source,
    asset_id,
    regexp_replace(
      regexp_replace(norm_value, '^https?://', ''),
      '[/?#].*$',
      ''
    ) AS host,
    NULL::INT AS port,
    NULL::TEXT AS scheme,
    note
  FROM assets_active
  WHERE asset_type = 'domain'
),
wildcard_seeds AS (
  SELECT
    platform,
    program_external_id,
    'wildcard'::TEXT AS seed_source,
    asset_id,
    regexp_replace(
      regexp_replace(norm_value, '^https?://', ''),
      '^\\*\\.',
      ''
    ) AS host,
    NULL::INT AS port,
    NULL::TEXT AS scheme,
    note
  FROM assets_active
  WHERE asset_type = 'wildcard'
),
url_prepared AS (
  SELECT
    asset_id,
    platform,
    program_external_id,
    note,
    norm_value,
    substring(norm_value FROM '^(https?)://') AS scheme,
    regexp_replace(norm_value, '^https?://', '') AS no_scheme
  FROM assets_active
  WHERE asset_type = 'url'
),
url_parts AS (
  SELECT
    asset_id,
    platform,
    program_external_id,
    note,
    scheme,
    regexp_replace(no_scheme, '[/?#].*$', '') AS hostport
  FROM url_prepared
),
url_seeds AS (
  SELECT
    platform,
    program_external_id,
    'url'::TEXT AS seed_source,
    asset_id,
    regexp_replace(hostport, ':[0-9]+$', '') AS host,
    CASE
      WHEN scheme IS NULL THEN NULL::INT
      WHEN substring(hostport FROM ':([0-9]+)$') IS NOT NULL
        THEN substring(hostport FROM ':([0-9]+)$')::INT
      WHEN scheme = 'https' THEN 443
      WHEN scheme = 'http' THEN 80
      ELSE NULL::INT
    END AS port,
    scheme,
    note
  FROM url_parts
)
SELECT DISTINCT ON (platform, program_external_id, host, port, scheme, seed_source)
  platform,
  program_external_id,
  seed_source,
  asset_id,
  host,
  port,
  scheme,
  note
FROM (
  SELECT * FROM domain_seeds
  UNION ALL
  SELECT * FROM wildcard_seeds
  UNION ALL
  SELECT * FROM url_seeds
) seeds
WHERE host IS NOT NULL
  AND host <> ''
  AND host !~ '\\s'
ORDER BY platform, program_external_id, host, port, scheme, seed_source, asset_id;

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

-- IP seed queue
CREATE TABLE IF NOT EXISTS ip_seed_queue (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'manual',
  program_external_id TEXT NOT NULL,
  seed_type TEXT NOT NULL, -- ip|cidr|asn
  seed_value TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new', -- new|processing|done|error
  error TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(platform, program_external_id, seed_type, seed_value)
);

CREATE INDEX IF NOT EXISTS idx_ip_seed_queue_status ON ip_seed_queue(status);
CREATE INDEX IF NOT EXISTS idx_ip_seed_queue_program ON ip_seed_queue(platform, program_external_id);

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

-- Generic job queue (queue-aware orchestration)
CREATE TABLE IF NOT EXISTS job_queue (
  id BIGSERIAL PRIMARY KEY,
  job_type TEXT NOT NULL,
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  priority INT NOT NULL DEFAULT 0,
  run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'new', -- new|running|done|failed
  tries INT NOT NULL DEFAULT 0,
  last_error TEXT,
  payload JSONB NOT NULL DEFAULT '{}'::JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_job_queue UNIQUE (job_type, platform, program_external_id, payload)
);

CREATE INDEX IF NOT EXISTS idx_job_queue_status
  ON job_queue(status);

CREATE INDEX IF NOT EXISTS idx_job_queue_due
  ON job_queue(status, run_after, priority DESC);

CREATE INDEX IF NOT EXISTS idx_job_queue_program
  ON job_queue(platform, program_external_id);

-- Task queue (simple scheduling)
CREATE TABLE IF NOT EXISTS task_queue (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  task_type TEXT NOT NULL,
  priority INT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'new', -- new|running|done|failed
  tries INT NOT NULL DEFAULT 0,
  last_error TEXT,
  run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_task_queue_status
  ON task_queue(status);

CREATE INDEX IF NOT EXISTS idx_task_queue_due
  ON task_queue(status, run_after, priority DESC);

CREATE INDEX IF NOT EXISTS idx_task_queue_program
  ON task_queue(platform, program_external_id);

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

-- Orchestrator counters (stable)
CREATE OR REPLACE VIEW v_counts_queue AS
SELECT
  (SELECT count(*) FROM targets WHERE platform='hackerone' AND http_scanned_at IS NULL) AS http_pending,
  (SELECT count(*) FROM targets WHERE platform='hackerone' AND port_scanned_at IS NULL) AS port_pending,
  (SELECT count(*) FROM targets WHERE platform='hackerone') AS targets_total;

-- Targets priority (task list)
CREATE OR REPLACE VIEW v_targets_priority AS
WITH weights AS (
  SELECT
    COALESCE(NULLIF(current_setting('bounty.priority.http_2xx', true), ''), '10')::INT AS w_http_2xx,
    COALESCE(NULLIF(current_setting('bounty.priority.auth', true), ''), '15')::INT AS w_auth,
    COALESCE(NULLIF(current_setting('bounty.priority.admin', true), ''), '18')::INT AS w_admin,
    COALESCE(NULLIF(current_setting('bounty.priority.upload', true), ''), '12')::INT AS w_upload,
    COALESCE(NULLIF(current_setting('bounty.priority.graphql', true), ''), '16')::INT AS w_graphql,
    COALESCE(NULLIF(current_setting('bounty.priority.openapi', true), ''), '14')::INT AS w_openapi,
    COALESCE(NULLIF(current_setting('bounty.priority.edge_fp', true), ''), '6')::INT AS w_edge,
    COALESCE(NULLIF(current_setting('bounty.priority.dns_asn', true), ''), '6')::INT AS w_asn,
    COALESCE(NULLIF(current_setting('bounty.priority.tls', true), ''), '6')::INT AS w_tls,
    COALESCE(NULLIF(current_setting('bounty.priority.surface_conf', true), ''), '8')::INT AS w_surface_conf
),
latest_tls AS (
  SELECT DISTINCT ON (target_id)
    target_id,
    port,
    subject_cn,
    issuer,
    not_before,
    not_after,
    fingerprint_sha256,
    san_domains,
    last_seen_at
  FROM tls_certs_latest
  ORDER BY target_id, last_seen_at DESC NULLS LAST
)
SELECT
  t.id AS target_id,
  t.platform,
  t.program_external_id,
  t.host,
  h.url AS http_url,
  h.final_url,
  h.status_code,
  h.title,
  h.content_type,
  h.server_header,
  h.cdn AS http_cdn,
  e.cdn_provider,
  e.waf_provider,
  e.confidence AS edge_confidence,
  d.asn,
  d.asn_org,
  d.cname AS dns_cname,
  c.port AS tls_port,
  c.subject_cn,
  c.issuer,
  c.not_before,
  c.not_after,
  c.fingerprint_sha256,
  cardinality(c.san_domains) AS tls_san_count,
  s.has_auth,
  s.has_openapi,
  s.has_upload,
  s.has_admin,
  s.has_graphql,
  s.confidence AS surface_confidence,
  s.reasons AS surface_reasons,
  (
    CASE WHEN h.status_code BETWEEN 200 AND 399 THEN w.w_http_2xx ELSE 0 END
    + CASE WHEN s.has_auth THEN w.w_auth ELSE 0 END
    + CASE WHEN s.has_admin THEN w.w_admin ELSE 0 END
    + CASE WHEN s.has_upload THEN w.w_upload ELSE 0 END
    + CASE WHEN s.has_graphql THEN w.w_graphql ELSE 0 END
    + CASE WHEN s.has_openapi THEN w.w_openapi ELSE 0 END
    + CASE WHEN e.confidence >= 50 THEN w.w_edge ELSE 0 END
    + CASE WHEN d.asn IS NOT NULL THEN w.w_asn ELSE 0 END
    + CASE WHEN c.fingerprint_sha256 IS NOT NULL THEN w.w_tls ELSE 0 END
    + CASE WHEN s.confidence >= 70 THEN w.w_surface_conf ELSE 0 END
  ) AS score,
  jsonb_build_object(
    'http_2xx', CASE WHEN h.status_code BETWEEN 200 AND 399 THEN w.w_http_2xx ELSE 0 END,
    'auth', CASE WHEN s.has_auth THEN w.w_auth ELSE 0 END,
    'admin', CASE WHEN s.has_admin THEN w.w_admin ELSE 0 END,
    'upload', CASE WHEN s.has_upload THEN w.w_upload ELSE 0 END,
    'graphql', CASE WHEN s.has_graphql THEN w.w_graphql ELSE 0 END,
    'openapi', CASE WHEN s.has_openapi THEN w.w_openapi ELSE 0 END,
    'edge_fp', CASE WHEN e.confidence >= 50 THEN w.w_edge ELSE 0 END,
    'dns_asn', CASE WHEN d.asn IS NOT NULL THEN w.w_asn ELSE 0 END,
    'tls', CASE WHEN c.fingerprint_sha256 IS NOT NULL THEN w.w_tls ELSE 0 END,
    'surface_conf', CASE WHEN s.confidence >= 70 THEN w.w_surface_conf ELSE 0 END
  ) AS why
FROM targets t
LEFT JOIN v_latest_http_by_target h ON h.target_id=t.id
LEFT JOIN edge_fingerprint_latest e ON e.target_id=t.id
LEFT JOIN dns_asn_latest d ON d.target_id=t.id
LEFT JOIN latest_tls c ON c.target_id=t.id
LEFT JOIN surface_signals_latest s ON s.target_id=t.id
CROSS JOIN weights w;

COMMIT;
