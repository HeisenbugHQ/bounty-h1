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
  WHERE platform='hackerone' AND identifier IS NOT NULL AND identifier <> ''
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
  ON p.platform='hackerone' AND p.external_id=a.program_external_id;

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

COMMIT;
