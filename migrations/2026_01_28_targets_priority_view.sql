BEGIN;

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
