-- Metabase surface queries (Postgres). Parameter: {{program_handle}}
-- All queries are plain SQL (no psql wrapper).

-- 1) Top findings per category (count)
SELECT
  category,
  COUNT(*) AS findings
FROM v_surface_top
WHERE program_handle = {{program_handle}}
GROUP BY category
ORDER BY findings DESC;

-- 2) Auth surfaces (confidence>=70) ordered by severity desc
SELECT *
FROM v_surface_top
WHERE program_handle = {{program_handle}}
  AND category = 'auth'
  AND confidence >= 70
ORDER BY severity DESC, last_seen_at DESC
LIMIT 200;

-- 3) OpenAPI/Swagger endpoints
SELECT *
FROM v_surface_top
WHERE program_handle = {{program_handle}}
  AND category = 'openapi'
ORDER BY confidence DESC, last_seen_at DESC
LIMIT 200;

-- 4) GraphQL endpoints
SELECT *
FROM v_surface_top
WHERE program_handle = {{program_handle}}
  AND category = 'graphql'
ORDER BY confidence DESC, last_seen_at DESC
LIMIT 200;

-- 5) Upload/Import endpoints
SELECT *
FROM v_surface_top
WHERE program_handle = {{program_handle}}
  AND category IN ('upload','import')
ORDER BY confidence DESC, last_seen_at DESC
LIMIT 200;

-- 6) Weak cookie flags on auth/api surfaces
SELECT
  f.program_handle,
  f.host,
  f.url,
  f.category,
  f.confidence,
  f.severity,
  f.status_code,
  f.title,
  f.final_url,
  f.last_seen_at
FROM v_surface_top f
JOIN surface_findings sf
  ON sf.url = f.url
  AND sf.category = f.category
  AND sf.program_external_id = (SELECT external_id FROM programs WHERE handle={{program_handle}} AND platform='hackerone' LIMIT 1)
WHERE f.program_handle = {{program_handle}}
  AND f.category IN ('auth','api')
  AND (
    (sf.evidence->'headers'->'set_cookie_flags') IS NOT NULL
    AND NOT (sf.evidence->'headers'->'set_cookie_flags' ? 'Secure')
    OR NOT (sf.evidence->'headers'->'set_cookie_flags' ? 'HttpOnly')
  )
ORDER BY f.severity DESC, f.last_seen_at DESC
LIMIT 200;

-- 7) CORS permissivo (acao="*") su auth/api
SELECT
  f.program_handle,
  f.host,
  f.url,
  f.category,
  f.confidence,
  f.severity,
  f.status_code,
  f.last_seen_at
FROM v_surface_top f
JOIN surface_findings sf
  ON sf.url = f.url
  AND sf.category = f.category
  AND sf.program_external_id = (SELECT external_id FROM programs WHERE handle={{program_handle}} AND platform='hackerone' LIMIT 1)
WHERE f.program_handle = {{program_handle}}
  AND f.category IN ('auth','api')
  AND sf.evidence->'headers'->>'acao' = '*'
ORDER BY f.severity DESC, f.last_seen_at DESC
LIMIT 200;

-- 8) Storage leaks candidates (.map/.env/.bak etc)
SELECT *
FROM v_surface_top
WHERE program_handle = {{program_handle}}
  AND category = 'storage'
ORDER BY confidence DESC, last_seen_at DESC
LIMIT 200;
