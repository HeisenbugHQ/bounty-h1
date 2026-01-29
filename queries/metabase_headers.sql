-- Metabase header queries (Postgres). Parameter: {{program_handle}}
-- All queries are plain SQL (no psql wrapper).

-- 1) CSP assente/presente + estratto direttiva (prime 120 chars)
SELECT
  t.host,
  h.final_url,
  h.status_code,
  CASE WHEN h.headers_selected->>'content-security-policy' IS NULL THEN 'absent' ELSE 'present' END AS csp_status,
  SUBSTRING(COALESCE(h.headers_selected->>'content-security-policy', '') FROM 1 FOR 120) AS csp_snippet,
  h.observed_at
FROM v_latest_http_by_target h
JOIN targets t ON t.id = h.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
ORDER BY h.observed_at DESC
LIMIT 500;

-- 2) CORS: wildcard ACAO
SELECT
  t.host,
  h.final_url,
  h.status_code,
  h.headers_selected->>'access-control-allow-origin' AS acao,
  h.headers_selected->>'access-control-allow-credentials' AS acac,
  h.observed_at
FROM v_latest_http_by_target h
JOIN targets t ON t.id = h.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
  AND h.headers_selected->>'access-control-allow-origin' = '*'
ORDER BY h.observed_at DESC
LIMIT 500;

-- 2b) CORS: ACAO più frequenti (fallback se non si può dedurre reflection)
SELECT
  h.headers_selected->>'access-control-allow-origin' AS acao,
  COUNT(*) AS hits,
  COUNT(DISTINCT t.id) AS targets
FROM v_latest_http_by_target h
JOIN targets t ON t.id = h.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
  AND h.headers_selected->>'access-control-allow-origin' IS NOT NULL
GROUP BY 1
ORDER BY hits DESC
LIMIT 100;

-- 3) Set-Cookie: flags deboli (manca Secure o HttpOnly)
SELECT
  t.host,
  h.final_url,
  h.status_code,
  h.headers_selected->'set-cookie' AS set_cookie_meta,
  h.observed_at
FROM v_latest_http_by_target h
JOIN targets t ON t.id = h.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
  AND (
    (COALESCE((h.headers_selected->'set-cookie'->>'count')::int, 0) > 0)
    AND (
      NOT (COALESCE(h.headers_selected->'set-cookie'->'flags', '[]'::jsonb) @> '["Secure"]'::jsonb)
      OR NOT (COALESCE(h.headers_selected->'set-cookie'->'flags', '[]'::jsonb) @> '["HttpOnly"]'::jsonb)
    )
  )
ORDER BY h.observed_at DESC
LIMIT 500;

-- 4) Redirect esterni (final_url domain != host)
WITH final_hosts AS (
  SELECT
    h.target_id,
    h.final_url,
    regexp_replace(regexp_replace(COALESCE(h.final_url, ''), '^https?://', ''), '/.*$', '') AS final_host
  FROM v_latest_http_by_target h
)
SELECT
  t.host,
  f.final_url,
  f.final_host,
  h.status_code,
  h.observed_at
FROM final_hosts f
JOIN v_latest_http_by_target h ON h.target_id = f.target_id
JOIN targets t ON t.id = f.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
  AND f.final_host <> ''
  AND lower(f.final_host) <> lower(t.host)
ORDER BY h.observed_at DESC
LIMIT 500;

-- 5) WAF hints (cf-ray / server-timing / via / cf-cache-status)
SELECT
  t.host,
  h.final_url,
  h.status_code,
  h.headers_selected,
  h.observed_at
FROM v_latest_http_by_target h
JOIN targets t ON t.id = h.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
  AND (
    h.headers_selected ? 'cf-ray'
    OR h.headers_selected ? 'server-timing'
    OR h.headers_selected ? 'via'
    OR h.headers_selected ? 'cf-cache-status'
  )
ORDER BY h.observed_at DESC
LIMIT 500;
