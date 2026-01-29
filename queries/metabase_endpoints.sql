-- Metabase queries (Postgres). Parameter: {{program_handle}}

-- Top endpoints from JS (url_observations source='js') for program
SELECT
  u.url,
  count(*) AS hits,
  count(DISTINCT u.target_id) AS targets
FROM url_observations u
JOIN targets t ON t.id = u.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE u.source = 'js'
  AND p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
GROUP BY u.url
ORDER BY hits DESC, targets DESC, u.url ASC;

-- Most frequent and most widespread parameters for program
SELECT
  pobs.param_name,
  count(*) AS hits,
  count(DISTINCT pobs.target_id) AS targets
FROM param_observations pobs
JOIN targets t ON t.id = pobs.target_id
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
GROUP BY pobs.param_name
ORDER BY hits DESC, targets DESC, pobs.param_name ASC;

-- New targets in last 24 hours for program
SELECT
  t.id,
  t.host,
  t.first_seen_at,
  t.last_seen_at
FROM targets t
JOIN programs p ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE p.platform = 'hackerone'
  AND p.handle = {{program_handle}}
  AND t.first_seen_at >= now() - interval '24 hours'
ORDER BY t.first_seen_at DESC, t.id DESC;

-- SAN candidates high confidence (>=80) not promoted
SELECT
  sc.id,
  sc.san_domain,
  sc.registrable_domain,
  sc.confidence,
  sc.status,
  sc.first_seen_at,
  sc.last_seen_at,
  sc.reasons,
  sc.source_host
FROM san_candidates sc
WHERE sc.platform = 'hackerone'
  AND sc.program_external_id = (
    SELECT external_id
    FROM programs
    WHERE platform='hackerone' AND handle = {{program_handle}}
    LIMIT 1
  )
  AND sc.confidence >= 80
  AND sc.status <> 'promoted'
ORDER BY sc.confidence DESC, sc.last_seen_at DESC, sc.id DESC;

-- Header-focused queries: see queries/metabase_headers.sql

-- Interesting headers (CSP/CORS/cookies/redirects/WAF hints)
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
    -- CSP missing or weak
    (NULLIF(h.headers_selected->'selected'->>'content-security-policy', '') IS NULL)
    OR (h.headers_selected->'selected'->>'content-security-policy' ~* '(unsafe-inline|unsafe-eval|\\*)')

    -- CORS wildcard
    OR (h.headers_selected->'selected'->>'access-control-allow-origin' = '*')

    -- Set-Cookie without Secure or HttpOnly
    OR (
      (h.headers_selected->'set_cookie'->'flags'->>'secure') IS NULL
      OR (h.headers_selected->'set_cookie'->'flags'->>'httponly') IS NULL
    )

    -- External redirect location
    OR (
      (h.headers_selected->'selected'->>'location') ~* '^https?://'
      AND (h.headers_selected->'selected'->>'location') !~* t.host
    )

    -- Via/WAF hints
    OR (h.headers_selected->'selected' ? 'via')
    OR (h.headers_selected->'selected' ? 'cf-ray')
    OR (h.headers_selected->'selected' ? 'cf-cache-status')
    OR (h.headers_selected::text ILIKE '%x-akamai-%')
    OR (h.headers_selected::text ILIKE '%x-sucuri-%')
  )
ORDER BY h.observed_at DESC
LIMIT 500;
