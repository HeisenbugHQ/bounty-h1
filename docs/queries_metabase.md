# Metabase SQL Queries

All queries are plain SQL, ready for Metabase (no `psql` wrappers).
Optional filters use Metabase variables inside `[[ ... ]]`.

---

## Endpoints interessanti

```sql
SELECT
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  u.url,
  u.source,
  COALESCE(u.meta->>'kind', '') AS kind,
  u.last_seen_at
FROM url_observations u
JOIN targets t ON t.id = u.target_id
LEFT JOIN programs p
  ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE t.platform = 'hackerone'
  AND (
    u.meta->>'kind' = 'endpoint'
    OR u.url ~* '/(api|graphql|v[0-9]+|oauth|auth|sso|login|admin|internal|private|swagger|openapi|api-docs)'
  )
  [[AND COALESCE(p.handle, t.program_external_id) = {{program}}]]
ORDER BY u.last_seen_at DESC
LIMIT 500;
```

---

## Nuove superfici (auth / openapi / upload)

```sql
SELECT
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  s.has_auth,
  s.has_openapi,
  s.has_upload,
  s.has_admin,
  s.has_graphql,
  s.confidence,
  s.reasons,
  s.last_seen_at
FROM surface_signals_latest s
JOIN targets t ON t.id = s.target_id
LEFT JOIN programs p
  ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE t.platform = 'hackerone'
  AND (s.has_auth OR s.has_openapi OR s.has_upload)
  AND s.last_seen_at >= now() - interval '7 days'
  [[AND COALESCE(p.handle, t.program_external_id) = {{program}}]]
ORDER BY s.last_seen_at DESC;
```

---

## Cambiamenti recenti (HTTP)

```sql
WITH ordered AS (
  SELECT
    o.target_id,
    o.observed_at,
    o.status_code,
    o.final_url,
    o.title,
    LAG(o.status_code) OVER (PARTITION BY o.target_id ORDER BY o.observed_at) AS prev_status_code,
    LAG(o.final_url) OVER (PARTITION BY o.target_id ORDER BY o.observed_at) AS prev_final_url,
    LAG(o.title) OVER (PARTITION BY o.target_id ORDER BY o.observed_at) AS prev_title
  FROM http_observations o
  WHERE o.observed_at >= now() - interval '7 days'
),
diffs AS (
  SELECT *
  FROM ordered
  WHERE (status_code IS DISTINCT FROM prev_status_code)
     OR (final_url IS DISTINCT FROM prev_final_url)
     OR (title IS DISTINCT FROM prev_title)
)
SELECT
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  d.observed_at,
  d.prev_status_code,
  d.status_code,
  d.prev_final_url,
  d.final_url,
  d.prev_title,
  d.title
FROM diffs d
JOIN targets t ON t.id = d.target_id
LEFT JOIN programs p
  ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE t.platform = 'hackerone'
  [[AND COALESCE(p.handle, t.program_external_id) = {{program}}]]
ORDER BY d.observed_at DESC
LIMIT 500;
```

---

## Targets priority (task list)

```sql
SELECT
  program_external_id,
  host,
  http_url,
  final_url,
  status_code,
  title,
  content_type,
  cdn_provider,
  waf_provider,
  asn,
  asn_org,
  tls_port,
  tls_san_count,
  has_auth,
  has_openapi,
  has_upload,
  has_admin,
  has_graphql,
  surface_confidence,
  score,
  why
FROM v_targets_priority
WHERE platform = 'hackerone'
  [[AND program_external_id = {{program_external_id}}]]
  [[AND score >= {{min_score}}]]
ORDER BY score DESC, target_id DESC
LIMIT 500;
```
