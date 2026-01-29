# Metabase Queries (SQL only)

All queries below are plain SQL (no `psql` wrapper). Ready to copy-paste into Metabase.

---

## Endpoints interessanti (per program handle)

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
  AND COALESCE(p.handle, t.program_external_id) = {{program}}
  AND (
    u.meta->>'kind' = 'endpoint'
    OR u.url ~* '/(api|graphql|v[0-9]+|oauth|auth|sso|login|admin|internal|private|swagger|openapi|api-docs)'
  )
ORDER BY u.last_seen_at DESC
LIMIT 500;
```

---

## Top params (per program handle)

```sql
SELECT
  COALESCE(p.handle, t.program_external_id) AS program,
  po.param_name,
  COUNT(*) AS occurrences,
  COUNT(DISTINCT po.target_id) AS targets
FROM param_observations po
JOIN targets t ON t.id = po.target_id
LEFT JOIN programs p
  ON p.platform = t.platform AND p.external_id = t.program_external_id
WHERE t.platform = 'hackerone'
  AND COALESCE(p.handle, t.program_external_id) = {{program}}
GROUP BY 1, 2
ORDER BY occurrences DESC
LIMIT 200;
```

---

## Target overview (per program handle, latest http + cdn/waf + ports count)

```sql
SELECT
  COALESCE(p.handle, t.program_external_id) AS program,
  t.host,
  h.status_code,
  h.final_url,
  h.title,
  h.content_type,
  h.server_header,
  h.cdn AS http_cdn,
  e.cdn_provider,
  e.waf_provider,
  COALESCE(pc.port_count, 0) AS port_count,
  h.observed_at AS http_observed_at
FROM targets t
LEFT JOIN programs p
  ON p.platform = t.platform AND p.external_id = t.program_external_id
LEFT JOIN v_latest_http_by_target h
  ON h.target_id = t.id
LEFT JOIN edge_fingerprint_latest e
  ON e.target_id = t.id
LEFT JOIN (
  SELECT target_id, COUNT(*) AS port_count
  FROM ports_latest
  GROUP BY target_id
) pc ON pc.target_id = t.id
WHERE t.platform = 'hackerone'
  AND COALESCE(p.handle, t.program_external_id) = {{program}}
ORDER BY h.observed_at DESC NULLS LAST, t.last_seen_at DESC
LIMIT 500;
```

---

## SAN candidates nuovi / needs_review

```sql
SELECT
  COALESCE(p.handle, s.program_external_id) AS program,
  s.san_domain,
  s.registrable_domain,
  s.confidence,
  s.status,
  s.reasons,
  s.first_seen_at,
  s.last_seen_at
FROM san_candidates s
LEFT JOIN programs p
  ON p.platform = s.platform AND p.external_id = s.program_external_id
WHERE s.platform = 'hackerone'
  AND s.status IN ('new', 'needs_review')
ORDER BY s.first_seen_at DESC
LIMIT 500;
```
