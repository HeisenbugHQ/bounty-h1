BEGIN;

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
    WHEN ident_l LIKE '%*.%' THEN regexp_replace(ident_l, '^.*\\*\\.', '')
    ELSE regexp_replace(ident_l, '/.*$', '')
  END AS host_base
FROM clean;

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

COMMIT;
