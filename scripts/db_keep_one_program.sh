#!/usr/bin/env bash
set -euo pipefail

KEY="${1:-}"
if [ -z "$KEY" ]; then
  echo "Usage: $0 <handle-or-external_id>"
  exit 1
fi

if [ -f ".env" ]; then
  set -a; source .env; set +a
fi

if [ -z "${DB_DSN:-}" ]; then
  echo "[-] Missing DB_DSN in .env"
  exit 1
fi

psql "$DB_DSN" -v ON_ERROR_STOP=1 <<SQL
BEGIN;

-- accept either handle OR external_id
CREATE TEMP TABLE keep_program AS
SELECT external_id
FROM programs
WHERE platform='hackerone'
  AND (lower(coalesce(handle,'')) = lower('${KEY}') OR external_id = '${KEY}')
LIMIT 1;

DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM keep_program) THEN
    RAISE NOTICE 'Program not found for key: ${KEY}';
    RAISE NOTICE 'Some available handles (top 20):';
    -- show some handles to help user pick the right one
    PERFORM 1;
  END IF;
END \$\$;

-- If not found, print handles and abort cleanly
\\if :ERROR
\\endif

-- Manual diagnostic if not found: show handles
-- We can't easily conditionally print in pure SQL without complexity, so do a second query:
SELECT handle, external_id, name
FROM programs
WHERE platform='hackerone' AND handle IS NOT NULL AND handle <> ''
ORDER BY handle
LIMIT 20;

-- hard fail if still not found
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM keep_program) THEN
    RAISE EXCEPTION 'Program handle/id not found: ${KEY}';
  END IF;
END \$\$;

DELETE FROM programs p
WHERE p.platform='hackerone'
  AND p.external_id NOT IN (SELECT external_id FROM keep_program);

DELETE FROM scopes s
WHERE s.platform='hackerone'
  AND s.program_external_id NOT IN (SELECT external_id FROM keep_program);

DELETE FROM targets t
WHERE t.platform='hackerone'
  AND t.program_external_id NOT IN (SELECT external_id FROM keep_program);

COMMIT;
SQL

echo "[+] Kept only program: $KEY"
