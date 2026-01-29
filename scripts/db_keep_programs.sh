#!/usr/bin/env bash
set -euo pipefail

if [ -f ".env" ]; then
  set -a; source .env; set +a
fi

if [ -z "${DB_DSN:-}" ]; then
  echo "[-] Missing DB_DSN"
  exit 1
fi

if [ $# -lt 1 ]; then
  echo "Usage: $0 <handle1> [handle2 ...]"
  exit 1
fi

HANDLES=("$@")
handles_sql="$(printf "'%s'," "${HANDLES[@]}")"
handles_sql="${handles_sql%,}"

psql "$DB_DSN" -v ON_ERROR_STOP=1 <<SQL
BEGIN;

CREATE TEMP TABLE keep_programs AS
SELECT external_id
FROM programs
WHERE platform='hackerone' AND handle IN (${handles_sql});

DELETE FROM programs p
WHERE p.platform='hackerone'
  AND p.external_id NOT IN (SELECT external_id FROM keep_programs);

DELETE FROM scopes s
WHERE s.platform='hackerone'
  AND s.program_external_id NOT IN (SELECT external_id FROM keep_programs);

DELETE FROM targets t
WHERE t.platform='hackerone'
  AND t.program_external_id NOT IN (SELECT external_id FROM keep_programs);

COMMIT;
SQL

echo "[+] Kept only programs: ${HANDLES[*]}"

