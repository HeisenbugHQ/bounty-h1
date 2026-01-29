#!/usr/bin/env bash
set -euo pipefail

if [ -f ".env" ]; then
  set -a; source .env; set +a
fi

if [ -z "${DB_DSN:-}" ]; then
  echo "[-] Missing DB_DSN in .env"
  exit 1
fi

echo "[+] Reset schema using init_db.sql"
psql "$DB_DSN" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO bounty;
GRANT ALL ON SCHEMA public TO public;
SQL

psql "$DB_DSN" -v ON_ERROR_STOP=1 -f sql/init_db.sql


# apply UI views (sonar etc)
if [ -f "sql/ui_views.sql" ]; then
  psql "$DB_DSN" -v ON_ERROR_STOP=1 -f sql/ui_views.sql
fi

echo "[+] Done."
