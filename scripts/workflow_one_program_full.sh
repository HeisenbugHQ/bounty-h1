#!/usr/bin/env bash
set -euo pipefail

PROGRAM_HANDLE="${1:-hackerone}"

echo "[+] FULL recon workflow for 1 program (sync all -> keep one): ${PROGRAM_HANDLE}"
echo "[+] Time: $(date -Is)"

docker compose up -d

echo "[1] reset schema"
bash scripts/db_reset.sh

echo "[2] sync hackerone (FULL catalog)"
python sync_h1.py

echo "[3] keep only program"
bash scripts/db_keep_one_program.sh "${PROGRAM_HANDLE}"

echo "[4] subdomains resolve -> targets"
python workers/dns/subdomains_resolve.py

echo "[5] http reinject"
python workers/meta/http_reinject.py

if [ "${RUN_WAYBACK:-true}" = "true" ] && [ -f "workers/dns/wayback_urls.py" ]; then
  echo "[6] wayback urls"
  python workers/dns/wayback_urls.py
fi

if [ "${RUN_EDGE_FP:-true}" = "true" ] && [ -f "workers/infra/edge_fingerprint.py" ]; then
  echo "[7] edge fingerprint"
  python workers/infra/edge_fingerprint.py
fi

echo "[8] port reinject"
python workers/infra/port_reinject.py

if [ "${RUN_NMAP:-true}" = "true" ] && [ -f "workers/infra/nmap_services.py" ]; then
  echo "[9] nmap services"
  python workers/infra/nmap_services.py
fi

if [ "${RUN_TLS:-true}" = "true" ] && [ -f "workers/tls/tls_miner.py" ]; then
  echo "[10] tls miner"
  python workers/tls/tls_miner.py
fi

if [ "${RUN_SAN:-true}" = "true" ] && [ -f "workers/tls/san_correlate.py" ]; then
  echo "[11] san correlate"
  python workers/tls/san_correlate.py
fi

if [ "${RUN_SAN_LEARN:-true}" = "true" ] && [ -f "workers/dns/learn_from_san.py" ]; then
  echo "[12] san learn (wordlist only)"
  python workers/dns/learn_from_san.py
fi

if [ "${RUN_PARAMS:-true}" = "true" ] && [ -f "workers/web/param_mine_html.py" ]; then
  echo "[13] param mine html"
  python workers/web/param_mine_html.py
fi

if [ "${RUN_PARAMS:-true}" = "true" ] && [ -f "workers/web/param_mine_js.py" ]; then
  echo "[14] param mine js"
  python workers/web/param_mine_js.py
fi

if [ -f "workers/infra/enrich_dns_asn.py" ]; then
  echo "[15] enrich dns/asn"
  python workers/infra/enrich_dns_asn.py
fi

echo "[+] DONE."
echo "[+] Metabase: http://localhost:3000"
