#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <handle1> <handle2> <handle3> <handle4> <handle5>"
  exit 1
fi

HANDLES=("$@")

echo "[+] FULL recon workflow for 5 programs: ${HANDLES[*]}"
docker compose up -d
bash scripts/db_reset.sh

python sync_h1.py
bash scripts/db_keep_programs.sh "${HANDLES[@]}"

for h in "${HANDLES[@]}"; do
  echo "[+] ===== PROGRAM: $h ====="
  # keep script already filtered DB; workers will only see these programs in DB anyway
  python workers/worker_subdomains_resolve.py
  python workers/worker_http_reinject.py
  python workers/worker_port_reinject.py
done

echo "[+] Optional stages (global): nmap/tls/san/params/enrich"
python workers/worker_nmap_services.py || true
python workers/worker_tls_miner.py || true
python workers/worker_san_correlate.py || true
python workers/worker_param_mine_html.py || true
python workers/worker_param_mine_js.py || true
python workers/worker_enrich_dns_asn.py || true

echo "[+] DONE."
