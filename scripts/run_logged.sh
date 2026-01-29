#!/usr/bin/env bash
set -euo pipefail

mkdir -p runtime/logs
ts="$(date +'%Y-%m-%d_%H-%M-%S')"
log="runtime/logs/run_${ts}.log"

# auto-export .env if present
if [ -f ".env" ]; then
  set -a
  source .env
  set +a
fi

# auto-activate venv if present
if [ -d ".venv" ] && [ -z "${VIRTUAL_ENV:-}" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

exec > >(tee -a "$log") 2>&1

echo "[+] Logging to: $log"
echo "[+] PWD: $(pwd)"
echo "[+] CMD: $*"
echo "[+] VENV: ${VIRTUAL_ENV:-none}"
echo "[+] DB_DSN set: $([[ -n "${DB_DSN:-}" ]] && echo YES || echo NO)"
echo

"$@"
