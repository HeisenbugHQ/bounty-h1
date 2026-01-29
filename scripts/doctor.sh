#!/usr/bin/env bash
set -u
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${REPO_ROOT}/runtime/logs"
mkdir -p "$LOG_DIR"

timestamp="$(date +"%Y-%m-%d_%H-%M-%S")"
log_file="${LOG_DIR}/doctor_${timestamp}.log"

exec > >(tee -a "$log_file") 2>&1

echo "[doctor] $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "repo: ${REPO_ROOT}"
echo "log:  ${log_file}"
echo

echo "[git] status"
git -C "$REPO_ROOT" status -sb || echo "  [WARN] git status failed"
echo

echo "[python] version + venv"
if command -v python >/dev/null 2>&1; then
  python --version
else
  echo "  [WARN] python not found in PATH"
fi

if [ -n "${VIRTUAL_ENV:-}" ]; then
  echo "  venv: active (${VIRTUAL_ENV})"
elif [ -d "${REPO_ROOT}/.venv" ]; then
  echo "  venv: .venv present (not active)"
else
  echo "  venv: not detected"
fi
echo

echo "[db] DB_DSN + connectivity"
if [ -z "${DB_DSN:-}" ]; then
  echo "  [WARN] DB_DSN is not set"
else
  echo "  DB_DSN is set"
  if command -v psql >/dev/null 2>&1; then
    if psql "$DB_DSN" -c "select 1"; then
      echo "  [OK] postgres responds to 'select 1'"
    else
      echo "  [ERROR] postgres did not respond to 'select 1'"
    fi
  else
    echo "  [WARN] psql not found in PATH"
  fi
fi
echo

echo "[tools] availability"
tools=(subfinder httpx naabu puredns ffuf anew nmap openssl)
for tool in "${tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  [OK] $tool: $(command -v "$tool")"
  else
    echo "  [MISSING] $tool"
  fi
done
echo

echo "[wordlists] line counts"
wordlists=(
  "wordlists/subdomains_small.txt"
  "wordlists/paths_small.txt"
  "wordlists/files_small.txt"
  "wordlists/custom/subdomains_custom.txt"
  "wordlists/custom/paths_custom.txt"
  "wordlists/custom/params_custom.txt"
  "wordlists/custom/endpoints_custom.txt"
  "wordlists/custom/infra_hints_custom.txt"
)
for wl in "${wordlists[@]}"; do
  if [ -f "${REPO_ROOT}/${wl}" ]; then
    lines="$(wc -l < "${REPO_ROOT}/${wl}" | tr -d ' ')"
    if [ "$lines" -gt 0 ]; then
      echo "  [OK] ${wl}: ${lines} lines"
    else
      echo "  [ERROR] ${wl}: empty"
    fi
  else
    echo "  [MISSING] ${wl}"
  fi
done
echo

echo "[db] public tables (top 10)"
if [ -z "${DB_DSN:-}" ]; then
  echo "  [WARN] DB_DSN is not set; skipping"
elif ! command -v psql >/dev/null 2>&1; then
  echo "  [WARN] psql not found; skipping"
else
  psql "$DB_DSN" -c "\\dt public.*" 2>/dev/null | awk '
    $2 == "public" && $3 != "" { print $3 }
  ' | head -n 10 | sed 's/^/  - /'
fi
echo

echo "[done]"
