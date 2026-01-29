#!/usr/bin/env bash
set -euo pipefail

# make_project_bundle.sh
# Crea uno zip del progetto escludendo roba inutile e .env (sempre)
# Uso:
#   bash scripts/make_project_bundle.sh
#   bash scripts/make_project_bundle.sh /percorso/progetto
# Output:
#   bundles/<nomeprogetto>_YYYY-MM-DD_HH-MM-SS.zip

ROOT="${1:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"
NAME="$(basename "$ROOT")"
TS="$(date +"%Y-%m-%d_%H-%M-%S")"

OUTDIR="$ROOT/runtime/bundles"
OUTZIP="$OUTDIR/${NAME}_${TS}.zip"

mkdir -p "$OUTDIR"

echo "[+] Bundling project: $ROOT"
echo "[+] Output: $OUTZIP"

# Se zip non è installato, errore chiaro
if ! command -v zip >/dev/null 2>&1; then
  echo "[!] 'zip' non trovato. Installa con:"
  echo "    sudo apt-get update && sudo apt-get install -y zip"
  exit 1
fi

# Crea lo zip con esclusioni robuste
# - esclude .env e qualsiasi variante (.env.*, *.env)
# - esclude venv, cache, logs, node_modules, build artifacts, git
# - esclude bundles precedenti
(
  cd "$ROOT"
  zip -r -9 "$OUTZIP" . \
    -x ".env" ".env.*" "*.env" "*.env.*" \
    -x ".git/*" ".github/*" \
    -x ".venv/*" "venv/*" \
    -x "__pycache__/*" "**/__pycache__/*" \
    -x ".pytest_cache/*" ".mypy_cache/*" ".ruff_cache/*" \
    -x "*.pyc" "*.pyo" \
    -x "runtime/logs/*" \
    -x "runtime/workflow_state/*" \
    -x "runtime/bundles/*" \
    -x "node_modules/*" \
    -x "dist/*" "build/*" ".build/*" \
    -x ".DS_Store" "Thumbs.db" \
    -x "bundles/*"
)

echo "[+] Done."
echo "[+] Created: $OUTZIP"
