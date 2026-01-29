#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[+] Restructuring repo at: $ROOT"

cd "$ROOT"

# ---- create directories ----
mkdir -p sql
mkdir -p runtime/logs
mkdir -p runtime/workflow_state
mkdir -p runtime/bundles
mkdir -p wordlists/seclists
mkdir -p wordlists/custom

# ---- move SQL files ----
if [ -f "init_db.sql" ] && [ ! -f "sql/init_db.sql" ]; then
  mv init_db.sql sql/
  echo "[+] moved init_db.sql -> sql/"
fi

if [ -f "ui_views.sql" ] && [ ! -f "sql/ui_views.sql" ]; then
  mv ui_views.sql sql/
  echo "[+] moved ui_views.sql -> sql/"
fi

# ---- move bundles (if any) ----
if [ -d "bundles" ]; then
  if [ ! -d "runtime/bundles" ]; then
    mv bundles runtime/
    echo "[+] moved bundles/ -> runtime/"
  fi
fi

# ---- move logs (if any) ----
if [ -d "logs" ]; then
  if [ ! -d "runtime/logs" ]; then
    mv logs runtime/
    echo "[+] moved logs/ -> runtime/"
  fi
fi

# ---- workflow state ----
if [ -d ".workflow_state" ]; then
  mv .workflow_state runtime/workflow_state
  echo "[+] moved .workflow_state -> runtime/workflow_state/"
fi

# ---- deprecated cleanup ----
if [ -d "deprecated" ]; then
  echo "[+] removing deprecated/"
  rm -rf deprecated
fi

# ---- ensure workers dir ----
if [ ! -d "workers" ]; then
  echo "[!] workers/ directory missing — aborting"
  exit 1
fi

# ---- ensure scripts dir ----
mkdir -p scripts

# ---- sanity checks ----
echo
echo "[✓] Structure check:"
for d in sql workers scripts wordlists runtime; do
  if [ -d "$d" ]; then
    echo "  OK: $d/"
  else
    echo "  MISSING: $d/"
  fi
done

echo
echo "[✓] Done. Repo structure is now FINAL."
