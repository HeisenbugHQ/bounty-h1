#!/usr/bin/env bash
set -euo pipefail

BRANCH="${1:-main}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[-] Not a git repo"
  exit 1
fi

# Safety: never commit env files even if user messed up
git reset -q .env 2>/dev/null || true
git reset -q .env.* 2>/dev/null || true

git add -A
if git diff --cached --quiet; then
  echo "[+] Nothing to commit."
  exit 0
fi

MSG="${2:-"Update recon pipeline"}"
git commit -m "$MSG"
git push -u origin "$BRANCH"
echo "[+] Pushed to origin/$BRANCH"
