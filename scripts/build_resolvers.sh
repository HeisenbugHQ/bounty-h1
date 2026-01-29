#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SEED_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
SEED_FILE="resolvers_seed.txt"
OUT_FILE="resolvers.txt"

# how many resolvers to test (keep it quick)
TEST_LIMIT="${TEST_LIMIT:-500}"
# how many valid resolvers we want at minimum
MIN_OK="${MIN_OK:-100}"

# test domains (stable)
TEST_DOMAINS=("google.com" "cloudflare.com" "github.com")

echo "[+] resolvers: preparing seed list..."
if [ ! -f "$SEED_FILE" ]; then
  echo "[+] Downloading $SEED_FILE from Trickest..."
  curl -fsSL "$SEED_URL" -o "$SEED_FILE"
fi

# normalize seed
tmp_seed="$(mktemp)"
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$SEED_FILE" | awk '!seen[$0]++' | head -n "$TEST_LIMIT" > "$tmp_seed"

echo "[+] resolvers: validating with dig (limit=$TEST_LIMIT)..."
tmp_ok="$(mktemp)"
while read -r r; do
  ok=1
  for d in "${TEST_DOMAINS[@]}"; do
    # +time=1 +tries=1 keeps it fast; any answer is fine
    if ! dig @"$r" "$d" A +time=1 +tries=1 +short >/dev/null 2>&1; then
      ok=0
      break
    fi
  done
  if [ "$ok" -eq 1 ]; then
    echo "$r" >> "$tmp_ok"
  fi
done < "$tmp_seed"

count_ok="$(wc -l < "$tmp_ok" | tr -d ' ')"
if [ "$count_ok" -lt "$MIN_OK" ]; then
  echo "[!] Only $count_ok resolvers validated (< $MIN_OK). Falling back to curated seed without validation."
  cp "$SEED_FILE" "$OUT_FILE"
else
  echo "[+] Valid resolvers: $count_ok"
  mv "$tmp_ok" "$OUT_FILE"
fi

rm -f "$tmp_seed" 2>/dev/null || true
echo "[+] Wrote $OUT_FILE ($(wc -l < "$OUT_FILE" | tr -d ' ') lines)"
