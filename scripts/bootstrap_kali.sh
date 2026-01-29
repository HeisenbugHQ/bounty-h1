#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[+] Bootstrap Kali (WSL) environment + recon tools (SecLists download-only)"
echo "    repo: $REPO_ROOT"

echo "[+] apt: update & install base packages..."
sudo apt update
sudo apt install -y \
  git curl wget unzip jq make gcc g++ \
  ca-certificates build-essential \
  python3 python3-venv python3-pip \
  dnsutils \
  nmap masscan \
  massdns \
  libpcap-dev \
  postgresql-client

echo "[+] Ensure Go is installed..."
if ! command -v go >/dev/null 2>&1; then
  sudo apt install -y golang-go
fi

GOPATH="$(go env GOPATH)"
GO_BIN="${GOPATH}/bin"
echo "[+] Go: GOPATH=$GOPATH"

echo "[+] Ensure Go bin is in PATH (current shell + persist)..."
export PATH="$PATH:$GO_BIN"

add_path_line() {
  local rc="$1"
  local line='export PATH="$PATH:$(go env GOPATH)/bin"'
  if [ -f "$rc" ]; then
    if ! grep -Fq "$line" "$rc"; then
      echo "$line" >> "$rc"
      echo "  - appended to $rc"
    fi
  else
    echo "$line" >> "$rc"
    echo "  - created $rc"
  fi
}
add_path_line "$HOME/.bashrc"
add_path_line "$HOME/.zshrc"

echo "[+] Installing Go tools (subfinder/httpx/naabu/puredns/ffuf/anew)..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/anew@latest

echo "[+] Python: create venv..."
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

echo "[+] Python: install requirements..."
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip wheel setuptools
pip install -r requirements.txt

WORDLIST_DIR="${REPO_ROOT}/wordlists"
SMALL_DIR="${WORDLIST_DIR}/small"
CUSTOM_DIR="${WORDLIST_DIR}/custom"

mkdir -p "$SMALL_DIR" "$CUSTOM_DIR"

# ---- download helpers (NO more empty files) ----
file_bytes() {
  local f="$1"
  if [ -f "$f" ]; then
    stat -c '%s' "$f" 2>/dev/null || wc -c <"$f" | tr -d ' '
  else
    echo "0"
  fi
}

# min_bytes: if existing file is smaller than this, re-download
download_strict() {
  local url="$1"
  local out="$2"
  local min_bytes="${3:-256}"
  local min_guard=100

  local sz
  sz="$(file_bytes "$out")"
  local threshold="$min_bytes"
  if [ "$threshold" -lt "$min_guard" ]; then
    threshold="$min_guard"
  fi

  if [ -s "$out" ] && [ "$sz" -ge "$threshold" ]; then
    echo "  [OK] exists: $out (bytes=$sz)"
    return 0
  fi

  echo "  [DL] $url -> $out (min_bytes=$min_bytes, guard=$min_guard)"
  local tmp="${out}.tmp.$$"
  rm -f "$tmp"

  # -f fail, -S show error, -s silent, -L follow redirects
  if ! curl -fSL "$url" -o "$tmp"; then
    echo "  [FATAL] download failed: $url"
    rm -f "$tmp"
    exit 2
  fi

  local tsz
  tsz="$(file_bytes "$tmp")"
  if [ "$tsz" -lt "$threshold" ]; then
    echo "  [FATAL] download produced too-small/empty file: $out (bytes=$tsz)"
    rm -f "$tmp"
    exit 2
  fi

  if head -c 2048 "$tmp" | grep -qiE '<html|404'; then
    echo "  [FATAL] download looks like HTML/404 for: $out"
    rm -f "$tmp"
    exit 2
  fi

  mv -f "$tmp" "$out"
  echo "  [OK] downloaded: $out (bytes=$tsz)"
}

ensure_symlink() {
  local target="$1"
  local link="$2"

  # create link (relative is fine) and validate target exists and non-empty
  ln -sf "$target" "$link"

  if [ ! -e "$link" ]; then
    echo "  [FATAL] symlink not created: $link"
    exit 2
  fi
  if [ ! -s "$link" ]; then
    echo "  [FATAL] symlink points to empty/missing file: $link -> $target"
    exit 2
  fi
}

ensure_seed_file() {
  local path="$1"
  local seed="$2"

  if [ -s "$path" ]; then
    return 0
  fi

  mkdir -p "$(dirname "$path")"
  printf "%s\n" "$seed" > "$path"

  if [ ! -s "$path" ]; then
    echo "  [FATAL] failed to seed non-empty file: $path"
    exit 2
  fi
}

echo "[+] Wordlists: downloading ONLY selected SMALL lists (SecLists raw)..."

# These thresholds are intentionally low but >0 to avoid "empty file" success.
download_strict \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
  "${SMALL_DIR}/subdomains-top1million-5000.txt" \
  20000

download_strict \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt" \
  "${SMALL_DIR}/raft-small-directories.txt" \
  2000

download_strict \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt" \
  "${SMALL_DIR}/raft-small-files.txt" \
  2000

echo "[+] Wordlists: creating stable aliases used by workers..."
ensure_symlink "small/subdomains-top1million-5000.txt" "${WORDLIST_DIR}/subdomains_small.txt"
ensure_symlink "small/raft-small-directories.txt"      "${WORDLIST_DIR}/paths_small.txt"
ensure_symlink "small/raft-small-files.txt"            "${WORDLIST_DIR}/files_small.txt"

echo "[+] Wordlists: ensure custom files exist..."
ensure_seed_file "${CUSTOM_DIR}/subdomains_custom.txt" "dev"
ensure_seed_file "${CUSTOM_DIR}/paths_custom.txt" "admin"
ensure_seed_file "${CUSTOM_DIR}/params_custom.txt" "id"
ensure_seed_file "${CUSTOM_DIR}/endpoints_custom.txt" "/api"
ensure_seed_file "${CUSTOM_DIR}/infra_hints_custom.txt" "cloudflare"

# ---- resolvers (make sure worker paths exist) ----
echo "[+] Resolvers: ensure resolvers.txt and wordlists/resolvers_valid.txt exist..."

if [ ! -s "${REPO_ROOT}/resolvers.txt" ]; then
  echo "  [DL] Trickest resolvers -> resolvers.txt"
  curl -fSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "${REPO_ROOT}/resolvers.txt" || true
fi

if [ ! -s "${REPO_ROOT}/resolvers.txt" ]; then
  echo "  [WARN] resolvers.txt not available (offline?). Writing minimal fallback."
  cat > "${REPO_ROOT}/resolvers.txt" <<'TXT'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
208.67.222.222
208.67.220.220
TXT
fi

mkdir -p "${WORDLIST_DIR}"
cp -f "${REPO_ROOT}/resolvers.txt" "${WORDLIST_DIR}/resolvers_valid.txt"

if [ ! -s "${WORDLIST_DIR}/resolvers_valid.txt" ]; then
  echo "  [FATAL] resolvers_valid.txt is empty"
  exit 2
fi

echo "[+] Sanity checks:"
echo "    massdns:   $(command -v massdns || echo MISSING)"
echo "    subfinder: $(command -v subfinder || echo MISSING)"
echo "    httpx:     $(command -v httpx || echo MISSING)"
echo "    naabu:     $(command -v naabu || echo MISSING)"
echo "    puredns:   $(command -v puredns || echo MISSING)"
echo "    ffuf:      $(command -v ffuf || echo MISSING)"
echo "    anew:      $(command -v anew || echo MISSING)"
echo "    psql:      $(command -v psql || echo MISSING)"
echo "    python:    $(python --version)"
echo "    resolvers: $(wc -l < resolvers.txt | tr -d ' ') lines"
echo "    resolvers_valid: $(wc -l < wordlists/resolvers_valid.txt | tr -d ' ') lines"
echo "    wordlists: subdomains_small=$(wc -l < wordlists/subdomains_small.txt | tr -d ' ')  paths_small=$(wc -l < wordlists/paths_small.txt | tr -d ' ')  files_small=$(wc -l < wordlists/files_small.txt | tr -d ' ')"
echo "    custom:    subdomains_custom=$(wc -l < wordlists/custom/subdomains_custom.txt | tr -d ' ')  paths_custom=$(wc -l < wordlists/custom/paths_custom.txt | tr -d ' ')  params_custom=$(wc -l < wordlists/custom/params_custom.txt | tr -d ' ')  endpoints_custom=$(wc -l < wordlists/custom/endpoints_custom.txt | tr -d ' ')  infra_hints_custom=$(wc -l < wordlists/custom/infra_hints_custom.txt | tr -d ' ')"

# hard fail if core aliases are empty (prevents your exact bug)
if [ ! -s "wordlists/subdomains_small.txt" ] || [ ! -s "wordlists/paths_small.txt" ] || [ ! -s "wordlists/files_small.txt" ]; then
  echo "[FATAL] one or more core wordlists are missing/empty. Bootstrap failed."
  exit 2
fi

# hard fail if core lists are too small (prevents HTML/empty downloads)
if [ "$(wc -l < wordlists/subdomains_small.txt | tr -d ' ')" -le 1000 ]; then
  echo "[FATAL] subdomains_small.txt too small (expected > 1000 lines)"
  exit 1
fi
if [ "$(wc -l < wordlists/paths_small.txt | tr -d ' ')" -le 100 ]; then
  echo "[FATAL] paths_small.txt too small (expected > 100 lines)"
  exit 1
fi
if [ "$(wc -l < wordlists/files_small.txt | tr -d ' ')" -le 100 ]; then
  echo "[FATAL] files_small.txt too small (expected > 100 lines)"
  exit 1
fi

# ensure custom wordlists required by workers are non-empty
if [ ! -s "wordlists/custom/subdomains_custom.txt" ] || [ ! -s "wordlists/custom/paths_custom.txt" ] || [ ! -s "wordlists/custom/params_custom.txt" ] || [ ! -s "wordlists/custom/endpoints_custom.txt" ] || [ ! -s "wordlists/custom/infra_hints_custom.txt" ]; then
  echo "[FATAL] one or more custom wordlists are missing/empty. Bootstrap failed."
  exit 2
fi

echo
echo "[+] Done."
echo "Next:"
echo "  - restart shell OR: source ~/.zshrc"
echo "  - activate venv: source .venv/bin/activate"
