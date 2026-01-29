#!/usr/bin/env python3
"""
workers/web/dir_fuzz.py

Directory fuzzing (attack surface expansion) with strict controls + learning loop.

- Runs only when RUN_DIRFUZZ=true
- Runs only on selected hosts:
  A) assets with tag DIRFUZZ_TAG (default 'fuzz') and asset_type in ('domain','url')
  OR
  B) regex filter DIRFUZZ_HOST_REGEX (applies to targets.host)

Optional program filter:
- DIRFUZZ_PROGRAM_HANDLE (e.g. 'adobe') filters assets/targets to that program only.

Tool:
- ffuf required

Writes:
- url_observations source='dir' with meta (status, length, words, lines)

Learning:
- appends discovered directory tokens into custom wordlist via 'anew'
  -> wordlists/custom/paths_custom.txt

Env:
  DB_DSN=...

Toggle:
  RUN_DIRFUZZ=true/false

Selection:
  DIRFUZZ_TAG=fuzz
  DIRFUZZ_HOST_REGEX=              # optional regex if you don't want assets selection
  DIRFUZZ_PROGRAM_HANDLE=          # optional (e.g. adobe)

Wordlists:
  DIRFUZZ_WORDLIST_BASE=wordlists/paths_small.txt
  DIRFUZZ_WORDLIST_CUSTOM=wordlists/custom/paths_custom.txt

Fuzz:
  DIRFUZZ_BIN=ffuf
  DIRFUZZ_MATCH_CODES=200,204,301,302,307,308,401,403
  DIRFUZZ_RATE=150
  DIRFUZZ_THREADS=20
  DIRFUZZ_TIMEOUT=15
  DIRFUZZ_MAX_URLS_PER_HOST=300
  DIRFUZZ_BATCH=10

Learning:
  DIRFUZZ_LEARN=true/false
  DIRFUZZ_MAX_LEARN_PER_HOST=100
  ANEW_BIN=anew
"""

import os
import re
import json
import tempfile
import subprocess
from datetime import datetime
from urllib.parse import urlparse, urljoin

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

RUN_DIRFUZZ = os.getenv("RUN_DIRFUZZ", "false").strip().lower() == "true"

TAG = os.getenv("DIRFUZZ_TAG", "fuzz").strip()
HOST_REGEX = os.getenv("DIRFUZZ_HOST_REGEX", "").strip()
PROGRAM_HANDLE = os.getenv("DIRFUZZ_PROGRAM_HANDLE", "").strip()

FFUF_BIN = os.getenv("DIRFUZZ_BIN", "ffuf").strip()
WORDLIST_BASE = os.getenv("DIRFUZZ_WORDLIST_BASE", "wordlists/paths_small.txt").strip()
WORDLIST_CUSTOM = os.getenv("DIRFUZZ_WORDLIST_CUSTOM", "wordlists/custom/paths_custom.txt").strip()

MATCH_CODES = os.getenv("DIRFUZZ_MATCH_CODES", "200,204,301,302,307,308,401,403").strip()
RATE = os.getenv("DIRFUZZ_RATE", "150").strip()
THREADS = os.getenv("DIRFUZZ_THREADS", "20").strip()
TIMEOUT = int(os.getenv("DIRFUZZ_TIMEOUT", "15"))
MAX_URLS_PER_HOST = int(os.getenv("DIRFUZZ_MAX_URLS_PER_HOST", "300"))
BATCH = int(os.getenv("DIRFUZZ_BATCH", "10"))

DIRFUZZ_LEARN = os.getenv("DIRFUZZ_LEARN", "true").strip().lower() == "true"
MAX_LEARN_PER_HOST = int(os.getenv("DIRFUZZ_MAX_LEARN_PER_HOST", "100"))
ANEW_BIN = os.getenv("ANEW_BIN", "anew").strip()

# conservative token filter: keep path-ish tokens without spaces
TOKEN_BAD_RE = re.compile(r"[\s]")


def ts():
    return datetime.now().strftime("%H:%M:%S")


def norm(s: str) -> str:
    return (s or "").strip()


def which(binname: str) -> str | None:
    import shutil
    return shutil.which(binname)


def ensure_wordlists():
    if not os.path.exists(WORDLIST_BASE) or os.path.getsize(WORDLIST_BASE) == 0:
        raise RuntimeError(f"Missing base wordlist: {WORDLIST_BASE} (run bootstrap / downloader)")
    os.makedirs(os.path.dirname(WORDLIST_CUSTOM), exist_ok=True)
    if not os.path.exists(WORDLIST_CUSTOM):
        open(WORDLIST_CUSTOM, "a", encoding="utf-8").close()


def load_words(path: str) -> list[str]:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            if TOKEN_BAD_RE.search(w):
                continue
            out.append(w)
    # dedupe preserve order
    seen = set()
    uniq = []
    for w in out:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq


def build_effective_wordlist() -> str:
    """
    Creates a temp merged wordlist = base + custom (dedup).
    Returns path to temp file.
    """
    base = load_words(WORDLIST_BASE)
    custom = load_words(WORDLIST_CUSTOM)
    base_set = set(base)
    merged = base + [w for w in custom if w not in base_set]

    tf = tempfile.NamedTemporaryFile("w+", delete=False)
    for w in merged:
        tf.write(w + "\n")
    tf.flush()
    tf.close()
    return tf.name


def resolve_program_external_id(conn, handle: str) -> str | None:
    if not handle:
        return None
    with conn.cursor() as cur:
        cur.execute(
            "SELECT external_id FROM programs WHERE platform='hackerone' AND handle=%s LIMIT 1",
            (handle,),
        )
        r = cur.fetchone()
        return str(r[0]) if r else None


def canonical_host_from_value_domain(value: str) -> str | None:
    v = (value or "").strip().lower().rstrip(".")
    if not v:
        return None
    # if someone puts "*.example.com" in domain, strip wildcard prefix
    if v.startswith("*."):
        v = v[2:]
    return v or None


def canonical_host_from_value_url(value: str) -> str | None:
    v = (value or "").strip()
    if not v:
        return None
    try:
        p = urlparse(v if "://" in v else "https://" + v)
        if p.netloc:
            return p.netloc.lower().rstrip(".")
    except Exception:
        return None
    return None


def read_selected_hosts(conn) -> set[str]:
    """
    Selection priority:
    - assets(tag) -> domain/url
    - plus optional HOST_REGEX against targets.host
    - optional PROGRAM_HANDLE filter for both sources
    """
    selected: set[str] = set()
    prog_ext = resolve_program_external_id(conn, PROGRAM_HANDLE)

    # A) assets-based selection
    with conn.cursor() as cur:
        if prog_ext:
            cur.execute(
                """
                SELECT asset_type, value
                FROM assets
                WHERE status='active'
                  AND program_external_id=%s
                  AND (%s = ANY(tags))
                  AND asset_type IN ('domain','url')
                """,
                (prog_ext, TAG),
            )
        else:
            cur.execute(
                """
                SELECT asset_type, value
                FROM assets
                WHERE status='active'
                  AND (%s = ANY(tags))
                  AND asset_type IN ('domain','url')
                """,
                (TAG,),
            )

        for atype, value in cur.fetchall():
            atype = (atype or "").strip().lower()
            value = norm(value)
            if not value:
                continue
            if atype == "domain":
                h = canonical_host_from_value_domain(value)
                if h:
                    selected.add(h)
            elif atype == "url":
                h = canonical_host_from_value_url(value)
                if h:
                    selected.add(h)

    # B) regex selection (targets.host)
    if HOST_REGEX:
        rx = re.compile(HOST_REGEX)
        with conn.cursor() as cur:
            if prog_ext:
                cur.execute(
                    """
                    SELECT DISTINCT host
                    FROM targets
                    WHERE platform='hackerone' AND program_external_id=%s
                    """,
                    (prog_ext,),
                )
            else:
                cur.execute("SELECT DISTINCT host FROM targets WHERE platform='hackerone'")
            for (h,) in cur.fetchall():
                h = (h or "").lower().rstrip(".")
                if h and rx.search(h):
                    selected.add(h)

    return selected


def fetch_http_seeds(conn, selected_hosts: set[str]):
    """
    Get base_url from latest http observation for selected hosts.
    """
    if not selected_hosts:
        return []

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.id, t.host, COALESCE(h.final_url, h.url) AS base_url
            FROM targets t
            JOIN v_latest_http_by_target h ON h.target_id=t.id
            WHERE t.platform='hackerone'
              AND t.host = ANY(%s)
              AND COALESCE(h.final_url, h.url) IS NOT NULL
            ORDER BY h.observed_at DESC
            LIMIT %s
            """,
            (list(selected_hosts), BATCH),
        )

        out = []
        for tid, host, base_url in cur.fetchall():
            out.append((int(tid), norm(host), norm(base_url)))
        return out


def upsert_url_obs(cur, target_id: int, url: str, meta: dict):
    cur.execute(
        """
        INSERT INTO url_observations(target_id, url, method, source, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,'GET','dir',%s,now(),now())
        ON CONFLICT (target_id, url, source)
        DO UPDATE SET last_seen_at=now(), meta=url_observations.meta || EXCLUDED.meta
        """,
        (target_id, url, Json(meta or {})),
    )


def run_ffuf(base_url: str, effective_wordlist_path: str) -> list[dict]:
    """
    Runs ffuf, returns list of result dicts.
    """
    base = base_url.rstrip("/")
    url = f"{base}/FUZZ"

    # output file
    out_fd, out_path = tempfile.mkstemp(prefix="ffuf_", suffix=".json")
    os.close(out_fd)

    cmd = [
        FFUF_BIN,
        "-u", url,
        "-w", effective_wordlist_path,
        "-mc", MATCH_CODES,
        "-rate", RATE,
        "-t", THREADS,
        "-timeout", str(TIMEOUT),
        "-of", "json",
        "-o", out_path,
        "-s",
        "-r",  # follow redirects
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(60, TIMEOUT * 25),
        )
        try:
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            return data.get("results", []) or []
        except Exception:
            return []
    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass


def extract_path_tokens_for_learning(results: list[dict]) -> list[str]:
    """
    Extract stable tokens for re-use:
    - first segment
    - first/second segments
    """
    learned: list[str] = []

    for r in results:
        u = r.get("url")
        if not u:
            continue
        try:
            p = urlparse(u)
            path = (p.path or "").strip("/")
            if not path:
                continue
            segs = [s for s in path.split("/") if s]
            if not segs:
                continue
            learned.append(segs[0])
            if len(segs) >= 2:
                learned.append(segs[0] + "/" + segs[1])
        except Exception:
            continue

    # clean + unique, preserve order
    out = []
    seen = set()
    for x in learned:
        x = (x or "").strip()
        if not x:
            continue
        if TOKEN_BAD_RE.search(x):
            continue
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def append_with_anew(words: list[str], path: str) -> int:
    if not words:
        return 0

    # dedupe input first
    seen = set()
    uniq = []
    for w in words:
        w = (w or "").strip()
        if w and w not in seen:
            seen.add(w)
            uniq.append(w)

    if which(ANEW_BIN):
        p = subprocess.run([ANEW_BIN, path], input="\n".join(uniq) + "\n", text=True, capture_output=True)
        return len([ln for ln in p.stdout.splitlines() if ln.strip()])

    existing = set(load_words(path))
    new = [w for w in uniq if w not in existing]
    if new:
        with open(path, "a", encoding="utf-8") as f:
            for w in new:
                f.write(w + "\n")
    return len(new)


def main():
    if not RUN_DIRFUZZ:
        print(f"[{ts()}] [SKIP] RUN_DIRFUZZ=false")
        return

    ensure_wordlists()

    if not which(FFUF_BIN):
        raise RuntimeError(f"Missing ffuf in PATH ({FFUF_BIN}). Run bootstrap.")

    effective_wordlist = build_effective_wordlist()
    try:
        base_cnt = len(load_words(WORDLIST_BASE))
        custom_cnt = len(load_words(WORDLIST_CUSTOM))
        eff_cnt = len(load_words(effective_wordlist))

        print(f"[{ts()}] [INFO] dirfuzz wordlists base={base_cnt} custom={custom_cnt} effective={eff_cnt} learn={'yes' if DIRFUZZ_LEARN else 'no'}")
        with psycopg.connect(DB_DSN) as conn:
            selected_hosts = read_selected_hosts(conn)
            print(f"[{ts()}] [INFO] dirfuzz selected_hosts={len(selected_hosts)} tag={TAG} regex={'yes' if HOST_REGEX else 'no'} program={PROGRAM_HANDLE or '-'}")

            if not selected_hosts:
                print(f"[{ts()}] [DONE] No selected hosts. Add assets with tag '{TAG}' (asset_type domain/url) or set DIRFUZZ_HOST_REGEX.")
                return

            seeds = fetch_http_seeds(conn, selected_hosts)
            print(f"[{ts()}] [INFO] dirfuzz seeds={len(seeds)} batch={BATCH} match_codes={MATCH_CODES} rate={RATE}")
            if not seeds:
                print(f"[{ts()}] [DONE] No http seeds for selected hosts (need httpx results).")
                return

            total_targets = 0
            total_urls = 0
            total_learned = 0

            for tid, host, base_url in seeds:
                try:
                    results = run_ffuf(base_url, effective_wordlist)[:MAX_URLS_PER_HOST]

                    with conn.cursor() as cur:
                        for r in results:
                            u = r.get("url")
                            if not u:
                                continue
                            meta = {
                                "from": "dirfuzz",
                                "base_url": base_url,
                                "status": r.get("status"),
                                "length": r.get("length"),
                                "words": r.get("words"),
                                "lines": r.get("lines"),
                            }
                            upsert_url_obs(cur, tid, u, meta)
                            total_urls += 1
                    conn.commit()
                    total_targets += 1

                    learned = 0
                    if DIRFUZZ_LEARN and results:
                        tokens = extract_path_tokens_for_learning(results)[:MAX_LEARN_PER_HOST]
                        learned = append_with_anew(tokens, WORDLIST_CUSTOM)
                        total_learned += learned

                    print(f"[{ts()}] [OK] host={host} base={base_url} urls_found={len(results)} learned_new={learned}")

                except Exception as e:
                    conn.rollback()
                    print(f"[{ts()}] [WARN] host={host} base={base_url} error={type(e).__name__}: {e}")

            print(f"[{ts()}] [DONE] dirfuzz targets={total_targets} url_upserts={total_urls} learned_new_total={total_learned}")
    finally:
        try:
            os.unlink(effective_wordlist)
        except Exception:
            pass


if __name__ == "__main__":
    main()
