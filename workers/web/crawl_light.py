#!/usr/bin/env python3
"""
workers/web/crawl_light.py

Light crawler for attack surface expansion:
- seeds from v_latest_http_by_target (final_url/url)
- only same-host navigation (strict netloc match)
- depth <= 2 by default
- cap per host URLs to avoid explosions
- stores:
  - url_observations source='crawl'
  - param_observations source='crawl'

Env (.env):
  DB_DSN=...

Optional:
  CRAWL_BATCH=30              # number of targets per run
  CRAWL_DEPTH=2
  CRAWL_MAX_URLS_PER_HOST=250
  CRAWL_TIMEOUT=12
  CRAWL_MAX_BYTES=1500000
  CRAWL_USER_AGENT="bounty-recon/1.0"
  CRAWL_ONLY_2XX_3XX=true
"""

import os
import re
from collections import deque
from datetime import datetime
from urllib.parse import urlparse, urljoin, urldefrag, parse_qsl

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

BATCH = int(os.getenv("CRAWL_BATCH", "30"))
DEPTH = int(os.getenv("CRAWL_DEPTH", "2"))
MAX_URLS_PER_HOST = int(os.getenv("CRAWL_MAX_URLS_PER_HOST", "250"))
TIMEOUT = int(os.getenv("CRAWL_TIMEOUT", "12"))
MAX_BYTES = int(os.getenv("CRAWL_MAX_BYTES", "1500000"))
UA = os.getenv("CRAWL_USER_AGENT", "bounty-recon/1.0")
ONLY_2XX_3XX = os.getenv("CRAWL_ONLY_2XX_3XX", "true").strip().lower() == "true"

ATTR_URL_RE = re.compile(r"""(?i)\b(?:href|src|action)\s*=\s*["']([^"'#\s]+)""")
PLAIN_URL_RE = re.compile(r"""https?://[^\s"'<>]+""", re.IGNORECASE)


def ts():
    return datetime.now().strftime("%H:%M:%S")


def norm_url(u: str) -> str:
    return (u or "").strip()


def normalize_crawl_url(u: str) -> str:
    u = norm_url(u)
    if not u:
        return u
    u, _ = urldefrag(u)  # remove #fragment
    return u


def same_host(a: str, b: str) -> bool:
    try:
        pa = urlparse(a)
        pb = urlparse(b)
        return pa.scheme in ("http", "https") and pb.scheme in ("http", "https") and pa.netloc.lower() == pb.netloc.lower()
    except Exception:
        return False


def extract_params(u: str) -> list[str]:
    try:
        qs = urlparse(u).query
        if not qs:
            return []
        return sorted({k for k, _ in parse_qsl(qs, keep_blank_values=True) if k})
    except Exception:
        return []


def http_get(url: str):
    import requests
    headers = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
    ct = (r.headers.get("content-type") or "").strip()
    body = r.content or b""
    if len(body) > MAX_BYTES:
        body = body[:MAX_BYTES]
    return int(r.status_code), ct, body, r.url


def fetch_seed_targets(cur):
    status_filter = ""
    if ONLY_2XX_3XX:
        status_filter = "AND h.status_code BETWEEN 200 AND 399"

    cur.execute(
        f"""
        SELECT t.id, t.host, COALESCE(h.final_url, h.url) AS seed_url, h.status_code, h.content_type
        FROM targets t
        JOIN v_latest_http_by_target h ON h.target_id=t.id
        WHERE COALESCE(h.final_url, h.url) IS NOT NULL
          {status_filter}
          AND (
            h.content_type ILIKE 'text/html%%'
            OR h.content_type ILIKE '%%text/html%%'
            OR h.content_type IS NULL
          )
        ORDER BY
          CASE
            WHEN h.status_code BETWEEN 200 AND 399
             AND (h.content_type ILIKE 'text/html%%' OR h.content_type ILIKE '%%text/html%%')
            THEN 0
            ELSE 1
          END,
          h.observed_at DESC
        LIMIT %s
        """,
        (BATCH,),
    )
    out = []
    for tid, host, seed_url, sc, ct in cur.fetchall():
        out.append((int(tid), host, norm_url(seed_url)))
    return out


def upsert_url_obs(cur, target_id: int, url: str, source: str, meta=None):
    cur.execute(
        """
        INSERT INTO url_observations(target_id, url, method, source, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,'GET',%s,%s,now(),now())
        ON CONFLICT (target_id, url, source)
        DO UPDATE SET last_seen_at=now(), meta=url_observations.meta || EXCLUDED.meta
        """,
        (target_id, url, source, Json(meta or {})),
    )


def upsert_param_obs(cur, target_id: int, url: str, param_name: str, source: str, confidence: int = 55, meta=None):
    cur.execute(
        """
        INSERT INTO param_observations(target_id, url, param_name, source, confidence, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,%s,%s,%s,%s,now(),now())
        ON CONFLICT (target_id, url, param_name, source)
        DO UPDATE SET
          last_seen_at=now(),
          confidence=GREATEST(param_observations.confidence, EXCLUDED.confidence),
          meta=param_observations.meta || EXCLUDED.meta
        """,
        (target_id, url, param_name, source, int(confidence), Json(meta or {})),
    )


def extract_links(base_url: str, html_text: str) -> set[str]:
    found = set()

    for m in ATTR_URL_RE.finditer(html_text):
        raw = m.group(1)
        if not raw:
            continue
        u = urljoin(base_url, raw.strip())
        u = normalize_crawl_url(u)
        if u.startswith("http://") or u.startswith("https://"):
            found.add(u)

    for m in PLAIN_URL_RE.finditer(html_text):
        u = normalize_crawl_url(m.group(0))
        if u.startswith("http://") or u.startswith("https://"):
            found.add(u)

    return found


def crawl_one_target(conn, target_id: int, seed_url: str):
    visited = set()
    q = deque()
    q.append((seed_url, 0))
    visited.add(seed_url)

    urls_added = 0
    params_added = 0
    pages_fetched = 0

    with conn.cursor() as cur:
        # store seed
        upsert_url_obs(cur, target_id, seed_url, "crawl", meta={"kind": "seed"})
        for p in extract_params(seed_url):
            upsert_param_obs(cur, target_id, seed_url, p, "crawl", confidence=55, meta={"from": "seed"})
            params_added += 1
        urls_added += 1

        while q and len(visited) < MAX_URLS_PER_HOST:
            url, depth = q.popleft()
            if depth > DEPTH:
                continue

            try:
                status, ct, body, final_url = http_get(url)
                pages_fetched += 1

                upsert_url_obs(cur, target_id, final_url, "crawl", meta={"kind": "page", "status": status, "content_type": ct})
                urls_added += 1

                # only parse html-ish
                if "text/html" not in (ct or "").lower():
                    continue

                text = body.decode("utf-8", errors="ignore")
                links = extract_links(final_url, text)

                for u in links:
                    if len(visited) >= MAX_URLS_PER_HOST:
                        break
                    if not same_host(seed_url, u):
                        continue
                    if u in visited:
                        continue
                    visited.add(u)
                    q.append((u, depth + 1))

                    upsert_url_obs(cur, target_id, u, "crawl", meta={"from": final_url, "depth": depth + 1})
                    urls_added += 1

                    for p in extract_params(u):
                        upsert_param_obs(cur, target_id, u, p, "crawl", confidence=55, meta={"from": final_url})
                        params_added += 1

            except Exception as e:
                # keep going, but record minimal error into url_observations
                upsert_url_obs(cur, target_id, url, "crawl", meta={"kind": "error", "error": f"{type(e).__name__}: {e}"})

    return pages_fetched, urls_added, params_added, len(visited)


def main():
    total_targets = 0
    total_pages = 0
    total_urls = 0
    total_params = 0

    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            seeds = fetch_seed_targets(cur)

        print(f"[{ts()}] [INFO] crawl targets={len(seeds)} batch={BATCH} depth={DEPTH} max_urls_per_host={MAX_URLS_PER_HOST}")
        if not seeds:
            print(f"[{ts()}] [DONE] crawl: nothing to do")
            return

        for tid, host, seed_url in seeds:
            try:
                pages, urls, params, visited = crawl_one_target(conn, tid, seed_url)
                conn.commit()
                total_targets += 1
                total_pages += pages
                total_urls += urls
                total_params += params
                print(f"[{ts()}] [OK] host={host} seed={seed_url} pages={pages} urls_upserted={urls} params_upserted={params} visited={visited}")
            except Exception as e:
                conn.rollback()
                print(f"[{ts()}] [WARN] host={host} seed={seed_url} error={type(e).__name__}: {e}")

    print(f"[{ts()}] [DONE] crawl targets={total_targets} pages={total_pages} url_upserts={total_urls} param_upserts={total_params}")


if __name__ == "__main__":
    main()
