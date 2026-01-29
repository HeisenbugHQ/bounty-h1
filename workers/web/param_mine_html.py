#!/usr/bin/env python3
"""
workers/worker_param_mine_html.py

HTML surface mining + LEARNING:
- params -> wordlists/custom/params_custom.txt
- paths tokens -> wordlists/custom/paths_custom.txt

Inputs:
- v_latest_http_by_target (base_url per target)

Writes:
- url_observations (source='html')
- param_observations (source='html')

Env:
  DB_DSN=...
  RUN_PARAM_HTML=true/false
  PARAM_HTML_BATCH=20
  PARAM_HTML_TIMEOUT=15
  PARAM_HTML_MAX_URLS_PER_TARGET=300
  PARAM_PROGRAM_HANDLE=adobe (optional)

Learning toggles:
  PARAM_LEARN=true/false
  PATH_LEARN=true/false

Files:
  PARAMS_CUSTOM_FILE=wordlists/custom/params_custom.txt
  PATHS_CUSTOM_FILE=wordlists/custom/paths_custom.txt
  ANEW_BIN=anew
"""

import os
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs

import requests
import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

RUN = os.getenv("RUN_PARAM_HTML", "true").strip().lower() == "true"
BATCH = int(os.getenv("PARAM_HTML_BATCH", "20"))
TIMEOUT = int(os.getenv("PARAM_HTML_TIMEOUT", "15"))
MAX_URLS_PER_TARGET = int(os.getenv("PARAM_HTML_MAX_URLS_PER_TARGET", "300"))

PROGRAM_HANDLE = os.getenv("PARAM_PROGRAM_HANDLE", "").strip()

PARAM_LEARN = os.getenv("PARAM_LEARN", "true").strip().lower() == "true"
PATH_LEARN = os.getenv("PATH_LEARN", "true").strip().lower() == "true"

PARAMS_CUSTOM_FILE = os.getenv("PARAMS_CUSTOM_FILE", "wordlists/custom/params_custom.txt").strip()
PATHS_CUSTOM_FILE = os.getenv("PATHS_CUSTOM_FILE", "wordlists/custom/paths_custom.txt").strip()
ANEW_BIN = os.getenv("ANEW_BIN", "anew").strip()

A_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
FORM_ACTION_RE = re.compile(r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
PARAM_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,80}$")
TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,60}[a-z0-9]$", re.IGNORECASE)


def ts():
    return datetime.now().strftime("%H:%M:%S")


def which(binname: str) -> str | None:
    import shutil
    return shutil.which(binname)


def ensure_file(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        open(path, "a", encoding="utf-8").close()


def append_with_anew(lines: list[str], path: str) -> int:
    if not lines:
        return 0
    ensure_file(path)

    seen = set()
    uniq = []
    for x in lines:
        x = (x or "").strip()
        if x and x not in seen:
            seen.add(x)
            uniq.append(x)

    if which(ANEW_BIN):
        import subprocess
        p = subprocess.run([ANEW_BIN, path], input="\n".join(uniq) + "\n", text=True, capture_output=True)
        return len([ln for ln in p.stdout.splitlines() if ln.strip()])

    # fallback
    existing = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            existing.add(ln.strip())
    new = [x for x in uniq if x not in existing]
    if new:
        with open(path, "a", encoding="utf-8") as f:
            for x in new:
                f.write(x + "\n")
    return len(new)


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


def fetch_queue(conn):
    prog = resolve_program_external_id(conn, PROGRAM_HANDLE)
    with conn.cursor() as cur:
        if prog:
            cur.execute(
                """
                SELECT t.id, t.host, COALESCE(h.final_url, h.url) AS base_url
                FROM targets t
                JOIN v_latest_http_by_target h ON h.target_id=t.id
                WHERE t.platform='hackerone'
                  AND t.program_external_id=%s
                ORDER BY h.observed_at DESC
                LIMIT %s
                """,
                (prog, BATCH),
            )
        else:
            cur.execute(
                """
                SELECT t.id, t.host, COALESCE(h.final_url, h.url) AS base_url
                FROM targets t
                JOIN v_latest_http_by_target h ON h.target_id=t.id
                WHERE t.platform='hackerone'
                ORDER BY h.observed_at DESC
                LIMIT %s
                """,
                (BATCH,),
            )
        return [(int(a), str(b), str(c)) for a, b, c in cur.fetchall()]


def upsert_url_obs(cur, target_id: int, url: str, meta: dict):
    cur.execute(
        """
        INSERT INTO url_observations(target_id, url, method, source, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,'GET','html',%s,now(),now())
        ON CONFLICT (target_id, url, source)
        DO UPDATE SET last_seen_at=now(), meta=url_observations.meta || EXCLUDED.meta
        """,
        (target_id, url, Json(meta or {})),
    )


def upsert_param_obs(cur, target_id: int, url: str, param_name: str, meta: dict):
    cur.execute(
        """
        INSERT INTO param_observations(target_id, url, param_name, source, confidence, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,%s,'html',60,%s,now(),now())
        ON CONFLICT (target_id, url, param_name, source)
        DO UPDATE SET last_seen_at=now(), meta=param_observations.meta || EXCLUDED.meta
        """,
        (target_id, url, param_name, Json(meta or {})),
    )


def safe_abs_urls(base_url: str, html: str) -> list[str]:
    out = []
    for m in A_HREF_RE.finditer(html):
        href = m.group(1).strip()
        if not href or href.startswith(("javascript:", "mailto:")):
            continue
        out.append(urljoin(base_url, href))

    for m in FORM_ACTION_RE.finditer(html):
        act = m.group(1).strip()
        if not act:
            continue
        out.append(urljoin(base_url, act))

    # dedupe + cap
    seen = set()
    uniq = []
    for u in out:
        u = u.strip()
        if not u:
            continue
        if u not in seen:
            seen.add(u)
            uniq.append(u)
        if len(uniq) >= MAX_URLS_PER_TARGET:
            break
    return uniq


def extract_params(url: str) -> list[str]:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query or "", keep_blank_values=True)
        names = []
        for k in qs.keys():
            k = (k or "").strip()
            if k and PARAM_NAME_RE.match(k):
                names.append(k)
        return names
    except Exception:
        return []


def extract_path_tokens(urls: list[str]) -> list[str]:
    tokens = []
    for u in urls:
        try:
            p = urlparse(u)
            path = (p.path or "").strip("/")
            if not path:
                continue
            segs = [s for s in path.split("/") if s]
            if not segs:
                continue
            # token 1 segment
            if TOKEN_RE.match(segs[0]):
                tokens.append(segs[0].lower())
            # token 2 segments
            if len(segs) >= 2 and TOKEN_RE.match(segs[0]) and TOKEN_RE.match(segs[1]):
                tokens.append((segs[0] + "/" + segs[1]).lower())
        except Exception:
            continue

    seen = set()
    uniq = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def main():
    if not RUN:
        print(f"[{ts()}] [SKIP] RUN_PARAM_HTML=false")
        return

    ensure_file(PARAMS_CUSTOM_FILE)
    ensure_file(PATHS_CUSTOM_FILE)

    url_upserts = 0
    param_upserts = 0
    learned_params = 0
    learned_paths = 0

    with psycopg.connect(DB_DSN) as conn:
        queue = fetch_queue(conn)
        print(f"[{ts()}] [INFO] param_html queue={len(queue)} batch={BATCH} learn_params={PARAM_LEARN} learn_paths={PATH_LEARN}")

        s = requests.Session()
        s.headers.update({"User-Agent": "bounty-h1-param-html/1.0"})

        for target_id, host, base_url in queue:
            try:
                r = s.get(base_url, timeout=TIMEOUT, allow_redirects=True)
                ct = (r.headers.get("content-type") or "").lower()
                if "text/html" not in ct and "application/xhtml" not in ct:
                    print(f"[{ts()}] [OK] host={host} non-html ct={ct.split(';')[0] if ct else 'unknown'}")
                    continue

                html = r.text or ""
                urls = safe_abs_urls(r.url, html)

                discovered_params = []
                with conn.cursor() as cur:
                    for u in urls:
                        upsert_url_obs(cur, target_id, u, {"from": "html", "seed": base_url, "final_seed": r.url})
                        url_upserts += 1

                        for pn in extract_params(u):
                            upsert_param_obs(cur, target_id, u, pn, {"from": "html"})
                            param_upserts += 1
                            discovered_params.append(pn)

                conn.commit()

                newly_p = 0
                newly_paths = 0
                if PARAM_LEARN and discovered_params:
                    newly_p = append_with_anew(discovered_params, PARAMS_CUSTOM_FILE)
                    learned_params += newly_p

                if PATH_LEARN and urls:
                    tokens = extract_path_tokens(urls)
                    newly_paths = append_with_anew(tokens, PATHS_CUSTOM_FILE)
                    learned_paths += newly_paths

                print(f"[{ts()}] [OK] host={host} html_urls={len(urls)} params={len(set(discovered_params))} learned(params/paths)={newly_p}/{newly_paths}")

            except Exception as e:
                conn.rollback()
                print(f"[{ts()}] [WARN] host={host} error={type(e).__name__}: {e}")

    print(f"[{ts()}] [DONE] url_upserts={url_upserts} param_upserts={param_upserts} learned_params={learned_params} learned_paths={learned_paths}")


if __name__ == "__main__":
    main()
