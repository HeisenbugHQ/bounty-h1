#!/usr/bin/env python3
"""
workers/worker_wayback_urls.py

Wayback URLs ingestion + LEARNING:
- paths tokens -> wordlists/custom/paths_custom.txt
- endpoints -> wordlists/custom/endpoints_custom.txt

Writes:
- url_observations (source='wayback')

Env:
  DB_DSN=...
  RUN_WAYBACK=true/false
  WAYBACK_BATCH=20
  WAYBACK_TIMEOUT=20
  WAYBACK_MAX_URLS_PER_HOST=500
  WAYBACK_COLLAPSE=true/false
  WAYBACK_PROGRAM_HANDLE=adobe (optional)

Learning toggles:
  PATH_LEARN=true/false
  ENDPOINT_LEARN=true/false

Files:
  PATHS_CUSTOM_FILE=wordlists/custom/paths_custom.txt
  ENDPOINTS_CUSTOM_FILE=wordlists/custom/endpoints_custom.txt
  ANEW_BIN=anew
"""

import os
import re
from datetime import datetime
from urllib.parse import urlparse

import requests
import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

RUN = os.getenv("RUN_WAYBACK", "true").strip().lower() == "true"
BATCH = int(os.getenv("WAYBACK_BATCH", "20"))
TIMEOUT = int(os.getenv("WAYBACK_TIMEOUT", "20"))
MAX_URLS_PER_HOST = int(os.getenv("WAYBACK_MAX_URLS_PER_HOST", "500"))
COLLAPSE = os.getenv("WAYBACK_COLLAPSE", "true").strip().lower() == "true"
PROGRAM_HANDLE = os.getenv("WAYBACK_PROGRAM_HANDLE", "").strip()

PATH_LEARN = os.getenv("PATH_LEARN", "true").strip().lower() == "true"
ENDPOINT_LEARN = os.getenv("ENDPOINT_LEARN", "true").strip().lower() == "true"

PATHS_CUSTOM_FILE = os.getenv("PATHS_CUSTOM_FILE", "wordlists/custom/paths_custom.txt").strip()
ENDPOINTS_CUSTOM_FILE = os.getenv("ENDPOINTS_CUSTOM_FILE", "wordlists/custom/endpoints_custom.txt").strip()
ANEW_BIN = os.getenv("ANEW_BIN", "anew").strip()

TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,60}[a-z0-9]$", re.IGNORECASE)
ENDPOINT_HINT_RE = re.compile(r"""^/(api|graphql|v1|v2|v3|oauth|auth|sso|login|admin|internal|private)\b""", re.IGNORECASE)


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


def fetch_hosts(conn):
    prog = resolve_program_external_id(conn, PROGRAM_HANDLE)
    with conn.cursor() as cur:
        if prog:
            cur.execute(
                """
                SELECT id, host
                FROM targets
                WHERE platform='hackerone' AND program_external_id=%s
                ORDER BY last_seen_at DESC
                LIMIT %s
                """,
                (prog, BATCH),
            )
        else:
            cur.execute(
                """
                SELECT id, host
                FROM targets
                WHERE platform='hackerone'
                ORDER BY last_seen_at DESC
                LIMIT %s
                """,
                (BATCH,),
            )
        return [(int(a), str(b)) for a, b in cur.fetchall()]


def upsert_url_obs(cur, target_id: int, url: str, meta: dict):
    cur.execute(
        """
        INSERT INTO url_observations(target_id, url, method, source, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,'GET','wayback',%s,now(),now())
        ON CONFLICT (target_id, url, source)
        DO UPDATE SET last_seen_at=now()
        """,
        (target_id, url, Json(meta or {})),
    )


def fetch_wayback_urls(session: requests.Session, host: str) -> list[str]:
    cdx = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{host}/*",
        "output": "json",
        "fl": "original",
        "filter": "statuscode:200",
        "limit": str(MAX_URLS_PER_HOST),
    }
    if COLLAPSE:
        params["collapse"] = "urlkey"

    r = session.get(cdx, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()

    out = []
    for row in data[1:]:
        if not row:
            continue
        u = (row[0] or "").strip()
        if not u:
            continue
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith("http://") and not u.startswith("https://"):
            u = "https://" + u
        out.append(u)

    # dedupe preserve order
    seen = set()
    uniq = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def extract_endpoints_and_paths(urls: list[str]) -> tuple[list[str], list[str]]:
    endpoints = []
    paths = []

    for u in urls:
        try:
            p = urlparse(u)
            path = (p.path or "").split("?")[0]
            if not path.startswith("/"):
                continue
            if path == "/":
                continue

            segs = [s for s in path.strip("/").split("/") if s]
            if not segs:
                continue

            ep1 = "/" + segs[0]
            endpoints.append(ep1)
            if len(segs) >= 2:
                endpoints.append("/" + segs[0] + "/" + segs[1])

            if ENDPOINT_HINT_RE.match(path):
                endpoints.append(path)

            # tokens for dirfuzz
            if TOKEN_RE.match(segs[0]):
                paths.append(segs[0].lower())
            if len(segs) >= 2 and TOKEN_RE.match(segs[0]) and TOKEN_RE.match(segs[1]):
                paths.append((segs[0] + "/" + segs[1]).lower())

        except Exception:
            continue

    # uniq preserve order
    def uniq(xs):
        s = set()
        out = []
        for x in xs:
            x = x.strip()
            if x and x not in s:
                s.add(x)
                out.append(x)
        return out

    return uniq(endpoints), uniq(paths)


def main():
    if not RUN:
        print(f"[{ts()}] [SKIP] RUN_WAYBACK=false")
        return

    ensure_file(PATHS_CUSTOM_FILE)
    ensure_file(ENDPOINTS_CUSTOM_FILE)

    with psycopg.connect(DB_DSN) as conn:
        hosts = fetch_hosts(conn)
        print(f"[{ts()}] [INFO] wayback batch={len(hosts)} max_urls_per_host={MAX_URLS_PER_HOST} learn_paths={PATH_LEARN} learn_endpoints={ENDPOINT_LEARN}")

        s = requests.Session()
        s.headers.update({"User-Agent": "bounty-h1-wayback/1.0"})

        total_url_upserts = 0
        learned_paths = 0
        learned_endpoints = 0

        for target_id, host in hosts:
            try:
                urls = fetch_wayback_urls(s, host)

                with conn.cursor() as cur:
                    for u in urls:
                        upsert_url_obs(cur, target_id, u, {"from": "wayback", "host": host})
                        total_url_upserts += 1

                conn.commit()

                eps, pts = extract_endpoints_and_paths(urls)

                lp = 0
                le = 0
                if PATH_LEARN and pts:
                    lp = append_with_anew(pts, PATHS_CUSTOM_FILE)
                    learned_paths += lp
                if ENDPOINT_LEARN and eps:
                    le = append_with_anew(eps, ENDPOINTS_CUSTOM_FILE)
                    learned_endpoints += le

                print(f"[{ts()}] [OK] host={host} urls={len(urls)} learned(paths/endpoints)={lp}/{le}")

            except Exception as e:
                conn.rollback()
                print(f"[{ts()}] [WARN] host={host} error={type(e).__name__}: {e}")

        print(f"[{ts()}] [DONE] wayback url_upserts={total_url_upserts} learned_paths={learned_paths} learned_endpoints={learned_endpoints}")


if __name__ == "__main__":
    main()
