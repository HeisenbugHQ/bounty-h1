#!/usr/bin/env python3
"""
workers/web/param_mine_js.py

JS surface mining + LEARNING:
- params -> wordlists/custom/params_custom.txt
- paths tokens -> wordlists/custom/paths_custom.txt
- endpoints -> wordlists/custom/endpoints_custom.txt

Inputs:
- v_latest_http_by_target (base_url per target)

Writes:
- url_observations (source='js')
- param_observations (source='js')

Env:
  DB_DSN=...
  RUN_PARAM_JS=true/false
  PARAM_JS_BATCH=20
  PARAM_JS_TIMEOUT=20
  PARAM_JS_MAX_PAGES_PER_TARGET=1
  PARAM_JS_MAX_JS_PER_TARGET=30
  PARAM_JS_MAX_JS_BYTES=2000000
  PARAM_JS_PROGRAM_HANDLE=adobe (optional)

Learning toggles:
  PARAM_LEARN=true/false
  PATH_LEARN=true/false
  ENDPOINT_LEARN=true/false

Files:
  PARAMS_CUSTOM_FILE=wordlists/custom/params_custom.txt
  PATHS_CUSTOM_FILE=wordlists/custom/paths_custom.txt
  ENDPOINTS_CUSTOM_FILE=wordlists/custom/endpoints_custom.txt
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

RUN = os.getenv("RUN_PARAM_JS", "true").strip().lower() == "true"
BATCH = int(os.getenv("PARAM_JS_BATCH", "20"))
TIMEOUT = int(os.getenv("PARAM_JS_TIMEOUT", "20"))

MAX_PAGES_PER_TARGET = int(os.getenv("PARAM_JS_MAX_PAGES_PER_TARGET", "1"))
MAX_JS_PER_TARGET = int(os.getenv("PARAM_JS_MAX_JS_PER_TARGET", "30"))
MAX_JS_BYTES = int(os.getenv("PARAM_JS_MAX_JS_BYTES", "2000000"))

PROGRAM_HANDLE = os.getenv("PARAM_JS_PROGRAM_HANDLE", "").strip()

PARAM_LEARN = os.getenv("PARAM_LEARN", "true").strip().lower() == "true"
PATH_LEARN = os.getenv("PATH_LEARN", "true").strip().lower() == "true"
ENDPOINT_LEARN = os.getenv("ENDPOINT_LEARN", "true").strip().lower() == "true"

PARAMS_CUSTOM_FILE = os.getenv("PARAMS_CUSTOM_FILE", "wordlists/custom/params_custom.txt").strip()
PATHS_CUSTOM_FILE = os.getenv("PATHS_CUSTOM_FILE", "wordlists/custom/paths_custom.txt").strip()
ENDPOINTS_CUSTOM_FILE = os.getenv("ENDPOINTS_CUSTOM_FILE", "wordlists/custom/endpoints_custom.txt").strip()
ANEW_BIN = os.getenv("ANEW_BIN", "anew").strip()

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
ABS_URL_RE = re.compile(r"""https?://[a-z0-9\.\-_:]+(?:/[^\s"'<>]*)?""", re.IGNORECASE)
REL_ENDPOINT_RE = re.compile(r"""(?:"|')(/(?:api|graphql|v1|v2|v3|oauth|auth|sso|login|admin|internal|private)[^"'<> \t\r\n]*)""", re.IGNORECASE)
PATH_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,60}[a-z0-9]$", re.IGNORECASE)
PARAM_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,80}$")


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
                (prog, BATCH),
            )
        else:
            cur.execute(
                """
                SELECT t.id, t.host, COALESCE(h.final_url, h.url) AS base_url
                FROM targets t
                JOIN v_latest_http_by_target h ON h.target_id=t.id
                WHERE t.platform='hackerone'
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
        return [(int(a), str(b), str(c)) for a, b, c in cur.fetchall()]


def upsert_url_obs(cur, target_id: int, url: str, meta: dict):
    cur.execute(
        """
        INSERT INTO url_observations(target_id, url, method, source, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,'GET','js',%s,now(),now())
        ON CONFLICT (target_id, url, source)
        DO UPDATE SET last_seen_at=now(), meta=url_observations.meta || EXCLUDED.meta
        """,
        (target_id, url, Json(meta or {})),
    )


def upsert_param_obs(cur, target_id: int, url: str, param_name: str, meta: dict):
    cur.execute(
        """
        INSERT INTO param_observations(target_id, url, param_name, source, confidence, meta, first_seen_at, last_seen_at)
        VALUES (%s,%s,%s,'js',70,%s,now(),now())
        ON CONFLICT (target_id, url, param_name, source)
        DO UPDATE SET last_seen_at=now(), meta=param_observations.meta || EXCLUDED.meta
        """,
        (target_id, url, param_name, Json(meta or {})),
    )


def extract_params_from_url(url: str) -> list[str]:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query or "", keep_blank_values=True)
        out = []
        for k in qs.keys():
            k = (k or "").strip()
            if k and PARAM_NAME_RE.match(k):
                out.append(k)
        return out
    except Exception:
        return []


def extract_path_tokens_from_urls(urls: list[str]) -> list[str]:
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
            if PATH_TOKEN_RE.match(segs[0]):
                tokens.append(segs[0].lower())
            if len(segs) >= 2 and PATH_TOKEN_RE.match(segs[0]) and PATH_TOKEN_RE.match(segs[1]):
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


def safe_get(session: requests.Session, url: str, timeout: int) -> requests.Response:
    r = session.get(url, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r


def normalize_candidate_url(seed_url: str, candidate: str) -> str | None:
    c = (candidate or "").strip()
    if not c:
        return None
    if c.startswith("//"):
        c = "https:" + c
    if c.startswith("http://") or c.startswith("https://"):
        return c
    if c.startswith("/"):
        return urljoin(seed_url, c)
    if c.startswith("./") or c.startswith("../"):
        return urljoin(seed_url, c)
    return None


def mine_js_text(seed_url: str, js_text: str) -> tuple[list[str], list[str], list[str]]:
    urls = []
    endpoints = []
    params = []

    for m in ABS_URL_RE.finditer(js_text or ""):
        u = m.group(0).strip()
        if u:
            urls.append(u)

    for m in REL_ENDPOINT_RE.finditer(js_text or ""):
        ep = m.group(1).strip()
        if ep:
            endpoints.append(ep)

    for u in urls:
        params.extend(extract_params_from_url(u))

    def uniq(xs):
        s = set()
        out = []
        for x in xs:
            x = (x or "").strip()
            if x and x not in s:
                s.add(x)
                out.append(x)
        return out

    return uniq(urls), uniq(endpoints), uniq(params)


def main():
    if not RUN:
        print(f"[{ts()}] [SKIP] RUN_PARAM_JS=false")
        return

    ensure_file(PARAMS_CUSTOM_FILE)
    ensure_file(PATHS_CUSTOM_FILE)
    ensure_file(ENDPOINTS_CUSTOM_FILE)

    with psycopg.connect(DB_DSN) as conn:
        queue = fetch_queue(conn)
        print(f"[{ts()}] [INFO] param_js queue={len(queue)} batch={BATCH} learn(params/paths/endpoints)={PARAM_LEARN}/{PATH_LEARN}/{ENDPOINT_LEARN}")

        s = requests.Session()
        s.headers.update({"User-Agent": "bounty-h1-param-js/1.0"})

        url_upserts = 0
        param_upserts = 0
        learned_params = 0
        learned_paths = 0
        learned_endpoints = 0

        for target_id, host, base_url in queue:
            try:
                r = safe_get(s, base_url, TIMEOUT)
                ct = (r.headers.get("content-type") or "").lower()
                if "text/html" not in ct and "application/xhtml" not in ct:
                    print(f"[{ts()}] [OK] host={host} non-html seed_ct={ct.split(';')[0] if ct else 'unknown'}")
                    continue

                html = r.text or ""
                script_srcs = []
                for m in SCRIPT_SRC_RE.finditer(html):
                    u = normalize_candidate_url(r.url, m.group(1))
                    if u:
                        script_srcs.append(u)

                # dedupe, cap
                seen = set()
                uniq_srcs = []
                for u in script_srcs:
                    if u not in seen:
                        seen.add(u)
                        uniq_srcs.append(u)
                    if len(uniq_srcs) >= MAX_JS_PER_TARGET:
                        break

                all_urls_found = []
                all_endpoints_found = []
                all_params_found = []

                # fetch JS and mine
                fetched = 0
                for js_url in uniq_srcs:
                    try:
                        jr = safe_get(s, js_url, TIMEOUT)
                        cjt = (jr.headers.get("content-type") or "").lower()
                        if "javascript" not in cjt and "ecmascript" not in cjt and "text/plain" not in cjt:
                            continue
                        if jr.content and len(jr.content) > MAX_JS_BYTES:
                            continue
                        js_text = jr.text or ""
                        urls, endpoints, params = mine_js_text(r.url, js_text)
                        all_urls_found.extend(urls)
                        all_endpoints_found.extend(endpoints)
                        all_params_found.extend(params)
                        fetched += 1
                    except Exception:
                        continue

                # turn endpoints into absolute URLs under seed origin
                seed_origin = f"{urlparse(r.url).scheme}://{urlparse(r.url).netloc}"
                endpoint_urls = [urljoin(seed_origin, ep) for ep in all_endpoints_found if ep.startswith("/")]

                # unify for path learning
                all_for_paths = list(all_urls_found) + list(endpoint_urls)

                with conn.cursor() as cur:
                    # upsert URLs discovered
                    for u in all_urls_found:
                        upsert_url_obs(cur, target_id, u, {"from": "js", "seed": base_url, "final_seed": r.url})
                        url_upserts += 1
                        for pn in extract_params_from_url(u):
                            upsert_param_obs(cur, target_id, u, pn, {"from": "js"})
                            param_upserts += 1

                    for u in endpoint_urls:
                        upsert_url_obs(cur, target_id, u, {"from": "js", "seed": base_url, "final_seed": r.url, "kind": "endpoint"})
                        url_upserts += 1

                    # also store params found directly from JS text as generic (url = seed final)
                    for pn in all_params_found:
                        pn = (pn or "").strip()
                        if pn and PARAM_NAME_RE.match(pn):
                            upsert_param_obs(cur, target_id, r.url, pn, {"from": "js", "note": "found_in_js_text"})
                            param_upserts += 1

                conn.commit()

                lp = le = lpa = 0
                if PARAM_LEARN and all_params_found:
                    lpa = append_with_anew(all_params_found, PARAMS_CUSTOM_FILE)
                    learned_params += lpa
                if ENDPOINT_LEARN and all_endpoints_found:
                    le = append_with_anew(all_endpoints_found, ENDPOINTS_CUSTOM_FILE)
                    learned_endpoints += le
                if PATH_LEARN and all_for_paths:
                    tokens = extract_path_tokens_from_urls(all_for_paths)
                    lp = append_with_anew(tokens, PATHS_CUSTOM_FILE)
                    learned_paths += lp

                print(f"[{ts()}] [OK] host={host} js_scripts={len(uniq_srcs)} fetched={fetched} urls={len(set(all_urls_found))} eps={len(set(all_endpoints_found))} learned(p/paths/eps)={lpa}/{lp}/{le}")

            except Exception as e:
                conn.rollback()
                print(f"[{ts()}] [WARN] host={host} error={type(e).__name__}: {e}")

        print(f"[{ts()}] [DONE] url_upserts={url_upserts} param_upserts={param_upserts} learned_params={learned_params} learned_paths={learned_paths} learned_endpoints={learned_endpoints}")


if __name__ == "__main__":
    main()
