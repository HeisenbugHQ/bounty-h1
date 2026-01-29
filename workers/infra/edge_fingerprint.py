#!/usr/bin/env python3
"""
workers/worker_edge_fingerprint.py

Edge/CDN/WAF hints from latest HTTP observations + LEARNING infra hints.

Inputs:
- targets
- v_latest_http_by_target (headers_selected, server_header, cdn, cname, ip, favicon_mmh3, final_url)

Writes:
- edge_fingerprint_latest (upsert by target_id)

Learning:
- providers/hints -> wordlists/custom/infra_hints_custom.txt

Env:
  DB_DSN=...
  RUN_EDGE_FP=true/false
  EDGE_FP_BATCH=50
  EDGE_FP_PROGRAM_HANDLE=adobe (optional)

Files:
  INFRA_HINTS_CUSTOM_FILE=wordlists/custom/infra_hints_custom.txt
  ANEW_BIN=anew
"""

import os
import re
from datetime import datetime

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

RUN = os.getenv("RUN_EDGE_FP", "true").strip().lower() == "true"
BATCH = int(os.getenv("EDGE_FP_BATCH", "50"))
PROGRAM_HANDLE = os.getenv("EDGE_FP_PROGRAM_HANDLE", "").strip()

INFRA_HINTS_CUSTOM_FILE = os.getenv("INFRA_HINTS_CUSTOM_FILE", "wordlists/custom/infra_hints_custom.txt").strip()
ANEW_BIN = os.getenv("ANEW_BIN", "anew").strip()


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
                SELECT t.id, t.host,
                       h.final_url, h.url, h.status_code, h.server_header, h.content_type,
                       h.cname, h.cdn, h.favicon_mmh3, h.headers_selected
                FROM targets t
                JOIN v_latest_http_by_target h ON h.target_id=t.id
                WHERE t.platform='hackerone' AND t.program_external_id=%s
                ORDER BY h.observed_at DESC
                LIMIT %s
                """,
                (prog, BATCH),
            )
        else:
            cur.execute(
                """
                SELECT t.id, t.host,
                       h.final_url, h.url, h.status_code, h.server_header, h.content_type,
                       h.cname, h.cdn, h.favicon_mmh3, h.headers_selected
                FROM targets t
                JOIN v_latest_http_by_target h ON h.target_id=t.id
                WHERE t.platform='hackerone'
                ORDER BY h.observed_at DESC
                LIMIT %s
                """,
                (BATCH,),
            )
        return cur.fetchall()


def pick_header(headers: dict, key: str) -> str:
    if not isinstance(headers, dict):
        return ""
    for k, v in headers.items():
        if (k or "").lower() == key.lower():
            if isinstance(v, list):
                return ", ".join([str(x) for x in v if x is not None])
            return str(v)
    return ""


def detect(headers: dict, server_header: str, cname: str, cdn_field: str) -> tuple[str, str, int, list[str], dict]:
    h = headers or {}
    sh = (server_header or "").lower()
    cn = (cname or "").lower()
    cdn = (cdn_field or "").lower()

    hints = []
    cdn_provider = ""
    waf_provider = ""
    confidence = 0

    via = pick_header(h, "via").lower()
    cf_ray = pick_header(h, "cf-ray")
    cf_cache = pick_header(h, "cf-cache-status")
    akamai = pick_header(h, "akamai-grn") or pick_header(h, "x-akamai-transformed")
    fastly = pick_header(h, "x-served-by") or pick_header(h, "x-cache") or pick_header(h, "x-fastly-request-id")
    incapsula = pick_header(h, "x-iinfo") or pick_header(h, "x-cdn")
    imperva = pick_header(h, "x-cdn") or pick_header(h, "x-imp")
    sucuri = pick_header(h, "x-sucuri-id") or pick_header(h, "x-sucuri-cache")
    aws_alb = pick_header(h, "x-amzn-trace-id") or pick_header(h, "x-amz-cf-id") or pick_header(h, "x-amz-request-id")

    # CDN detection
    if cf_ray or "cloudflare" in sh or "cloudflare" in cn or "cloudflare" in cdn or ("cloudflare" in via):
        cdn_provider = "cloudflare"
        confidence += 35
        hints.append("cdn:cloudflare")
    if akamai or "akamai" in cn or "akamai" in cdn or "akamaitechnologies" in cn:
        cdn_provider = cdn_provider or "akamai"
        confidence += 30
        hints.append("cdn:akamai")
    if fastly or "fastly" in cn or "fastly" in cdn:
        cdn_provider = cdn_provider or "fastly"
        confidence += 25
        hints.append("cdn:fastly")
    if "amazonaws" in cn or aws_alb or "cloudfront" in cn or "cloudfront" in cdn:
        cdn_provider = cdn_provider or "aws"
        confidence += 20
        hints.append("cdn:aws")

    # WAF-ish detection (very heuristic)
    if "incap" in cn or incapsula or "incapsula" in cdn:
        waf_provider = "imperva/incapsula"
        confidence += 25
        hints.append("waf:imperva")
    if sucuri:
        waf_provider = waf_provider or "sucuri"
        confidence += 20
        hints.append("waf:sucuri")
    if "cf-" in (cf_cache or "").lower() or cf_ray:
        waf_provider = waf_provider or "cloudflare"
        confidence += 10
        hints.append("waf:cloudflare")

    # clamp
    confidence = max(0, min(100, confidence))

    raw = {
        "server_header": server_header,
        "cname": cname,
        "cdn_field": cdn_field,
        "via": via,
        "cf_ray": cf_ray,
        "cf_cache_status": cf_cache,
        "akamai_headers": bool(akamai),
        "fastly_headers": bool(fastly),
        "aws_headers": bool(aws_alb),
        "incapsula_headers": bool(incapsula),
        "sucuri_headers": bool(sucuri),
    }
    return cdn_provider, waf_provider, confidence, hints, raw


def upsert_edge(cur, target_id: int, cdn_provider: str, waf_provider: str, confidence: int, raw_json: dict):
    cur.execute(
        """
        INSERT INTO edge_fingerprint_latest(target_id, cdn_provider, waf_provider, confidence, raw_json, first_seen_at, last_seen_at)
        VALUES (%s,%s,%s,%s,%s,now(),now())
        ON CONFLICT (target_id)
        DO UPDATE SET
          cdn_provider=EXCLUDED.cdn_provider,
          waf_provider=EXCLUDED.waf_provider,
          confidence=EXCLUDED.confidence,
          raw_json=edge_fingerprint_latest.raw_json || EXCLUDED.raw_json,
          last_seen_at=now()
        """,
        (target_id, cdn_provider or None, waf_provider or None, int(confidence), Json(raw_json or {})),
    )


def main():
    if not RUN:
        print(f"[{ts()}] [SKIP] RUN_EDGE_FP=false")
        return

    ensure_file(INFRA_HINTS_CUSTOM_FILE)

    with psycopg.connect(DB_DSN) as conn:
        rows = fetch_queue(conn)
        print(f"[{ts()}] [INFO] edge_fp queue={len(rows)} batch={BATCH}")

        upserts = 0
        learned = 0

        for (target_id, host, final_url, url, status_code, server_header, content_type, cname, cdn_field, favicon_mmh3, headers_selected) in rows:
            try:
                headers = headers_selected or {}
                cdn_provider, waf_provider, conf, hints, raw = detect(headers, server_header, cname, cdn_field)

                raw["host"] = host
                raw["url"] = final_url or url
                raw["status_code"] = status_code
                raw["content_type"] = content_type
                raw["favicon_mmh3"] = favicon_mmh3

                with conn.cursor() as cur:
                    upsert_edge(cur, int(target_id), cdn_provider, waf_provider, conf, raw)
                conn.commit()
                upserts += 1

                new = append_with_anew(hints, INFRA_HINTS_CUSTOM_FILE) if hints else 0
                learned += new

                print(f"[{ts()}] [OK] host={host} cdn={cdn_provider or '-'} waf={waf_provider or '-'} conf={conf} learned={new}")

            except Exception as e:
                conn.rollback()
                print(f"[{ts()}] [WARN] host={host} error={type(e).__name__}: {e}")

        print(f"[{ts()}] [DONE] edge_fp upserts={upserts} learned_hints={learned}")


if __name__ == "__main__":
    main()
