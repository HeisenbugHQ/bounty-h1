#!/usr/bin/env python3
"""
sync_yeswehack.py

Sync YesWeHack programs/scopes into the normalized schema.

Requirements:
- DB_DSN
- YESWEHACK_PROGRAMS_URL (list endpoint)
- optional YESWEHACK_SCOPES_URL_TEMPLATE (format with {program_id})
- YESWEHACK_API_TOKEN (or YESWEHACK_AUTH_HEADER)

Notes:
- Idempotent upserts into programs/scopes (platform='yeswehack')
- Canonicalization via lib.sync_common.match_or_create_canonical
"""

import json
import os
import sys
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from lib.sync_common import (
    normalize_asset_type,
    upsert_program,
    upsert_scope,
    derive_fingerprints_from_scopes,
    derive_fingerprints_from_program,
    upsert_program_fingerprint,
    match_or_create_canonical,
)

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PLATFORM = "yeswehack"
PROGRAMS_URL = os.getenv("YESWEHACK_PROGRAMS_URL", "").strip()
SCOPES_URL_TEMPLATE = os.getenv("YESWEHACK_SCOPES_URL_TEMPLATE", "").strip()
TOKEN = os.getenv("YESWEHACK_API_TOKEN", "").strip()
AUTH_HEADER = os.getenv("YESWEHACK_AUTH_HEADER", "").strip()
TOKEN_TYPE = os.getenv("YESWEHACK_TOKEN_TYPE", "Bearer").strip() or "Bearer"

HTTP_TIMEOUT = int(os.getenv("YESWEHACK_HTTP_TIMEOUT", "60"))
HTTP_RETRIES = int(os.getenv("YESWEHACK_HTTP_RETRIES", "3"))
HTTP_RETRY_SLEEP = float(os.getenv("YESWEHACK_HTTP_RETRY_SLEEP", "2"))


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def build_headers() -> dict:
    if AUTH_HEADER:
        try:
            k, v = AUTH_HEADER.split(":", 1)
            return {k.strip(): v.strip()}
        except Exception:
            return {}
    if TOKEN:
        return {"Authorization": f"{TOKEN_TYPE} {TOKEN}"}
    return {}


def request_json(session: requests.Session, url: str, params=None) -> Optional[dict]:
    last_txt = ""
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            r = session.get(url, headers=build_headers(), params=params, timeout=HTTP_TIMEOUT)
            st = r.status_code
            last_txt = r.text or ""
            if st in (401, 403):
                log("[FATAL] YesWeHack API requires a token. Set YESWEHACK_API_TOKEN in .env.")
                return None
            if st == 429 or (500 <= st <= 599):
                sleep_s = HTTP_RETRY_SLEEP * attempt
                log(f"[WARN] HTTP {st} {url} attempt={attempt}/{HTTP_RETRIES} sleep={sleep_s:.1f}s")
                time.sleep(sleep_s)
                continue
            ct = (r.headers.get("content-type", "") or "").lower()
            if "json" in ct:
                return r.json()
            return json.loads(last_txt)
        except Exception as e:
            sleep_s = HTTP_RETRY_SLEEP * attempt
            log(f"[WARN] request error {type(e).__name__}: {e} attempt={attempt}/{HTTP_RETRIES} sleep={sleep_s:.1f}s")
            time.sleep(sleep_s)
    log(f"[FATAL] fetch failed: {url} ({last_txt[:200]})")
    return None


def extract_programs(data: Any) -> list[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "programs", "results", "items"):
            v = data.get(key)
            if isinstance(v, list):
                return v
    return []


def extract_scopes(program_item: dict) -> list[dict]:
    for key in ("scopes", "targets", "in_scope", "scope"):
        v = program_item.get(key)
        if isinstance(v, list):
            return v
    return []


def clean_identifier(asset_type: str, identifier: str) -> str:
    ident = (identifier or "").strip()
    if not ident:
        return ""
    if asset_type in ("domain", "wildcard"):
        return ident.lower().rstrip(".")
    if asset_type == "url":
        try:
            p = urlparse(ident)
            if p.scheme and p.netloc:
                host = p.netloc.lower()
                return f"{p.scheme.lower()}://{host}{p.path or ''}"
        except Exception:
            pass
        return ident
    return ident


def main():
    if not TOKEN and not AUTH_HEADER:
        raise RuntimeError("Missing YESWEHACK_API_TOKEN (or YESWEHACK_AUTH_HEADER) in .env")
    if not PROGRAMS_URL:
        raise RuntimeError("Missing YESWEHACK_PROGRAMS_URL in .env")

    s = requests.Session()
    s.headers.update({"User-Agent": "bounty-h1-sync/1.0"})

    programs_upserted = 0
    scopes_upserted = 0
    canonical_linked = 0
    canonical_created = 0
    ambiguous = 0

    data = request_json(s, PROGRAMS_URL)
    if not data:
        sys.exit(2)

    programs = extract_programs(data)
    if not programs:
        log("[WARN] no programs found in response")

    with psycopg.connect(DB_DSN) as conn:
        conn.autocommit = False

        for item in programs:
            external_id = str(item.get("id") or item.get("program_id") or item.get("uuid") or item.get("code") or item.get("handle") or "").strip()
            if not external_id:
                continue
            handle = item.get("handle") or item.get("slug") or item.get("code")
            name = item.get("name") or item.get("title") or handle
            policy = item.get("policy") or item.get("url") or item.get("website")

            upsert_program(conn, PLATFORM, external_id, handle, name, None, None, policy, item)
            programs_upserted += 1

            scopes = extract_scopes(item)
            if not scopes and SCOPES_URL_TEMPLATE:
                url = SCOPES_URL_TEMPLATE.format(program_id=external_id)
                sdata = request_json(s, url)
                scopes = extract_programs(sdata) if sdata else []

            if scopes:
                with conn.cursor() as cur:
                    for sc in scopes:
                        raw_type = sc.get("asset_type") or sc.get("type") or sc.get("asset")
                        identifier = sc.get("identifier") or sc.get("asset_identifier") or sc.get("target") or sc.get("value")
                        identifier = (identifier or "").strip()
                        if not identifier:
                            continue
                        asset_type = normalize_asset_type(PLATFORM, raw_type, identifier)
                        identifier = clean_identifier(asset_type, identifier)
                        eligible_for_bounty = sc.get("eligible_for_bounty")
                        if eligible_for_bounty is None:
                            eligible_for_bounty = sc.get("eligible_for_submission")
                        if eligible_for_bounty is None:
                            eligible_for_bounty = True
                        instruction = sc.get("instruction") or sc.get("note") or sc.get("description")

                        upsert_scope(cur, PLATFORM, external_id, asset_type, identifier, bool(eligible_for_bounty), instruction, sc)
                        scopes_upserted += 1

            # canonicalization
            program_obj = {
                "platform": PLATFORM,
                "external_id": external_id,
                "handle": handle,
                "name": name,
                "website": item.get("website") or item.get("url"),
                "policy": policy,
                "raw_json": item,
            }
            canonical_id = match_or_create_canonical(conn, program_obj)
            domains = derive_fingerprints_from_scopes(conn, PLATFORM, external_id)
            for d in domains:
                upsert_program_fingerprint(conn, canonical_id, "domain", d, weight=10)
            fp = derive_fingerprints_from_program(program_obj)
            if fp.get("website_host"):
                upsert_program_fingerprint(conn, canonical_id, "website_host", fp["website_host"], weight=8)

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT confidence, reasons
                    FROM program_identities
                    WHERE platform=%s AND program_external_id=%s
                    LIMIT 1
                    """,
                    (PLATFORM, external_id),
                )
                row = cur.fetchone()
            if row:
                conf = int(row[0] or 0)
                reasons = row[1] or {}
                if reasons.get("ambiguous"):
                    ambiguous += 1
                elif conf >= 80:
                    canonical_linked += 1
                else:
                    canonical_created += 1

        conn.commit()

    log(
        f"[DONE] programs_upserted={programs_upserted} scopes_upserted={scopes_upserted} "
        f"canonical_linked={canonical_linked} canonical_created={canonical_created} ambiguous={ambiguous}"
    )


if __name__ == "__main__":
    main()
