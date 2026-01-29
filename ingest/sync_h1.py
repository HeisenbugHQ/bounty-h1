#!/usr/bin/env python3
"""
sync_h1.py (FULL CATALOG)

Popola il DB in modo idempotente secondo lo schema:
- programs  (tutti i programmi)
- scopes    (structured_scopes per programma, se disponibile)

NON fa reset schema.
NON filtra per bounty.
NON è pensato per essere eseguito ad ogni test.

Env:
  DB_DSN (required)
  H1_USERNAME / H1_TOKEN (required)

Optional tuning:
  H1_PAGE_SIZE=100
  H1_HTTP_TIMEOUT=60
  H1_HTTP_RETRIES=4
  H1_HTTP_RETRY_SLEEP=2.0
  H1_MAX_PAGES=5000
"""

import os
import sys
import time
import json
from typing import Optional, Tuple, Any

import requests
import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
H1_USERNAME = os.getenv("H1_USERNAME")
H1_TOKEN = os.getenv("H1_TOKEN")

if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")
if not H1_USERNAME or not H1_TOKEN:
    raise RuntimeError("Missing H1_USERNAME/H1_TOKEN in .env")

API = "https://api.hackerone.com/v1"
AUTH = (H1_USERNAME, H1_TOKEN)

PAGE_SIZE = int(os.getenv("H1_PAGE_SIZE", "100"))
HTTP_TIMEOUT = int(os.getenv("H1_HTTP_TIMEOUT", "60"))
HTTP_RETRIES = int(os.getenv("H1_HTTP_RETRIES", "4"))
HTTP_RETRY_SLEEP = float(os.getenv("H1_HTTP_RETRY_SLEEP", "2.0"))
MAX_PAGES = int(os.getenv("H1_MAX_PAGES", "5000"))


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def request_json(session: requests.Session, url: str, params=None) -> Tuple[int, str, Optional[dict]]:
    """
    Retry minimale su 429 e 5xx.
    Return: (status_code, text, json_or_none)
    """
    last_txt = ""
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            r = session.get(url, auth=AUTH, params=params, timeout=HTTP_TIMEOUT)
            st = r.status_code
            last_txt = r.text or ""

            if st == 429 or (500 <= st <= 599):
                sleep_s = HTTP_RETRY_SLEEP * attempt
                log(f"[WARN] HTTP {st} {url} attempt={attempt}/{HTTP_RETRIES} sleep={sleep_s:.1f}s")
                time.sleep(sleep_s)
                continue

            ct = (r.headers.get("content-type", "") or "").lower()
            data = r.json() if ct.startswith("application/json") else None
            return st, last_txt, data

        except Exception as e:
            sleep_s = HTTP_RETRY_SLEEP * attempt
            log(f"[WARN] request error {type(e).__name__}: {e} attempt={attempt}/{HTTP_RETRIES} sleep={sleep_s:.1f}s")
            time.sleep(sleep_s)

    return 0, last_txt[:500], None


def upsert_program(conn, prog_id: str, handle: Optional[str], name: Optional[str],
                  offers_bounties: Any, currency: Any, policy: Any, raw_obj: dict):
    """
    programs schema:
      platform, external_id, handle, name, offers_bounties, currency, policy, raw_json, first_seen_at, last_seen_at
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO programs(
              platform, external_id, handle, name,
              offers_bounties, currency, policy, raw_json,
              first_seen_at, last_seen_at
            )
            VALUES ('hackerone', %s, %s, %s, %s, %s, %s, %s::jsonb, now(), now())
            ON CONFLICT (platform, external_id)
            DO UPDATE SET
              handle=EXCLUDED.handle,
              name=EXCLUDED.name,
              offers_bounties=EXCLUDED.offers_bounties,
              currency=EXCLUDED.currency,
              policy=EXCLUDED.policy,
              raw_json=EXCLUDED.raw_json,
              last_seen_at=now();
            """,
            (prog_id, handle, name, offers_bounties, currency, policy, json.dumps(raw_obj)),
        )


def upsert_scope(cur,
                program_external_id: str,
                asset_type: Optional[str],
                identifier: str,
                eligible_for_bounty: bool,
                instruction: Optional[str],
                raw_json: dict):
    """
    scopes schema:
      platform, program_external_id, asset_type, identifier,
      eligible_for_bounty, instruction, raw_json, first_seen_at, last_seen_at
    """
    cur.execute(
        """
        INSERT INTO scopes(
          platform, program_external_id, asset_type, identifier,
          eligible_for_bounty, instruction, raw_json, first_seen_at, last_seen_at
        )
        VALUES ('hackerone', %s,%s,%s,%s,%s,%s,now(),now())
        ON CONFLICT (platform, program_external_id, identifier)
        DO UPDATE SET
          asset_type=EXCLUDED.asset_type,
          eligible_for_bounty=EXCLUDED.eligible_for_bounty,
          instruction=EXCLUDED.instruction,
          raw_json=EXCLUDED.raw_json,
          last_seen_at=now();
        """,
        (
            program_external_id,
            asset_type,
            identifier,
            bool(eligible_for_bounty),
            instruction,
            Json(raw_json or {}),
        ),
    )


def parse_structured_scope_item(item: dict):
    """
    HackerOne structured scopes: ci adattiamo a possibili varianti chiavi.
    """
    attrs = item.get("attributes", {}) or {}

    asset_type = (attrs.get("asset_type") or attrs.get("type") or attrs.get("asset") or "").strip() or None

    identifier = (
        attrs.get("asset_identifier")
        or attrs.get("identifier")
        or attrs.get("asset")
        or attrs.get("value")
        or ""
    )
    identifier = (identifier or "").strip()

    instruction = attrs.get("instruction")
    instruction = str(instruction) if instruction is not None else None

    e_bounty = attrs.get("eligible_for_bounty")
    if e_bounty is None:
        e_bounty = attrs.get("eligible_for_submission")
    if e_bounty is None:
        e_bounty = True

    return asset_type, identifier, bool(e_bounty), instruction, item


def main():
    log("Starting HackerOne sync (FULL CATALOG: programs + structured_scopes)")
    log(f"DB_DSN={DB_DSN}")

    s = requests.Session()
    s.headers.update({"User-Agent": "bounty-h1-sync/1.0"})

    with psycopg.connect(DB_DSN) as conn:
        conn.autocommit = False

        page = 1
        programs_seen = 0
        programs_upserted = 0
        scopes_upserted = 0
        scopes_404 = 0
        scopes_other_err = 0

        while True:
            st, txt, data = request_json(
                s,
                f"{API}/hackers/programs",
                params={"page[number]": page, "page[size]": PAGE_SIZE},
            )
            if st != 200 or not data:
                log(f"[FATAL] programs fetch failed HTTP {st}: {txt[:200]}")
                sys.exit(2)

            items = data.get("data", []) or []
            if not items:
                break

            log(f"Programs page {page}: {len(items)} items")

            # 1) upsert programs della pagina
            try:
                for it in items:
                    programs_seen += 1
                    attrs = it.get("attributes", {}) or {}

                    prog_id = str(it.get("id"))
                    handle = (attrs.get("handle") or "").strip() or None
                    name = attrs.get("name")
                    offers_bounties = attrs.get("offers_bounties")
                    currency = attrs.get("currency")
                    policy = attrs.get("submission_state")

                    upsert_program(conn, prog_id, handle, name, offers_bounties, currency, policy, it)
                    programs_upserted += 1

                conn.commit()
            except Exception as e:
                conn.rollback()
                log(f"[FATAL] program upsert failed: {type(e).__name__}: {e}")
                sys.exit(3)

            # 2) scopes per programma (handle)
            for it in items:
                attrs = it.get("attributes", {}) or {}

                prog_id = str(it.get("id"))
                handle = (attrs.get("handle") or "").strip()
                if not handle:
                    continue

                url = f"{API}/hackers/programs/{handle}/structured_scopes"
                s_st, s_txt, s_data = request_json(s, url)

                if s_st == 404:
                    scopes_404 += 1
                    continue
                if s_st != 200 or not s_data:
                    scopes_other_err += 1
                    continue

                scopes = s_data.get("data", []) or []
                try:
                    with conn.cursor() as cur:
                        for scope_item in scopes:
                            asset_type, identifier, e_bounty, instruction, raw_item = parse_structured_scope_item(scope_item)
                            if not identifier:
                                continue
                            upsert_scope(cur, prog_id, asset_type, identifier, e_bounty, instruction, raw_item)
                            scopes_upserted += 1
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    log(f"[WARN] scope upsert failed for {handle} (id={prog_id}): {type(e).__name__}: {e}")

            page += 1
            if page > MAX_PAGES:
                log(f"[WARN] reached MAX_PAGES={MAX_PAGES}, stopping")
                break

        log(
            "[DONE] "
            f"programs_seen={programs_seen} programs_upserted={programs_upserted} "
            f"scopes_upserted={scopes_upserted} scopes_404={scopes_404} scopes_other_err={scopes_other_err}"
        )


if __name__ == "__main__":
    main()
