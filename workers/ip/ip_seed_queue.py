#!/usr/bin/env python3
"""
workers/worker_ip_seed_queue.py

Populate ip_seed_queue from v_ip_seeds for a program.
"""

import os
import sys
from datetime import datetime

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PROGRAM_HANDLE = os.getenv("PROGRAM_HANDLE", "").strip()


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(level: str, msg: str):
    print(f"[{ts()}] [{level}] {msg}", flush=True)


def resolve_program_external_id(conn, handle: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT external_id
            FROM programs
            WHERE platform='hackerone' AND handle=%s
            LIMIT 1
            """,
            (handle,),
        )
        r = cur.fetchone()
        return str(r[0]) if r else None


def main():
    if not PROGRAM_HANDLE:
        log("INFO", "PROGRAM_HANDLE is required but missing; set it in .env")
        sys.exit(2)

    seeds_total = 0
    inserted = 0
    updated = 0
    skipped_invalid = 0

    with psycopg.connect(DB_DSN) as conn:
        program_external_id = resolve_program_external_id(conn, PROGRAM_HANDLE)
        if not program_external_id:
            log("INFO", f"PROGRAM_HANDLE not found in programs: {PROGRAM_HANDLE} (platform=hackerone)")
            sys.exit(3)

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asset_type, value, note
                FROM v_ip_seeds
                WHERE platform='hackerone' AND program_external_id=%s
                """,
                (program_external_id,),
            )
            rows = cur.fetchall()

        seeds_total = len(rows)

        with conn.cursor() as cur:
            for asset_type, value, note in rows:\n                seed_type = 'cidr' if asset_type == 'cidr' else ('asn' if asset_type == 'asn' else 'ip')\n                seed_value = (value or '').strip().lower()\n\n                if seed_type == 'asn':\n                    seed_value = seed_value.removeprefix('as')\n\n                if not seed_value:\n                    skipped_invalid += 1\n                    continue
                cur.execute(
                    """
                    INSERT INTO ip_seed_queue(
                      platform, program_external_id, seed_type, seed_value, status, error, first_seen_at, last_seen_at
                    )
                    VALUES ('hackerone', %s, %s, %s, 'new', NULL, now(), now())
                    ON CONFLICT (platform, program_external_id, seed_type, seed_value)
                    DO UPDATE SET
                      last_seen_at=now(),
                      status=CASE
                        WHEN ip_seed_queue.status='error' THEN 'new'
                        ELSE ip_seed_queue.status
                      END
                    RETURNING (xmax = 0) AS inserted;
                    """,
                    (program_external_id, seed_type, seed_value),
                )
                was_inserted = cur.fetchone()[0]
                if was_inserted:
                    inserted += 1
                else:
                    updated += 1

        conn.commit()

    log(
        "INFO",
        f"seeds_total={seeds_total} inserted={inserted} updated={updated} skipped_invalid={skipped_invalid}",
    )
    log("DONE", "ip_seed_queue sync complete")


if __name__ == "__main__":
    main()
