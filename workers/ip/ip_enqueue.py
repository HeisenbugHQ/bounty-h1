#!/usr/bin/env python3
"""
workers/worker_ip_enqueue.py

Enqueue IP discovery seeds into ip_discovery_queue from v_ip_seeds.
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

PROGRAM_HANDLE = os.getenv("IP_PROGRAM_HANDLE", "").strip() or os.getenv("PROGRAM_HANDLE", "").strip()


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
        log("INFO", "PROGRAM_HANDLE (or IP_PROGRAM_HANDLE) is required but missing; set it in .env")
        sys.exit(2)

    queued_new = 0
    touched_existing = 0
    total_seeds = 0
    skipped_invalid = 0

    with psycopg.connect(DB_DSN) as conn:
        program_external_id = resolve_program_external_id(conn, PROGRAM_HANDLE)
        if not program_external_id:
            log("INFO", f"PROGRAM_HANDLE not found in programs: {PROGRAM_HANDLE} (platform=hackerone)")
            sys.exit(3)

        platform = "hackerone"

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asset_type, value
                FROM v_ip_seeds
                WHERE platform=%s AND program_external_id=%s
                """,
                (platform, program_external_id),
            )
            rows = cur.fetchall()

        total_seeds = len(rows)

        with conn.cursor() as cur:
            for asset_type, value in rows:
                seed_type = (asset_type or "").strip()
                seed_value = (value or "").strip()

                if not seed_type or not seed_value:
                    skipped_invalid += 1
                    continue

                cur.execute(
                    """
                    INSERT INTO ip_discovery_queue(
                      platform, program_external_id, seed_type, seed_value, status, tries, last_error, first_seen_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, 'new', 0, NULL, now(), now())
                    ON CONFLICT (platform, program_external_id, seed_type, seed_value)
                    DO UPDATE SET
                      last_seen_at=now(),
                      status=CASE
                        WHEN ip_discovery_queue.status='error' THEN 'new'
                        ELSE ip_discovery_queue.status
                      END
                    RETURNING (xmax = 0) AS inserted;
                    """,
                    (platform, program_external_id, seed_type, seed_value),
                )
                was_inserted = cur.fetchone()[0]
                if was_inserted:
                    queued_new += 1
                else:
                    touched_existing += 1

        conn.commit()

    log(
        "INFO",
        f"queued_new={queued_new} touched_existing={touched_existing} total_seeds={total_seeds} skipped_invalid={skipped_invalid}",
    )
    log("DONE", "ip_discovery_queue enqueue complete")


if __name__ == "__main__":
    main()
