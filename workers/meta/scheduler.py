#!/usr/bin/env python3
"""
workers/meta/scheduler.py

Simple scheduler that enqueues tasks based on new events:
- new targets -> http_reinject
- new ports   -> nmap_services
- new urls    -> crawl_light
- new tls     -> san_correlate

Idempotency: avoids enqueueing duplicate 'new/running' task_type per program.
"""

import os
from datetime import datetime, timedelta

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PROGRAM_HANDLE = os.getenv("PROGRAM_HANDLE", "").strip()
EVENT_LIMIT = int(os.getenv("SCHED_EVENT_LIMIT", "200"))


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str):
    print(f"[{ts()}] {msg}", flush=True)


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


def enqueue_task(conn, platform: str, program_external_id: str, task_type: str, priority: int) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO task_queue(platform, program_external_id, task_type, priority, status, tries, last_error, run_after, first_seen_at, last_seen_at)
            SELECT %s,%s,%s,%s,'new',0,NULL,now(),now(),now()
            WHERE NOT EXISTS (
              SELECT 1 FROM task_queue
              WHERE platform=%s AND program_external_id=%s AND task_type=%s
                AND status IN ('new','running')
            )
            RETURNING (xmax = 0) AS inserted;
            """,
            (platform, program_external_id, task_type, int(priority),
             platform, program_external_id, task_type),
        )
        row = cur.fetchone()
        return bool(row[0]) if row else False


def main():
    platform = "hackerone"
    with psycopg.connect(DB_DSN) as conn:
        prog_ext = resolve_program_external_id(conn, PROGRAM_HANDLE)
        if PROGRAM_HANDLE and not prog_ext:
            log(f"[WARN] PROGRAM_HANDLE={PROGRAM_HANDLE} not found; nothing to schedule")
            return

        if not prog_ext:
            log("[WARN] PROGRAM_HANDLE missing; scheduler requires a program handle")
            return

        counts = {"targets": 0, "ports": 0, "urls": 0, "tls": 0, "tasks": 0}

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id
                FROM targets
                WHERE platform=%s AND program_external_id=%s
                  AND first_seen_at = last_seen_at
                ORDER BY first_seen_at DESC
                LIMIT %s
                """,
                (platform, prog_ext, EVENT_LIMIT),
            )
            counts["targets"] = len(cur.fetchall())

            cur.execute(
                """
                SELECT target_id
                FROM ports_latest
                WHERE target_id IN (
                  SELECT id FROM targets WHERE platform=%s AND program_external_id=%s
                )
                  AND first_seen_at = last_seen_at
                LIMIT %s
                """,
                (platform, prog_ext, EVENT_LIMIT),
            )
            counts["ports"] = len(cur.fetchall())

            cur.execute(
                """
                SELECT target_id
                FROM url_observations
                WHERE target_id IN (
                  SELECT id FROM targets WHERE platform=%s AND program_external_id=%s
                )
                  AND first_seen_at = last_seen_at
                LIMIT %s
                """,
                (platform, prog_ext, EVENT_LIMIT),
            )
            counts["urls"] = len(cur.fetchall())

            cur.execute(
                """
                SELECT target_id
                FROM tls_certs_latest
                WHERE target_id IN (
                  SELECT id FROM targets WHERE platform=%s AND program_external_id=%s
                )
                  AND first_seen_at = last_seen_at
                LIMIT %s
                """,
                (platform, prog_ext, EVENT_LIMIT),
            )
            counts["tls"] = len(cur.fetchall())

        if counts["targets"] > 0:
            if enqueue_task(conn, platform, prog_ext, "http_reinject", 90):
                counts["tasks"] += 1
        if counts["ports"] > 0:
            if enqueue_task(conn, platform, prog_ext, "nmap_services", 80):
                counts["tasks"] += 1
        if counts["urls"] > 0:
            if enqueue_task(conn, platform, prog_ext, "crawl_light", 70):
                counts["tasks"] += 1
        if counts["tls"] > 0:
            if enqueue_task(conn, platform, prog_ext, "san_correlate", 60):
                counts["tasks"] += 1

        conn.commit()

    log(
        f"[DONE] events targets={counts['targets']} ports={counts['ports']} "
        f"urls={counts['urls']} tls={counts['tls']} tasks_enqueued={counts['tasks']}"
    )


if __name__ == "__main__":
    main()
