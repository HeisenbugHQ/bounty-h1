#!/usr/bin/env python3
import os
import sys
import json
import argparse
from datetime import datetime

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")


VALID_TYPES = {"domain", "wildcard", "url", "ip", "cidr", "asn", "other"}


def ts():
    return datetime.now().strftime("%H:%M:%S")


def norm(s: str) -> str:
    return (s or "").strip()


def resolve_program_external_id(conn, handle: str) -> str:
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
        row = cur.fetchone()
        if not row:
            cur.execute(
                """
                SELECT handle, external_id, name
                FROM programs
                WHERE platform='hackerone'
                ORDER BY handle
                LIMIT 20
                """
            )
            top = cur.fetchall()
            print(f"[{ts()}] [ERROR] Program handle not found: {handle}", file=sys.stderr)
            print(f"[{ts()}] Some handles (top 20):", file=sys.stderr)
            for h, eid, name in top:
                print(f"  - {h} ({eid}) {name}", file=sys.stderr)
            raise SystemExit(2)
        return str(row[0])


def main():
    ap = argparse.ArgumentParser(description="Add manual/import asset to DB")
    ap.add_argument("--platform", default="manual", help="asset platform label (default: manual)")
    ap.add_argument("--program", help="program handle (H1 handle, e.g. adobe)")
    ap.add_argument("--program-external-id", help="program external_id (e.g. 347)")
    ap.add_argument("--type", required=True, choices=sorted(VALID_TYPES))
    ap.add_argument("--value", required=True)
    ap.add_argument("--status", default="active", choices=["active", "paused", "archived"])
    ap.add_argument("--tag", action="append", default=[], help="repeatable tags")
    ap.add_argument("--note", default="")
    ap.add_argument("--json", dest="raw_json", default="", help="raw json string (optional)")
    args = ap.parse_args()

    if not args.program and not args.program_external_id:
        print(f"[{ts()}] [ERROR] Provide --program or --program-external-id", file=sys.stderr)
        raise SystemExit(2)

    raw = {}
    if args.raw_json:
        try:
            raw = json.loads(args.raw_json)
        except Exception as e:
            print(f"[{ts()}] [ERROR] invalid --json: {e}", file=sys.stderr)
            raise SystemExit(2)

    with psycopg.connect(DB_DSN) as conn:
        program_external_id = args.program_external_id
        if not program_external_id:
            program_external_id = resolve_program_external_id(conn, args.program)

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets(platform, program_external_id, asset_type, value, tags, note, status, raw_json, first_seen_at, last_seen_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
                ON CONFLICT (platform, program_external_id, asset_type, value)
                DO UPDATE SET
                  last_seen_at=now(),
                  status=EXCLUDED.status,
                  tags=(SELECT ARRAY(SELECT DISTINCT unnest(assets.tags || EXCLUDED.tags))),
                  note=CASE WHEN EXCLUDED.note <> '' THEN EXCLUDED.note ELSE assets.note END,
                  raw_json=assets.raw_json || EXCLUDED.raw_json
                """,
                (
                    args.platform,
                    program_external_id,
                    args.type,
                    norm(args.value),
                    args.tag,
                    norm(args.note),
                    args.status,
                    Json(raw),
                ),
            )
        conn.commit()

    print(f"[{ts()}] [OK] asset upserted program_external_id={program_external_id} type={args.type} value={args.value}")


if __name__ == "__main__":
    main()
