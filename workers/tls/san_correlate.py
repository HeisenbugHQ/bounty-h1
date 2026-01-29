#!/usr/bin/env python3
"""
workers/worker_san_correlate.py

Extract SAN domains from tls_certs_latest and stage them into san_candidates.

Schema assumptions (as per your init_db.sql):
- programs(platform, external_id, handle, ...)
- targets(id, platform, program_external_id, host, ...)
- tls_certs_latest(target_id, port, san_domains TEXT[], ...)
- san_candidates(platform, program_external_id, san_domain, registrable_domain, source_target_id, source_host, source_port, confidence, reasons, status, ...)

No usage of targets.san_scanned_at (does not exist).

Env:
  DB_DSN (required)
  RUN_SAN=true/false               (default true)
  SAN_PROGRAM_HANDLE=adobe         (optional)
  SAN_BATCH=500                    (default 500)
  SAN_MIN_LABELS=2                 (default 2)   # ignore junk
  SAN_MIN_CONF=40                  (default 40)
  SAN_STATUS_DEFAULT=new           (default new)
"""

import os
import re
from datetime import datetime
from typing import Optional, List, Tuple

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

RUN = os.getenv("RUN_SAN", "true").strip().lower() == "true"
PROGRAM_HANDLE = os.getenv("SAN_PROGRAM_HANDLE", "").strip()

BATCH = int(os.getenv("SAN_BATCH", "500"))
SAN_MIN_LABELS = int(os.getenv("SAN_MIN_LABELS", "2"))
SAN_MIN_CONF = int(os.getenv("SAN_MIN_CONF", "40"))
STATUS_DEFAULT = os.getenv("SAN_STATUS_DEFAULT", "new").strip() or "new"

HOST_RE = re.compile(r"^[a-z0-9][a-z0-9\.\-]{0,252}[a-z0-9]$", re.IGNORECASE)


def ts():
    return datetime.now().strftime("%H:%M:%S")


def resolve_program_external_id(conn, handle: str) -> Optional[str]:
    if not handle:
        return None
    with conn.cursor() as cur:
        cur.execute(
            "SELECT external_id FROM programs WHERE platform='hackerone' AND handle=%s LIMIT 1",
            (handle,),
        )
        r = cur.fetchone()
        return str(r[0]) if r else None


def normalize_san(x: str) -> Optional[str]:
    x = (x or "").strip().lower()
    if not x:
        return None

    # drop wildcard prefix
    if x.startswith("*."):
        x = x[2:]

    # drop trailing dot
    if x.endswith("."):
        x = x[:-1]

    # very basic validation
    if len(x) < 3 or len(x) > 253:
        return None
    if not HOST_RE.match(x):
        return None
    if x.count(".") + 1 < SAN_MIN_LABELS:
        return None

    return x


def registrable_domain_guess(host: str) -> Optional[str]:
    """
    Minimal (not PSL-accurate). Good enough for grouping / sanity.
    If you want PSL accuracy later: add publicsuffix2/tldextract.
    """
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def fetch_tls_rows(cur, program_external_id: Optional[str], limit: int) -> List[Tuple[int, str, int, list]]:
    """
    Returns: [(target_id, host, port, san_domains[]), ...]
    """
    if program_external_id:
        cur.execute(
            """
            SELECT t.id, t.host, c.port, c.san_domains
            FROM tls_certs_latest c
            JOIN targets t ON t.id=c.target_id
            WHERE t.platform='hackerone'
              AND t.program_external_id=%s
              AND c.san_domains IS NOT NULL
              AND cardinality(c.san_domains) > 0
            ORDER BY c.last_seen_at DESC NULLS LAST
            LIMIT %s
            """,
            (program_external_id, limit),
        )
    else:
        cur.execute(
            """
            SELECT t.id, t.host, c.port, c.san_domains
            FROM tls_certs_latest c
            JOIN targets t ON t.id=c.target_id
            WHERE t.platform='hackerone'
              AND c.san_domains IS NOT NULL
              AND cardinality(c.san_domains) > 0
            ORDER BY c.last_seen_at DESC NULLS LAST
            LIMIT %s
            """,
            (limit,),
        )
    rows = []
    for tid, host, port, sans in cur.fetchall():
        rows.append((int(tid), str(host), int(port), list(sans or [])))
    return rows


def upsert_candidate(cur,
                     program_external_id: str,
                     san_domain: str,
                     registrable_domain: Optional[str],
                     source_target_id: int,
                     source_host: str,
                     source_port: int,
                     confidence: int,
                     reasons: dict,
                     status: str):
    cur.execute(
        """
        INSERT INTO san_candidates(
          platform, program_external_id,
          san_domain, registrable_domain,
          source_target_id, source_host, source_port,
          confidence, reasons, status,
          first_seen_at, last_seen_at
        )
        VALUES (
          'hackerone', %s,
          %s, %s,
          %s, %s, %s,
          %s, %s, %s,
          now(), now()
        )
        ON CONFLICT (platform, program_external_id, san_domain)
        DO UPDATE SET
          registrable_domain = COALESCE(EXCLUDED.registrable_domain, san_candidates.registrable_domain),
          source_target_id = COALESCE(EXCLUDED.source_target_id, san_candidates.source_target_id),
          source_host = COALESCE(EXCLUDED.source_host, san_candidates.source_host),
          source_port = COALESCE(EXCLUDED.source_port, san_candidates.source_port),
          confidence = GREATEST(san_candidates.confidence, EXCLUDED.confidence),
          reasons = san_candidates.reasons || EXCLUDED.reasons,
          last_seen_at = now();
        """,
        (
            program_external_id,
            san_domain,
            registrable_domain,
            source_target_id,
            source_host,
            source_port,
            int(confidence),
            Json(reasons or {}),
            status,
        ),
    )


def main():
    if not RUN:
        print(f"[{ts()}] [SKIP] RUN_SAN=false")
        return

    staged = 0
    skipped_low_conf = 0
    tls_rows = 0

    with psycopg.connect(DB_DSN) as conn:
        prog_ext = resolve_program_external_id(conn, PROGRAM_HANDLE)
        with conn.cursor() as cur:
            rows = fetch_tls_rows(cur, prog_ext, BATCH)

        tls_rows = len(rows)
        print(f"[{ts()}] [INFO] san_correlate tls_rows={tls_rows} batch={BATCH} program={PROGRAM_HANDLE or '-'}")

        if not rows:
            print(f"[{ts()}] [DONE] No TLS rows with SANs.")
            return

        with conn.cursor() as cur:
            for target_id, host, port, sans in rows:
                # program_external_id must come from targets
                cur.execute("SELECT program_external_id FROM targets WHERE id=%s LIMIT 1", (target_id,))
                r = cur.fetchone()
                if not r:
                    continue
                program_external_id = str(r[0])

                for raw in sans:
                    sd = normalize_san(str(raw))
                    if not sd:
                        continue

                    reg = registrable_domain_guess(sd)
                    conf = 60
                    reasons = {
                        "from": "tls_san",
                        "source_host": host,
                        "source_port": port,
                    }

                    if conf < SAN_MIN_CONF:
                        skipped_low_conf += 1
                        continue

                    upsert_candidate(
                        cur,
                        program_external_id=program_external_id,
                        san_domain=sd,
                        registrable_domain=reg,
                        source_target_id=target_id,
                        source_host=host,
                        source_port=port,
                        confidence=conf,
                        reasons=reasons,
                        status=STATUS_DEFAULT,
                    )
                    staged += 1

        conn.commit()

    print(f"[{ts()}] [DONE] tls_rows={tls_rows} staged={staged} skipped_low_conf={skipped_low_conf}")


if __name__ == "__main__":
    main()
