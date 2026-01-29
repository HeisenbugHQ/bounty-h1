#!/usr/bin/env python3
"""
workers/ip/ip_discovery.py

Process ip_discovery_queue entries for a program.
"""

import json
import os
import re
import sys
import time
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
import subprocess

import psycopg
import requests
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PROGRAM_HANDLE = os.getenv("PROGRAM_HANDLE", "").strip()

BATCH = int(os.getenv("IP_BATCH", "50"))
CIDR_MAX_HOSTS = int(os.getenv("IP_CIDR_MAX_HOSTS", "4096"))
RDNS_SAMPLE = int(os.getenv("IP_RDNS_SAMPLE", "200"))
ASN_CACHE_TTL_HOURS = int(os.getenv("ASN_CACHE_TTL_HOURS", "24"))

CACHE_DIR = Path("runtime/cache")

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


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


def fetch_and_mark_processing(conn, platform: str, program_external_id: str, batch: int):
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, seed_type, seed_value, tries
                FROM ip_discovery_queue
                WHERE status='new'
                  AND platform=%s
                  AND program_external_id=%s
                ORDER BY id
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (platform, program_external_id, batch),
            )
            rows = cur.fetchall()
            if rows:
                ids = [r[0] for r in rows]
                cur.execute(
                    """
                    UPDATE ip_discovery_queue
                    SET status='processing', last_seen_at=now()
                    WHERE id = ANY(%s)
                    """,
                    (ids,),
                )
            return rows


def mark_done(conn, item_id: int):
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ip_discovery_queue
                SET status='done', last_seen_at=now(), last_error=NULL
                WHERE id=%s
                """,
                (item_id,),
            )


def mark_error(conn, item_id: int, tries: int, err: str):
    next_tries = tries + 1
    status = "error" if next_tries >= 3 else "new"
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ip_discovery_queue
                SET tries=%s, status=%s, last_error=%s, last_seen_at=now()
                WHERE id=%s
                """,
                (next_tries, status, err, item_id),
            )


def upsert_ip_asset(conn, platform: str, program_external_id: str, ip_value: str, source: str, rdns: str | None = None):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ip_assets_latest(
              platform, program_external_id, ip, source, rdns, first_seen_at, last_seen_at
            )
            VALUES (%s,%s,%s,%s,%s,now(),now())
            ON CONFLICT (platform, program_external_id, ip)
            DO UPDATE SET
              last_seen_at=now(),
              source=EXCLUDED.source,
              rdns=COALESCE(EXCLUDED.rdns, ip_assets_latest.rdns)
            RETURNING (xmax = 0) AS inserted;
            """,
            (platform, program_external_id, ip_value, source, rdns),
        )
        return bool(cur.fetchone()[0])


def upsert_target(conn, platform: str, program_external_id: str, host: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO targets(platform, program_external_id, host, source_scope_identifier, first_seen_at, last_seen_at)
            VALUES (%s,%s,%s,'ip_discovery',now(),now())
            ON CONFLICT (platform, program_external_id, host)
            DO UPDATE SET last_seen_at=now()
            RETURNING (xmax = 0) AS inserted;
            """,
            (platform, program_external_id, host),
        )
        return bool(cur.fetchone()[0])


def valid_hostname(h: str) -> bool:
    if not h:
        return False
    h = h.strip().rstrip(".").lower()
    if len(h) == 0 or len(h) > 253:
        return False
    if HOST_RE.match(h) is None:
        return False
    return True


def dig_rdns(ip_value: str):
    try:
        proc = subprocess.run(
            ["dig", "+short", "-x", ip_value],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        log("WARN", "dig not found; skipping RDNS")
        return None
    except subprocess.TimeoutExpired:
        return None

    if not proc.stdout:
        return None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        host = line.rstrip(".").lower()
        if valid_hostname(host):
            return host
    return None


def normalize_asn(value: str) -> int | None:
    v = (value or "").strip().upper()
    if v.startswith("AS"):
        v = v[2:]
    if not v.isdigit():
        return None
    try:
        return int(v)
    except Exception:
        return None


def load_asn_cache(asn: int):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = CACHE_DIR / f"asn_{asn}.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        fetched_at = data.get("fetched_at")
        if not fetched_at:
            return None
        dt = datetime.fromisoformat(fetched_at)
        if datetime.now() - dt > timedelta(hours=ASN_CACHE_TTL_HOURS):
            return None
        return data
    except Exception:
        return None


def save_asn_cache(asn: int, prefixes: list[str]):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = CACHE_DIR / f"asn_{asn}.json"
    data = {
        "asn": asn,
        "fetched_at": datetime.now().isoformat(),
        "prefixes": prefixes,
    }
    p.write_text(json.dumps(data))


def fetch_asn_prefixes(asn: int):
    cached = load_asn_cache(asn)
    if cached and isinstance(cached.get("prefixes"), list):
        return [str(x) for x in cached["prefixes"]]

    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    last_err = None
    for attempt in range(3):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                last_err = f"http_{resp.status_code}"
                raise RuntimeError(last_err)
            data = resp.json()
            prefixes = []
            for p in data.get("data", {}).get("ipv4_prefixes", []):
                if "prefix" in p:
                    prefixes.append(p["prefix"])
            for p in data.get("data", {}).get("ipv6_prefixes", []):
                if "prefix" in p:
                    prefixes.append(p["prefix"])
            save_asn_cache(asn, prefixes)
            return prefixes
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(1 * (2 ** attempt))
                continue
            raise RuntimeError(f"asn_fetch_failed:{last_err}")


def enqueue_cidr(conn, platform: str, program_external_id: str, prefix: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ip_discovery_queue(
              platform, program_external_id, seed_type, seed_value, status, tries, last_error, first_seen_at, last_seen_at
            )
            VALUES (%s,%s,'cidr',%s,'new',0,NULL,now(),now())
            ON CONFLICT (platform, program_external_id, seed_type, seed_value)
            DO UPDATE SET
              last_seen_at=now(),
              status=CASE
                WHEN ip_discovery_queue.status='error' THEN 'new'
                ELSE ip_discovery_queue.status
              END
            RETURNING (xmax = 0) AS inserted;
            """,
            (platform, program_external_id, prefix),
        )
        return bool(cur.fetchone()[0])


def process_seed_ip(conn, platform: str, program_external_id: str, seed_value: str):
    ip_obj = ipaddress.ip_address(seed_value)
    ips_added = 0
    rdns_found = 0
    targets_added = 0

    rdns = dig_rdns(str(ip_obj))
    inserted = upsert_ip_asset(conn, platform, program_external_id, str(ip_obj), "seed_ip", rdns)
    if inserted:
        ips_added += 1

    if rdns:
        rdns_found += 1
        if upsert_target(conn, platform, program_external_id, rdns):
            targets_added += 1

    return {
        "ips_added": ips_added,
        "rdns_found": rdns_found,
        "targets_added": targets_added,
        "cidrs_enqueued": 0,
    }


def process_seed_cidr(conn, platform: str, program_external_id: str, seed_value: str):
    net = ipaddress.ip_network(seed_value, strict=False)
    if net.num_addresses > CIDR_MAX_HOSTS:
        raise RuntimeError(f"cidr_too_large:{net.num_addresses}")

    ips_added = 0
    rdns_found = 0
    targets_added = 0

    rdns_budget = RDNS_SAMPLE
    for ip in net.hosts():
        rdns = None
        if rdns_budget > 0:
            rdns = dig_rdns(str(ip))
            rdns_budget -= 1

        inserted = upsert_ip_asset(conn, platform, program_external_id, str(ip), "cidr", rdns)
        if inserted:
            ips_added += 1
        if rdns:
            rdns_found += 1
            if upsert_target(conn, platform, program_external_id, rdns):
                targets_added += 1

    return {
        "ips_added": ips_added,
        "rdns_found": rdns_found,
        "targets_added": targets_added,
        "cidrs_enqueued": 0,
    }


def process_seed_asn(conn, platform: str, program_external_id: str, seed_value: str):
    asn = normalize_asn(seed_value)
    if asn is None:
        raise RuntimeError("invalid_asn")

    prefixes = fetch_asn_prefixes(asn)
    cidrs_enqueued = 0
    for prefix in prefixes:
        if enqueue_cidr(conn, platform, program_external_id, prefix):
            cidrs_enqueued += 1

    return {
        "ips_added": 0,
        "rdns_found": 0,
        "targets_added": 0,
        "cidrs_enqueued": cidrs_enqueued,
    }


def main():
    if not PROGRAM_HANDLE:
        log("INFO", "PROGRAM_HANDLE is required but missing; set it in .env")
        sys.exit(2)

    with psycopg.connect(DB_DSN) as conn:
        program_external_id = resolve_program_external_id(conn, PROGRAM_HANDLE)
        if not program_external_id:
            log("INFO", f"PROGRAM_HANDLE not found in programs: {PROGRAM_HANDLE} (platform=hackerone)")
            sys.exit(3)

        platform = "hackerone"

        batch = fetch_and_mark_processing(conn, platform, program_external_id, BATCH)
        if not batch:
            log("DONE", "ip_discovery: nothing pending")
            return

        for item_id, seed_type, seed_value, tries in batch:
            seed_type = (seed_type or "").strip().lower()
            seed_value = (seed_value or "").strip()
            outcome = "done"
            counts = {"ips_added": 0, "rdns_found": 0, "targets_added": 0, "cidrs_enqueued": 0}

            try:
                if seed_type == "ip":
                    counts = process_seed_ip(conn, platform, program_external_id, seed_value)
                elif seed_type == "cidr":
                    counts = process_seed_cidr(conn, platform, program_external_id, seed_value)
                elif seed_type == "asn":
                    counts = process_seed_asn(conn, platform, program_external_id, seed_value)
                else:
                    raise RuntimeError("unknown_seed_type")

                conn.commit()
                mark_done(conn, item_id)
                outcome = "done"
            except Exception as e:
                conn.rollback()
                err = str(e)
                if err.startswith("cidr_too_large:"):
                    pass
                mark_error(conn, item_id, int(tries), err)
                outcome = f"error:{err}"

            log(
                "INFO",
                "seed=%s/%s outcome=%s ips_added=%d rdns_found=%d targets_added=%d cidrs_enqueued=%d"
                % (
                    seed_type,
                    seed_value,
                    outcome,
                    counts["ips_added"],
                    counts["rdns_found"],
                    counts["targets_added"],
                    counts["cidrs_enqueued"],
                ),
            )

    log("DONE", "ip_discovery batch complete")


if __name__ == "__main__":
    main()
