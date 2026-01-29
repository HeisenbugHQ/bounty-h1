#!/usr/bin/env python3
"""
workers/dns/ct_crtsh.py

Fetch subdomains from crt.sh for registrable domains derived from v_dns_seeds.

Env:
  DB_DSN=...
  PROGRAM_HANDLE=adobe
  CT_TIMEOUT=20
  CT_RETRY=2
"""

import os
import re
import time
from datetime import datetime

import psycopg
import requests
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PROGRAM_HANDLE = os.getenv("PROGRAM_HANDLE", "").strip()
CT_TIMEOUT = int(os.getenv("CT_TIMEOUT", "20"))
CT_RETRY = int(os.getenv("CT_RETRY", "2"))

HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def norm(s: str) -> str:
    return (s or "").strip().lower().rstrip(".")


def plausible_host(h: str) -> bool:
    h = norm(h)
    if not h or "." not in h or len(h) > 253:
        return False
    return HOST_RE.match(h) is not None


def approx_reg_domain(host: str) -> str:
    host = norm(host)
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def valid_idna(host: str) -> bool:
    try:
        host.encode("ascii").decode("idna")
        return True
    except UnicodeError:
        return False


def resolve_program_external_id(conn, handle: str) -> str | None:
    if not handle:
        return None
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


def fetch_seed_domains(conn, program_external_id: str) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT host_base
            FROM v_dns_seeds
            WHERE platform='hackerone' AND program_external_id=%s
            """,
            (program_external_id,),
        )
        rows = [r[0] for r in cur.fetchall()]

    seeds = set()
    for h in rows:
        host = norm(h)
        if not plausible_host(host):
            continue
        reg = approx_reg_domain(host)
        if plausible_host(reg):
            seeds.add(reg)
    return sorted(seeds)


def fetch_crtsh(domain: str) -> list[dict]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    last_err = None
    for attempt in range(CT_RETRY + 1):
        try:
            r = requests.get(url, timeout=CT_TIMEOUT)
            if r.status_code != 200:
                last_err = RuntimeError(f"HTTP {r.status_code}")
                time.sleep(1)
                continue
            try:
                return r.json() if r.text.strip() else []
            except Exception as e:
                last_err = e
                time.sleep(1)
                continue
        except Exception as e:
            last_err = e
            time.sleep(1)
            continue
    raise RuntimeError(f"crt.sh failed for {domain}: {last_err}")


def normalize_name(n: str) -> str:
    n = norm(n)
    if n.startswith("*."):
        n = n[2:]
    if n.startswith("*"):
        n = n[1:]
    return norm(n)


def extract_subdomains(rows: list[dict]) -> set[str]:
    out = set()
    for row in rows:
        nv = row.get("name_value") if isinstance(row, dict) else None
        if not nv:
            continue
        for raw in str(nv).splitlines():
            host = normalize_name(raw)
            if not host or " " in host or "_" in host:
                continue
            if not plausible_host(host):
                continue
            if not valid_idna(host):
                continue
            out.add(host)
    return out


def upsert_discoveries(conn, program_external_id: str, root: str, subs: set[str]) -> int:
    if not subs:
        return 0
    inserted = 0
    with conn.cursor() as cur:
        for s in subs:
            cur.execute(
                """
                INSERT INTO subdomain_discoveries(
                  platform, program_external_id, root_domain, subdomain, source, first_seen_at, last_seen_at
                )
                VALUES ('hackerone', %s, %s, %s, 'ct_crtsh', now(), now())
                ON CONFLICT (platform, program_external_id, subdomain)
                DO UPDATE SET last_seen_at=now()
                """,
                (program_external_id, root, s),
            )
            inserted += 1
    return inserted


def upsert_targets(conn, program_external_id: str, root: str, subs: set[str]) -> int:
    if not subs:
        return 0
    inserted = 0
    with conn.cursor() as cur:
        for h in subs:
            cur.execute(
                """
                INSERT INTO targets(platform, program_external_id, source_scope_identifier, host, first_seen_at, last_seen_at)
                VALUES ('hackerone', %s, %s, %s, now(), now())
                ON CONFLICT (platform, program_external_id, host)
                DO UPDATE SET last_seen_at=now()
                """,
                (program_external_id, root, h),
            )
            inserted += 1
    return inserted


def main():
    if not PROGRAM_HANDLE:
        raise RuntimeError("Missing PROGRAM_HANDLE")

    domains_scanned = 0
    subdomains_found = 0
    targets_upserted = 0

    with psycopg.connect(DB_DSN) as conn:
        program_external_id = resolve_program_external_id(conn, PROGRAM_HANDLE)
        if not program_external_id:
            raise RuntimeError(f"Program handle not found: {PROGRAM_HANDLE}")

        seeds = fetch_seed_domains(conn, program_external_id)
        if not seeds:
            print(f"[{ts()}] [DONE] no DNS seeds for program={PROGRAM_HANDLE}")
            return

        for domain in seeds:
            domains_scanned += 1
            try:
                rows = fetch_crtsh(domain)
            except Exception as e:
                print(f"[{ts()}] [WARN] crt.sh failed domain={domain}: {e}")
                continue

            subs = extract_subdomains(rows)
            subdomains_found += len(subs)

            upsert_discoveries(conn, program_external_id, domain, subs)
            targets_upserted += upsert_targets(conn, program_external_id, domain, subs)
            conn.commit()

    print(
        f"[{ts()}] [DONE] domains_scanned={domains_scanned} "
        f"subdomains_found={subdomains_found} targets_upserted={targets_upserted}"
    )


if __name__ == "__main__":
    main()
