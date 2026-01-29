#!/usr/bin/env python3
"""
workers/infra/enrich_dns_asn.py

DNS + ASN enrichment:
- resolve A/AAAA/CNAME for targets.host
- ASN lookup via Team Cymru DNS (TXT query) using first IPv4 if available
- upsert into dns_asn_latest
- mark targets.enriched_at

Env (.env):
  DB_DSN=...
Optional:
  ENRICH_DNS_BATCH=200
  DNS_TIMEOUT=3
  DNS_LIFETIME=5
  ENRICH_ONLY_HTTP_DONE=true   # if true, enrich only http_scanned targets
"""

import os
import ipaddress
from datetime import datetime

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

BATCH = int(os.getenv("ENRICH_DNS_BATCH", "200"))
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "3"))
DNS_LIFETIME = float(os.getenv("DNS_LIFETIME", "5"))
ONLY_HTTP_DONE = os.getenv("ENRICH_ONLY_HTTP_DONE", "true").strip().lower() == "true"


def ts():
    return datetime.now().strftime("%H:%M:%S")


def norm_host(h: str) -> str:
    return (h or "").strip().lower().rstrip(".")


def get_resolver():
    import dns.resolver
    r = dns.resolver.Resolver(configure=True)
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_LIFETIME
    return r


def resolve_records(resolver, host: str):
    import dns.resolver
    import dns.exception

    a = []
    aaaa = []
    cname = None

    try:
        ans = resolver.resolve(host, "A")
        for rr in ans:
            a.append(str(rr))
    except Exception:
        pass

    try:
        ans = resolver.resolve(host, "AAAA")
        for rr in ans:
            aaaa.append(str(rr))
    except Exception:
        pass

    try:
        ans = resolver.resolve(host, "CNAME")
        for rr in ans:
            cname = str(rr.target).rstrip(".")
            break
    except Exception:
        pass

    return a, aaaa, cname


def asn_lookup_cymru(resolver, ipv4: str):
    """
    Team Cymru DNS:
      <reversed-ip>.origin.asn.cymru.com TXT
    Returns (asn:int|None, org:str|None)
    """
    import dns.resolver

    try:
        ip = ipaddress.ip_address(ipv4)
        if ip.version != 4:
            return None, None
        rev = ".".join(reversed(ipv4.split(".")))
        q = f"{rev}.origin.asn.cymru.com"
        ans = resolver.resolve(q, "TXT")
        txt = None
        for rr in ans:
            # rr.strings for older versions, rr.to_text for newer
            txt = rr.to_text().strip('"')
            break
        if not txt:
            return None, None

        # format: "ASN | PREFIX | CC | REGISTRY | ALLOCATED | AS Name"
        parts = [p.strip() for p in txt.split("|")]
        if not parts or not parts[0].isdigit():
            return None, None
        asn = int(parts[0])
        org = parts[-1] if len(parts) >= 1 else None
        return asn, org
    except Exception:
        return None, None


def fetch_batch(conn):
    with conn.cursor() as cur:
        if ONLY_HTTP_DONE:
            cur.execute(
                """
                SELECT id, host
                FROM targets
                WHERE enriched_at IS NULL
                  AND http_scanned_at IS NOT NULL
                ORDER BY id
                LIMIT %s
                """,
                (BATCH,),
            )
        else:
            cur.execute(
                """
                SELECT id, host
                FROM targets
                WHERE enriched_at IS NULL
                ORDER BY id
                LIMIT %s
                """,
                (BATCH,),
            )
        return [(int(r[0]), norm_host(r[1])) for r in cur.fetchall()]


def upsert_dns_asn(conn, target_id: int, a_list, aaaa_list, cname, asn, org):
    a_inet = []
    aaaa_inet = []

    for x in a_list:
        try:
            a_inet.append(ipaddress.ip_address(x))
        except Exception:
            pass
    for x in aaaa_list:
        try:
            aaaa_inet.append(ipaddress.ip_address(x))
        except Exception:
            pass

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO dns_asn_latest(target_id, a_records, aaaa_records, cname, asn, asn_org, first_seen_at, last_seen_at)
            VALUES (%s,%s,%s,%s,%s,%s,now(),now())
            ON CONFLICT (target_id)
            DO UPDATE SET
              last_seen_at=now(),
              a_records=EXCLUDED.a_records,
              aaaa_records=EXCLUDED.aaaa_records,
              cname=EXCLUDED.cname,
              asn=EXCLUDED.asn,
              asn_org=EXCLUDED.asn_org
            """,
            (
                target_id,
                a_inet if a_inet else None,
                aaaa_inet if aaaa_inet else None,
                cname,
                asn,
                org,
            ),
        )


def mark_enriched(conn, target_ids):
    if not target_ids:
        return 0
    with conn.cursor() as cur:
        cur.execute("UPDATE targets SET enriched_at=now() WHERE id = ANY(%s)", (target_ids,))
        return cur.rowcount


def main():
    resolver = get_resolver()

    with psycopg.connect(DB_DSN) as conn:
        batch = fetch_batch(conn)
        if not batch:
            print(f"[{ts()}] [DONE] enrich_dns_asn: nothing pending")
            return

        enriched = 0
        for tid, host in batch:
            a_list, aaaa_list, cname = resolve_records(resolver, host)

            asn = None
            org = None
            if a_list:
                asn, org = asn_lookup_cymru(resolver, a_list[0])

            try:
                upsert_dns_asn(conn, tid, a_list, aaaa_list, cname, asn, org)
                conn.commit()
                enriched += 1
                print(f"[{ts()}] [OK] {host} A={len(a_list)} AAAA={len(aaaa_list)} CNAME={'yes' if cname else 'no'} ASN={asn or ''}")
            except Exception as e:
                conn.rollback()
                print(f"[{ts()}] [WARN] {host} error={type(e).__name__}: {e}")

        marked = mark_enriched(conn, [tid for tid, _ in batch])
        conn.commit()

    print(f"[{ts()}] [DONE] enrich_dns_asn processed={len(batch)} enriched_rows={enriched} marked_enriched={marked}")


if __name__ == "__main__":
    main()
