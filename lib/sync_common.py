#!/usr/bin/env python3
"""
Common sync helpers for multi-platform ingestion and canonicalization.
"""

import json
import re
from urllib.parse import urlparse
from typing import Any, Optional

import psycopg
from psycopg.types.json import Json

EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)


def normalize_asset_type(platform: str, raw_scope_type: Optional[str], identifier: str) -> str:
    at = (raw_scope_type or "").strip().lower()
    ident = (identifier or "").strip()
    if at in {"domain", "wildcard", "url", "ip", "cidr", "asn", "other"}:
        return at
    if at in {"hostname", "fqdn"}:
        return "domain"
    if at in {"wildcard_domain", "wildcardhostname", "wildcard_domain_name"}:
        return "wildcard"
    if at in {"uri", "website", "web", "url"}:
        return "url"
    if at in {"ipv4", "ipv6", "ip_address"}:
        return "ip"
    if at in {"network", "netblock"}:
        return "cidr"
    if at in {"asn", "as"}:
        return "asn"

    low = ident.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return "url"
    if low.startswith("*."):
        return "wildcard"
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$", low):
        return "cidr"
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", low):
        return "ip"
    if re.match(r"^(AS)?\d+$", low, re.IGNORECASE):
        return "asn"
    if "." in low:
        return "domain"
    return "other"


def upsert_program(conn, platform: str, external_id: str, handle: Optional[str], name: Optional[str],
                  offers_bounties: Any, currency: Any, policy: Any, raw_json: dict):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO programs(
              platform, external_id, handle, name,
              offers_bounties, currency, policy, raw_json,
              first_seen_at, last_seen_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, now(), now())
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
            (platform, external_id, handle, name, offers_bounties, currency, policy, json.dumps(raw_json or {})),
        )


def upsert_scope(cur, platform: str, program_external_id: str, asset_type: str, identifier: str,
                eligible_for_bounty: bool, instruction: Optional[str], raw_json: dict):
    cur.execute(
        """
        INSERT INTO scopes(
          platform, program_external_id, asset_type, identifier,
          eligible_for_bounty, instruction, raw_json, first_seen_at, last_seen_at
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,now(),now())
        ON CONFLICT (platform, program_external_id, identifier)
        DO UPDATE SET
          asset_type=EXCLUDED.asset_type,
          eligible_for_bounty=EXCLUDED.eligible_for_bounty,
          instruction=EXCLUDED.instruction,
          raw_json=EXCLUDED.raw_json,
          last_seen_at=now();
        """,
        (platform, program_external_id, asset_type, identifier, bool(eligible_for_bounty), instruction, Json(raw_json or {})),
    )


def registrable_domain_guess(host: str) -> Optional[str]:
    parts = [p for p in (host or "").lower().split(".") if p]
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def extract_email_domains(text: str) -> list[str]:
    if not text:
        return []
    return sorted({m.group(1).lower() for m in EMAIL_RE.finditer(text)})


def website_host(website: str) -> Optional[str]:
    if not website:
        return None
    try:
        p = urlparse(website)
        return (p.netloc or p.path).lower()
    except Exception:
        return None


def upsert_program_identity(conn, canonical_id: int, platform: str, external_id: str,
                            handle: Optional[str], name: Optional[str], website: Optional[str],
                            confidence: int, reasons: dict | None):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO program_identities(
              canonical_id, platform, program_external_id, handle, name, website,
              confidence, reasons, first_seen_at, last_seen_at
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
            ON CONFLICT (platform, program_external_id)
            DO UPDATE SET
              canonical_id=EXCLUDED.canonical_id,
              handle=EXCLUDED.handle,
              name=EXCLUDED.name,
              website=EXCLUDED.website,
              confidence=EXCLUDED.confidence,
              reasons=EXCLUDED.reasons,
              last_seen_at=now();
            """,
            (canonical_id, platform, external_id, handle, name, website, int(confidence), Json(reasons or {})),
        )


def upsert_program_fingerprint(conn, canonical_id: int, kind: str, value: str, weight: int = 10, source: str = "derived"):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO program_fingerprints(
              canonical_id, kind, value, weight, source, first_seen_at, last_seen_at
            )
            VALUES (%s,%s,%s,%s,%s,now(),now())
            ON CONFLICT (canonical_id, kind, value)
            DO UPDATE SET
              weight=GREATEST(program_fingerprints.weight, EXCLUDED.weight),
              source=EXCLUDED.source,
              last_seen_at=now();
            """,
            (canonical_id, kind, value, int(weight), source),
        )


def derive_fingerprints_from_scopes(conn, platform: str, program_external_id: str) -> list[str]:
    domains = set()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT host_base
            FROM v_scope_domains
            WHERE platform=%s AND program_external_id=%s
            """,
            (platform, program_external_id),
        )
        for (host_base,) in cur.fetchall():
            rd = registrable_domain_guess(host_base)
            if rd:
                domains.add(rd)
    return sorted(domains)


def derive_fingerprints_from_program(program: dict) -> dict:
    domains = set()
    website = program.get("website") or program.get("url") or program.get("homepage")
    whost = website_host(website) if website else None
    if whost:
        rd = registrable_domain_guess(whost)
        if rd:
            domains.add(rd)

    emails = []
    policy = program.get("policy") or ""
    emails.extend(extract_email_domains(policy))

    raw_json = program.get("raw_json") or {}
    for k in ("website", "url", "homepage", "security_contact", "security_email", "contact"):
        v = raw_json.get(k)
        if isinstance(v, str):
            emails.extend(extract_email_domains(v))

    brand = (program.get("name") or "").strip().lower()
    return {
        "website_host": whost,
        "domains": sorted(domains),
        "email_domains": sorted(set(emails)),
        "brand": brand,
    }


def match_or_create_canonical(conn, program: dict) -> int:
    platform = program.get("platform")
    external_id = program.get("external_id")
    handle = program.get("handle")
    name = program.get("name") or handle or external_id
    website = program.get("website")

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT canonical_id
            FROM program_identities
            WHERE platform=%s AND program_external_id=%s
            LIMIT 1
            """,
            (platform, external_id),
        )
        r = cur.fetchone()
        if r:
            return int(r[0])

    fp = derive_fingerprints_from_program(program)
    candidate_values = []
    candidate_values.extend([("domain", d) for d in fp.get("domains", [])])
    if fp.get("website_host"):
        candidate_values.append(("website_host", fp["website_host"]))
    if fp.get("brand"):
        candidate_values.append(("brand", fp["brand"]))

    canonical_ids = set()
    reasons = {"matches": []}
    if candidate_values:
        with conn.cursor() as cur:
            for kind, value in candidate_values:
                cur.execute(
                    """
                    SELECT canonical_id
                    FROM program_fingerprints
                    WHERE kind=%s AND value=%s
                    """,
                    (kind, value),
                )
                rows = cur.fetchall()
                if rows:
                    reasons["matches"].append({"kind": kind, "value": value, "canonical_ids": [int(r[0]) for r in rows]})
                for (cid,) in rows:
                    canonical_ids.add(int(cid))

    if len(canonical_ids) == 1:
        canonical_id = list(canonical_ids)[0]
        upsert_program_identity(conn, canonical_id, platform, external_id, handle, name, website, 80, reasons)
        return canonical_id

    # ambiguous or none -> create new canonical
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO canonical_programs(canonical_name, website, first_seen_at, last_seen_at)
            VALUES (%s, %s, now(), now())
            RETURNING id;
            """,
            (name, website),
        )
        canonical_id = int(cur.fetchone()[0])

    conf = 0 if canonical_ids else 40
    if canonical_ids:
        reasons["ambiguous"] = True
        reasons["candidates"] = sorted(canonical_ids)

    upsert_program_identity(conn, canonical_id, platform, external_id, handle, name, website, conf, reasons)

    # seed fingerprints for new canonical
    if fp.get("brand"):
        upsert_program_fingerprint(conn, canonical_id, "brand", fp["brand"], weight=5)
    for d in fp.get("domains", []):
        upsert_program_fingerprint(conn, canonical_id, "domain", d, weight=10)
    for d in fp.get("email_domains", []):
        upsert_program_fingerprint(conn, canonical_id, "email_domain", d, weight=5)
    if fp.get("website_host"):
        upsert_program_fingerprint(conn, canonical_id, "website_host", fp["website_host"], weight=8)

    return canonical_id
