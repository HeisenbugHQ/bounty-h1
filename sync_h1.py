#!/usr/bin/env python3
"""
HackerOne -> Postgres ingest (programs + structured scopes)

Caratteristiche:
- Output progressivo (pagine, programmi, scopes, rate, commit)
- Robustezza: errori per singolo programma non fermano tutto
- Commit incrementale (non perdi lavoro se crasha a metà)
- "Skip unchanged": usa SHA256 del JSON per non riscrivere dati uguali
  e, se un programma non cambia, può saltare anche la risincronizzazione degli scope
- Gestione 400 su structured_scopes come "fine paginazione" (alcuni endpoint fanno così)
- Gestione 429 con Retry-After
"""

import os
import sys
import time
import json
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests
import psycopg
from psycopg.types.json import Jsonb
from dotenv import load_dotenv

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# -------------------- CONFIG --------------------

load_dotenv(dotenv_path=".env")

DB_DSN = os.getenv("DB_DSN")
H1_USERNAME = os.getenv("H1_USERNAME")
H1_TOKEN = os.getenv("H1_TOKEN")

if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")
if not H1_USERNAME or not H1_TOKEN:
    raise RuntimeError("Missing H1_USERNAME/H1_TOKEN in .env")

H1_BASE = "https://api.hackerone.com/v1"

PAGE_SIZE = 100
COMMIT_EVERY = 25

# Se True: scarica scope solo per programmi con offers_bounties=True (più veloce)
SCOPES_ONLY_BOUNTY = False

# Se True: se un programma non è cambiato, NON riscarica gli scope (molto più veloce in cronjob)
SKIP_SCOPES_IF_PROGRAM_UNCHANGED = True

# Throttle: di default 0 (massima velocità). Se prendi 429, alza (es 0.05)
SLEEP_BETWEEN_PROGRAMS = 0.0
SLEEP_BETWEEN_SCOPE_PAGES = 0.0


# -------------------- UTIL --------------------

def ts() -> str:
    return time.strftime("%H:%M:%S")

def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", flush=True)

def sha256_json(obj: Any) -> str:
    # sort_keys=True rende l'hash stabile
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def human_rate(n: int, seconds: float) -> str:
    if seconds <= 0:
        return "∞/s"
    return f"{n/seconds:.2f}/s"

def make_session() -> requests.Session:
    s = requests.Session()
    s.auth = (H1_USERNAME, H1_TOKEN)
    s.headers.update({"Accept": "application/json"})

    retry = Retry(
        total=5,
        backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

def request_json(session: requests.Session, url: str, params: Dict[str, Any]) -> Tuple[int, Any, requests.Response]:
    """
    GET JSON con gestione 429 Retry-After.
    Ritorna (status_code, parsed_json_or_text, response).
    """
    r = session.get(url, params=params, timeout=30)

    if r.status_code == 429:
        ra = r.headers.get("Retry-After")
        wait = int(ra) if ra and ra.isdigit() else 10
        log(f"[RATE LIMIT] 429 su {url}. Sleep {wait}s")
        time.sleep(wait)
        r = session.get(url, params=params, timeout=30)

    try:
        return r.status_code, r.json(), r
    except Exception:
        return r.status_code, r.text, r


# -------------------- DB: schema bootstrap (non distruttivo) --------------------

def ensure_schema(conn: psycopg.Connection) -> None:
    """
    Non crea le tabelle (le hai già), ma aggiunge colonne utili se mancanti.
    Così lo script è portabile e "self-healing".
    """
    with conn.cursor() as cur:
        cur.execute("ALTER TABLE programs ADD COLUMN IF NOT EXISTS raw_hash TEXT;")
        cur.execute("ALTER TABLE programs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;")
        cur.execute("ALTER TABLE scopes ADD COLUMN IF NOT EXISTS raw_hash TEXT;")
        cur.execute("ALTER TABLE scopes ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_programs_raw_hash ON programs(raw_hash);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scopes_raw_hash ON scopes(raw_hash);")
    conn.commit()


# -------------------- DB: upsert con skip se invariato --------------------

def upsert_program(
    cur,
    external_id: str,
    handle: Optional[str],
    name: Optional[str],
    offers_bounties: Optional[bool],
    raw_obj: Any,
    raw_hash: str,
    updated_at: Optional[str],
) -> bool:
    """
    Ritorna True se il record è stato inserito/aggiornato (cioè era diverso),
    False se era già identico (skip).
    """
    cur.execute(
        """
        INSERT INTO programs(
          platform, external_id, handle, name, offers_bounties,
          raw_json, raw_hash, updated_at, last_seen_at
        )
        VALUES ('hackerone', %s, %s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (platform, external_id) DO UPDATE SET
          handle=EXCLUDED.handle,
          name=EXCLUDED.name,
          offers_bounties=EXCLUDED.offers_bounties,
          raw_json=EXCLUDED.raw_json,
          raw_hash=EXCLUDED.raw_hash,
          updated_at=EXCLUDED.updated_at,
          last_seen_at=now()
        WHERE programs.raw_hash IS DISTINCT FROM EXCLUDED.raw_hash
        RETURNING 1
        """,
        (external_id, handle, name, offers_bounties, Jsonb(raw_obj), raw_hash, updated_at),
    )
    # se non ritorna righe, significa "unchanged"
    return cur.fetchone() is not None

def upsert_scope(
    cur,
    program_external_id: str,
    asset_type: Optional[str],
    identifier: str,
    eligible_for_bounty: Optional[bool],
    eligible_for_submission: Optional[bool],
    instruction: Optional[str],
    raw_obj: Any,
    raw_hash: str,
    updated_at: Optional[str],
) -> bool:
    """
    True se inserito/aggiornato (diverso), False se invariato.
    """
    if not identifier:
        return False

    cur.execute(
        """
        INSERT INTO scopes(
          platform, program_external_id, asset_type, identifier,
          eligible_for_bounty, eligible_for_submission, instruction,
          raw_json, raw_hash, updated_at, last_seen_at
        )
        VALUES ('hackerone', %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (platform, program_external_id, identifier) DO UPDATE SET
          asset_type=EXCLUDED.asset_type,
          eligible_for_bounty=EXCLUDED.eligible_for_bounty,
          eligible_for_submission=EXCLUDED.eligible_for_submission,
          instruction=EXCLUDED.instruction,
          raw_json=EXCLUDED.raw_json,
          raw_hash=EXCLUDED.raw_hash,
          updated_at=EXCLUDED.updated_at,
          last_seen_at=now()
        WHERE scopes.raw_hash IS DISTINCT FROM EXCLUDED.raw_hash
        RETURNING 1
        """,
        (
            program_external_id, asset_type, identifier,
            eligible_for_bounty, eligible_for_submission, instruction,
            Jsonb(raw_obj), raw_hash, updated_at
        ),
    )
    return cur.fetchone() is not None


# -------------------- SYNC: scopes --------------------

def sync_program_scopes(
    cur,
    session: requests.Session,
    handle: str,
    program_external_id: str,
) -> Tuple[int, int]:
    """
    Ritorna (scope_rows_seen, scope_rows_changed).
    """
    seen = 0
    changed = 0
    page = 1

    while True:
        url = f"{H1_BASE}/hackers/programs/{handle}/structured_scopes"
        params = {"page[number]": page, "page[size]": PAGE_SIZE}
        status, js, _ = request_json(session, url, params)

        if status in (401, 403, 404):
            return seen, changed

        # alcuni endpoint: oltre ultima pagina = 400
        if status == 400:
            return seen, changed

        if status >= 400:
            log(f"[WARN] scopes HTTP {status} for {handle} page={page}. Stop scopes for this program.")
            return seen, changed

        items = js.get("data", []) if isinstance(js, dict) else []
        if not items:
            break

        for sc in items:
            seen += 1
            a = sc.get("attributes", {})
            asset_type = a.get("asset_type") or a.get("type") or "unknown"
            identifier = a.get("asset_identifier") or a.get("identifier") or a.get("asset")

            eligible_for_bounty = a.get("eligible_for_bounty")
            if not isinstance(eligible_for_bounty, bool):
                eligible_for_bounty = None

            eligible_for_submission = a.get("eligible_for_submission")
            if not isinstance(eligible_for_submission, bool):
                eligible_for_submission = None

            instruction = a.get("instruction") or a.get("description")
            updated_at = a.get("updated_at")  # se presente

            rh = sha256_json(sc)

            if upsert_scope(
                cur,
                program_external_id=program_external_id,
                asset_type=str(asset_type) if asset_type else None,
                identifier=str(identifier) if identifier else "",
                eligible_for_bounty=eligible_for_bounty,
                eligible_for_submission=eligible_for_submission,
                instruction=instruction,
                raw_obj=sc,
                raw_hash=rh,
                updated_at=updated_at,
            ):
                changed += 1

        page += 1
        if SLEEP_BETWEEN_SCOPE_PAGES:
            time.sleep(SLEEP_BETWEEN_SCOPE_PAGES)

    return seen, changed


# -------------------- SYNC: programs --------------------

@dataclass
class Counters:
    programs_seen: int = 0
    programs_changed: int = 0
    bounty_programs_seen: int = 0
    scopes_seen: int = 0
    scopes_changed: int = 0
    scopes_errors: int = 0


def preload_program_hashes(conn: psycopg.Connection) -> Dict[str, Optional[str]]:
    """
    Precarica (external_id -> raw_hash) per decidere velocemente se un programma è cambiato.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT external_id, raw_hash FROM programs WHERE platform='hackerone';")
        return {row[0]: row[1] for row in cur.fetchall()}


def sync_hackerone() -> Counters:
    session = make_session()
    start = time.time()
    c = Counters()

    log("Starting HackerOne sync")
    log(f"SCOPES_ONLY_BOUNTY={SCOPES_ONLY_BOUNTY}")
    log(f"SKIP_SCOPES_IF_PROGRAM_UNCHANGED={SKIP_SCOPES_IF_PROGRAM_UNCHANGED}")
    log(f"DB_DSN={DB_DSN}")

    with psycopg.connect(DB_DSN) as conn:
        ensure_schema(conn)

        existing_hashes = preload_program_hashes(conn)

        with conn.cursor() as cur:
            page = 1

            while True:
                url = f"{H1_BASE}/hackers/programs"
                params = {"page[number]": page, "page[size]": PAGE_SIZE}
                status, js, _ = request_json(session, url, params)

                if status >= 400:
                    raise RuntimeError(f"Programs fetch failed HTTP {status} page={page}. Body: {str(js)[:200]}")

                items = js.get("data", []) if isinstance(js, dict) else []
                if not items:
                    break

                log(f"Programs page {page}: {len(items)} items")

                for p in items:
                    c.programs_seen += 1

                    attrs = p.get("attributes", {})
                    handle = attrs.get("handle") or p.get("id")
                    name = attrs.get("name")

                    offers_bounties = attrs.get("offers_bounties")
                    if not isinstance(offers_bounties, bool):
                        offers_bounties = None
                    if offers_bounties is True:
                        c.bounty_programs_seen += 1

                    updated_at = attrs.get("updated_at")  # se presente
                    external_id = str(attrs.get("handle") or p.get("id") or handle)

                    rh = sha256_json(p)

                    changed = upsert_program(
                        cur,
                        external_id=external_id,
                        handle=str(handle) if handle else None,
                        name=name,
                        offers_bounties=offers_bounties,
                        raw_obj=p,
                        raw_hash=rh,
                        updated_at=updated_at,
                    )

                    if changed:
                        c.programs_changed += 1
                        existing_hashes[external_id] = rh

                    # Progress leggero ogni 10 programmi
                    if c.programs_seen % 10 == 0:
                        elapsed = time.time() - start
                        log(
                            f"Programs seen={c.programs_seen} changed={c.programs_changed} "
                            f"(bounty={c.bounty_programs_seen}) | "
                            f"Scopes seen={c.scopes_seen} changed={c.scopes_changed} errors={c.scopes_errors} | "
                            f"rate={human_rate(c.programs_seen, elapsed)}"
                        )

                    # Decide se fare scopes
                    do_scopes = bool(handle)
                    if SCOPES_ONLY_BOUNTY and offers_bounties is not True:
                        do_scopes = False

                    # Se il programma non cambia e vuoi ottimizzare cronjob: salta scopes
                    if do_scopes and SKIP_SCOPES_IF_PROGRAM_UNCHANGED:
                        old = existing_hashes.get(external_id)
                        # old è già stato aggiornato sopra se changed=True, quindi qui:
                        # se NON changed, allora old == rh e possiamo saltare
                        if not changed and old == rh:
                            do_scopes = False

                    if do_scopes:
                        try:
                            seen, ch = sync_program_scopes(cur, session, handle=str(handle), program_external_id=external_id)
                            c.scopes_seen += seen
                            c.scopes_changed += ch
                        except Exception as e:
                            c.scopes_errors += 1
                            log(f"[WARN] scopes failed for {handle}: {type(e).__name__}: {str(e)[:120]}")

                    # Commit incrementale
                    if c.programs_seen % COMMIT_EVERY == 0:
                        conn.commit()
                        log(f"Committed (programs_seen={c.programs_seen}, scopes_seen={c.scopes_seen})")

                    if SLEEP_BETWEEN_PROGRAMS:
                        time.sleep(SLEEP_BETWEEN_PROGRAMS)

                page += 1

            conn.commit()

    elapsed = time.time() - start
    log(
        f"Done in {elapsed:.1f}s | programs_seen={c.programs_seen} programs_changed={c.programs_changed} "
        f"bounty_programs_seen={c.bounty_programs_seen} | scopes_seen={c.scopes_seen} scopes_changed={c.scopes_changed} "
        f"scopes_errors={c.scopes_errors}"
    )
    return c


if __name__ == "__main__":
    try:
        sync_hackerone()
    except KeyboardInterrupt:
        log("Interrupted by user.")
        sys.exit(130)
    except Exception as e:
        log(f"[FATAL] {type(e).__name__}: {e}")
        sys.exit(1)
