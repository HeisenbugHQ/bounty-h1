#!/usr/bin/env python3
"""
workers/dns/subdomains_bruteforce.py

Bruteforce subdomains ONLY for wildcard assets:
- input: assets where asset_type='wildcard' and status='active'
- for each *.example.com:
  - generate candidates: <word>.<root>
  - resolve with puredns (gate)
  - upsert into targets
  - optional: audit in subdomain_discoveries

Toggle:
  RUN_BRUTE=true/false

Env:
  DB_DSN=...
  RUN_BRUTE=true
  BRUTE_PROGRAM_HANDLE=adobe            # optional limit to one program handle
  BRUTE_WORDLIST=wordlists/subdomains_small.txt
  BRUTE_MAX_PER_ROOT=50000
  BRUTE_BATCH_ROOTS=20
  PUREDNS_BIN=puredns
  RESOLVERS_FILE=resolvers.txt
  PUREDNS_TIMEOUT=600
  BRUTE_RATE=0
  SAVE_DISCOVERIES=true
"""

import os
import re
import tempfile
import subprocess
from datetime import datetime

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

RUN_BRUTE = os.getenv("RUN_BRUTE", "false").strip().lower() == "true"
PROGRAM_HANDLE = os.getenv("BRUTE_PROGRAM_HANDLE", "").strip()
WORDLIST = os.getenv("BRUTE_WORDLIST", "wordlists/subdomains_small.txt").strip()
MAX_PER_ROOT = int(os.getenv("BRUTE_MAX_PER_ROOT", "50000"))
BATCH_ROOTS = int(os.getenv("BRUTE_BATCH_ROOTS", "20"))
PUREDNS_BIN = os.getenv("PUREDNS_BIN", "puredns")
RESOLVERS_FILE = os.getenv("RESOLVERS_FILE", "resolvers.txt")
PUREDNS_TIMEOUT = int(os.getenv("PUREDNS_TIMEOUT", "600"))
BRUTE_RATE = os.getenv("BRUTE_RATE", "0").strip()
SAVE_DISCOVERIES = os.getenv("SAVE_DISCOVERIES", "true").strip().lower() == "true"

HOST_RE = re.compile(r"^[a-z0-9][a-z0-9\.\-]{1,251}[a-z0-9]$")


def ts():
    return datetime.now().strftime("%H:%M:%S")


def norm(s: str) -> str:
    return (s or "").strip().lower().rstrip(".")


def plausible_domain(d: str) -> bool:
    d = norm(d)
    if not d or "." not in d:
        return False
    if len(d) > 253:
        return False
    return bool(HOST_RE.match(d))


def wildcard_to_root(v: str) -> str:
    v = norm(v)
    v = v.replace("http://", "").replace("https://", "")
    v = v.split("/")[0]
    if v.startswith("*."):
        v = v[2:]
    v = v.replace("*.", "")
    v = v.replace("*", "")
    return norm(v)


def load_words(path: str) -> list[str]:
    if not os.path.exists(path):
        raise RuntimeError(f"Missing wordlist: {path}")
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().lower()
            if not w or w.startswith("#"):
                continue
            # safe sub label
            if all(c.isalnum() or c in ("-", "_") for c in w):
                out.append(w.replace("_", "-"))
    # dedupe preserve order
    seen = set()
    uniq = []
    for w in out:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq


def ensure_non_empty_file(path: str, label: str) -> None:
    if not os.path.exists(path):
        raise RuntimeError(f"Missing {label}: {path}")
    if os.path.getsize(path) <= 0:
        raise RuntimeError(f"Empty {label}: {path} (run bootstrap)")


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


def fetch_wildcard_assets(conn):
    """
    Returns list of (program_external_id, wildcard_value)
    """
    program_external_id = resolve_program_external_id(conn, PROGRAM_HANDLE)
    with conn.cursor() as cur:
        if program_external_id:
            cur.execute(
                """
                SELECT program_external_id, value
                FROM assets
                WHERE status='active' AND asset_type='wildcard'
                  AND program_external_id=%s
                ORDER BY last_seen_at DESC
                LIMIT %s
                """,
                (program_external_id, BATCH_ROOTS),
            )
        else:
            cur.execute(
                """
                SELECT program_external_id, value
                FROM assets
                WHERE status='active' AND asset_type='wildcard'
                ORDER BY last_seen_at DESC
                LIMIT %s
                """,
                (BATCH_ROOTS,),
            )
        return [(str(a), str(v)) for a, v in cur.fetchall()]


def run_puredns_resolve(domains: list[str]) -> set[str]:
    if not domains:
        return set()

    with tempfile.NamedTemporaryFile("w+", delete=False) as fin:
        for d in domains:
            fin.write(d + "\n")
        fin.flush()
        in_path = fin.name

    with tempfile.NamedTemporaryFile("w+", delete=False) as fout:
        out_path = fout.name

    cmd = [
        PUREDNS_BIN, "resolve", in_path,
        "-r", RESOLVERS_FILE,
        "--write", out_path,
        "--rate-limit", BRUTE_RATE,
    ]

    subprocess.run(cmd, capture_output=True, text=True, timeout=PUREDNS_TIMEOUT)

    resolved = set()
    with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            d = norm(line)
            if plausible_domain(d):
                resolved.add(d)
    return resolved


def upsert_targets(conn, program_external_id: str, root: str, hosts: set[str]) -> int:
    added = 0
    with conn.cursor() as cur:
        for h in hosts:
            cur.execute(
                """
                INSERT INTO targets(platform, program_external_id, source_scope_identifier, host, first_seen_at, last_seen_at)
                VALUES ('hackerone', %s, %s, %s, now(), now())
                ON CONFLICT (platform, program_external_id, host)
                DO UPDATE SET last_seen_at=now()
                """,
                (program_external_id, root, h),
            )
            added += 1
    return added


def save_discoveries(conn, program_external_id: str, root: str, subs: set[str]):
    if not SAVE_DISCOVERIES:
        return
    try:
        with conn.cursor() as cur:
            for s in subs:
                cur.execute(
                    """
                    INSERT INTO subdomain_discoveries(platform, program_external_id, root_domain, subdomain, source, first_seen_at, last_seen_at)
                    VALUES ('hackerone', %s, %s, %s, 'bruteforce', now(), now())
                    ON CONFLICT (platform, program_external_id, subdomain)
                    DO UPDATE SET last_seen_at=now()
                    """,
                    (program_external_id, root, s),
                )
    except Exception:
        # table missing or permissions: ignore
        return


def main():
    if not RUN_BRUTE:
        print(f"[{ts()}] [SKIP] RUN_BRUTE=false")
        return

    ensure_non_empty_file(WORDLIST, "wordlist")
    ensure_non_empty_file(RESOLVERS_FILE, "resolvers file")

    words = load_words(WORDLIST)
    print(f"[{ts()}] [INFO] brute wordlist={WORDLIST} words={len(words)} max_per_root={MAX_PER_ROOT}")

    total_roots = 0
    total_candidates = 0
    total_resolved = 0
    total_upserted = 0

    with psycopg.connect(DB_DSN) as conn:
        assets = fetch_wildcard_assets(conn)
        if not assets:
            print(f"[{ts()}] [DONE] no wildcard assets found (assets.asset_type='wildcard')")
            return

        # group by program_external_id
        # for each wildcard, root = *.example.com -> example.com
        for program_external_id, wildcard in assets:
            root = wildcard_to_root(wildcard)
            if not plausible_domain(root):
                print(f"[{ts()}] [WARN] invalid wildcard/root: {wildcard} -> {root}")
                continue

            total_roots += 1
            print(f"[{ts()}] [RUN] root={root} program={program_external_id}")

            # candidates
            cand = [f"{w}.{root}" for w in words]
            if len(cand) > MAX_PER_ROOT:
                cand = cand[:MAX_PER_ROOT]

            total_candidates += len(cand)
            resolved = run_puredns_resolve(cand)
            total_resolved += len(resolved)

            save_discoveries(conn, program_external_id, root, resolved)
            up = upsert_targets(conn, program_external_id, root, resolved)
            conn.commit()

            total_upserted += up
            print(f"[{ts()}] [OK] root={root} candidates={len(cand)} resolved={len(resolved)} targets_upserted={up}")

    print(f"[{ts()}] [DONE] roots={total_roots} candidates={total_candidates} resolved={total_resolved} targets_upserted={total_upserted}")


if __name__ == "__main__":
    main()
