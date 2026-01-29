#!/usr/bin/env python3
"""
workers/worker_subdomains_resolve.py

Simple + robust root selection and subdomain resolution:
- Read scopes (and optionally assets) for ONE program handle (SUBDOMAINS_PROGRAM_HANDLE)
- Keep only DNS-like roots (domain/wildcard/url) and drop app/store IDs, third-party noise
- subfinder -> candidates
- puredns resolve -> resolved
- ALWAYS seed at least the root itself into targets (so downstream can run)
- Upsert targets + (optional) subdomain_discoveries

Why this exists:
- If resolvers file is missing, puredns resolves nothing -> pipeline stalls at 0 targets.
- HackerOne scopes include non-DNS identifiers (app ids, store URLs, etc.) -> must be filtered.

Env:
  DB_DSN (required)

Program filter:
  SUBDOMAINS_PROGRAM_HANDLE=bitmex   (required in our workflow)
  SUBDOMAINS_BATCH_ROOTS=30

Tools:
  SUBFINDER_BIN=subfinder
  PUREDNS_BIN=puredns
  RESOLVERS_FILE=wordlists/resolvers_valid.txt
  SUBFINDER_TIMEOUT=120
  PUREDNS_TIMEOUT=180
  SUBFINDER_ALL=true
  SUBFINDER_RECURSIVE=false

Behavior:
  SAVE_DISCOVERIES=true/false    (default true)
  ONLY_BOUNTY_PROGRAMS=false/true (default false)  # optional filter at program level

Exit codes:
  2 missing program handle
  3 handle not found in DB
  4 missing resolvers file
"""

import os
import re
import sys
import time
import tempfile
import subprocess
from dataclasses import dataclass

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PROGRAM_HANDLE = os.getenv("SUBDOMAINS_PROGRAM_HANDLE", "").strip()
BATCH_ROOTS = int(os.getenv("SUBDOMAINS_BATCH_ROOTS", "30"))

ONLY_BOUNTY = os.getenv("ONLY_BOUNTY_PROGRAMS", "false").strip().lower() == "true"

SUBFINDER_BIN = os.getenv("SUBFINDER_BIN", "subfinder").strip()
PUREDNS_BIN = os.getenv("PUREDNS_BIN", "puredns").strip()
RESOLVERS_FILE = os.getenv("RESOLVERS_FILE", "wordlists/resolvers_valid.txt").strip()

SUBFINDER_TIMEOUT = int(os.getenv("SUBFINDER_TIMEOUT", "120"))
PUREDNS_TIMEOUT = int(os.getenv("PUREDNS_TIMEOUT", "180"))
SUBFINDER_ALL = os.getenv("SUBFINDER_ALL", "true").strip().lower() == "true"
SUBFINDER_RECURSIVE = os.getenv("SUBFINDER_RECURSIVE", "false").strip().lower() == "true"

SAVE_DISCOVERIES = os.getenv("SAVE_DISCOVERIES", "true").strip().lower() == "true"

HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?)+$", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\\.[a-z]{2,}$")

DEFAULT_DENY_HOSTS = {
    "play.google.com",
    "testflight.apple.com",
    "apps.apple.com",
    "apple.com",
    "google.com",
    "github.com",
    "raw.githubusercontent.com",
    "freshdesk.com",
    "freshworks.com",
}
DENY_SUFFIXES = {".app.android", ".android", ".ios"}

ROOT_DENYLIST_ENV = os.getenv("ROOT_DENYLIST", "")
DENY_HOSTS = set(DEFAULT_DENY_HOSTS)
if ROOT_DENYLIST_ENV.strip():
    for item in ROOT_DENYLIST_ENV.split(","):
        h = (item or "").strip().lower().rstrip(".")
        if h:
            DENY_HOSTS.add(h)

def ts() -> str:
    return time.strftime("%H:%M:%S")

def norm(s: str) -> str:
    return (s or "").strip().lower().rstrip(".")

def plausible_host(h: str) -> bool:
    h = norm(h)
    if not h or "." not in h or len(h) > 253:
        return False
    return HOST_RE.match(h) is not None

@dataclass(frozen=True)
class Root:
    host: str
    source_scope_identifier: str

def resolve_program_external_id(conn, handle: str) -> str | None:
    with conn.cursor() as cur:
        if ONLY_BOUNTY:
            cur.execute(
                """
                SELECT external_id
                FROM programs
                WHERE platform='hackerone' AND handle=%s AND offers_bounties=true
                LIMIT 1
                """,
                (handle,),
            )
        else:
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

def normalize_root_host(raw_host: str) -> str:
    h = norm(raw_host)
    if not h:
        return ""
    # remove scheme defensively
    h = re.sub(r"^https?://", "", h)
    # strip path/query/fragment
    h = re.sub(r"[/?#].*$", "", h)
    # strip port
    h = re.sub(r":[0-9]+$", "", h)
    # strip wildcard prefix
    h = re.sub(r"^\*\.", "", h)
    return norm(h)


def is_quality_root(host: str) -> tuple[bool, str]:
    h = normalize_root_host(host)
    if not h:
        return False, "empty"
    if " " in h:
        return False, "space"
    if "_" in h:
        return False, "underscore"
    if "." not in h:
        return False, "no_dot"
    if h in DENY_HOSTS:
        return False, "denylist_exact"
    for suf in DENY_SUFFIXES:
        if h.endswith(suf):
            return False, "denylist_suffix"
    if DOMAIN_RE.match(h) is None:
        return False, "domain_regex"
    if HOST_RE.match(h) is None:
        return False, "host_regex"
    return True, "ok"


def fetch_root_candidates(conn, program_external_id: str) -> list[tuple[str, str, str]]:
    """
    Returns rows of (source, host, scope_identifier) where:
    - source is "scope" or "asset"
    - scope_identifier is a stable provenance string for targets.source_scope_identifier
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH scope_hosts AS (
              SELECT
                'scope'::TEXT AS src,
                host_base AS host,
                scope_identifier AS scope_identifier
              FROM v_scope_domains
              WHERE platform='hackerone' AND program_external_id=%s
            ),
            asset_hosts AS (
              SELECT
                'asset'::TEXT AS src,
                host AS host,
                ('asset:' || asset_id::TEXT) AS scope_identifier
              FROM v_dns_seeds
              WHERE platform='hackerone'
                AND program_external_id=%s
                AND seed_source IN ('domain','wildcard','url')
            )
            SELECT src, host, scope_identifier
            FROM scope_hosts
            UNION
            SELECT src, host, scope_identifier
            FROM asset_hosts;
            """,
            (program_external_id, program_external_id),
        )
        rows = cur.fetchall()
    return [(str(r[0]), str(r[1] or ""), str(r[2] or "")) for r in rows]


def build_roots(candidates: list[tuple[str, str, str]]) -> tuple[list[Root], dict, list[tuple[str, str]]]:
    roots_total_scopes = sum(1 for src, _, _ in candidates if src == "scope")
    roots_total_assets = sum(1 for src, _, _ in candidates if src == "asset")

    # normalize + filter quality
    filtered: list[tuple[str, str, str]] = []
    rejected: list[tuple[str, str]] = []
    for src, raw_host, scope_ident in candidates:
        host = normalize_root_host(raw_host)
        ok, reason = is_quality_root(host)
        if not ok:
            if host:
                rejected.append((host, reason))
            continue
        filtered.append((src, host, scope_ident))

    # dedupe by host, prefer scope provenance when available
    roots_by_host: dict[str, Root] = {}
    for src, host, scope_ident in filtered:
        root = Root(host=host, source_scope_identifier=scope_ident)
        if host not in roots_by_host:
            roots_by_host[host] = root
            continue
        existing = roots_by_host[host]
        if existing.source_scope_identifier.startswith("asset:") and not scope_ident.startswith("asset:"):
            roots_by_host[host] = root

    # root dedupe: if parent domain exists, drop deeper subdomains as enumeration roots
    hosts = sorted(roots_by_host.keys(), key=lambda x: (x.count("."), x))
    keep = set(hosts)
    hostset = set(hosts)
    for h in hosts:
        parts = h.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in hostset:
                if h in keep and h != parent:
                    keep.discard(h)
                break

    final = [roots_by_host[h] for h in hosts if h in keep][:BATCH_ROOTS]

    stats = {
        "roots_total_scopes": roots_total_scopes,
        "roots_total_assets": roots_total_assets,
        "roots_after_filter": len(final),
    }
    return final, stats, rejected

def run_subfinder(root_domain: str) -> list[str]:
    cmd = [SUBFINDER_BIN, "-silent", "-d", root_domain]
    if SUBFINDER_ALL:
        cmd.append("-all")
    if SUBFINDER_RECURSIVE:
        cmd.append("-recursive")

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBFINDER_TIMEOUT)
    out = []
    for line in (p.stdout or "").splitlines():
        d = norm(line)
        if plausible_host(d) and (d == root_domain or d.endswith("." + root_domain) or d.endswith(root_domain)):
            out.append(d)
    # always include root itself
    out.append(norm(root_domain))
    # unique preserve order
    seen = set()
    uniq = []
    for x in out:
        if x and x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq

def run_puredns_resolve(domains: list[str]) -> list[str]:
    if not domains:
        return []

    if not os.path.exists(RESOLVERS_FILE):
        print(f"[{ts()}] [FATAL] RESOLVERS_FILE missing: {RESOLVERS_FILE}", flush=True)
        print(f"[{ts()}] Fix (example): mkdir -p wordlists && curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o {RESOLVERS_FILE}", flush=True)
        sys.exit(4)

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
        "--rate-limit", "0",
        "-q",
    ]

    # NOTE: puredns sometimes returns rc=0 even on internal errors; we must rely on output file.
    _ = subprocess.run(cmd, capture_output=True, text=True, timeout=PUREDNS_TIMEOUT)

    resolved = []
    try:
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                d = norm(line)
                if plausible_host(d):
                    resolved.append(d)
    except Exception:
        resolved = []

    # unique preserve order
    seen = set()
    uniq = []
    for x in resolved:
        if x and x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq

def upsert_targets_and_discoveries(program_external_id: str, root: Root, resolved: list[str], candidates: list[str]) -> int:
    """
    Always seed at least root.host into targets if resolved is empty.
    Commit happens per root for robustness.
    """
    seed = resolved[:] if resolved else [root.host]

    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            added = 0
            for h in seed:
                cur.execute(
                    """
                    INSERT INTO targets(platform, program_external_id, source_scope_identifier, host, first_seen_at, last_seen_at)
                    VALUES ('hackerone', %s, %s, %s, now(), now())
                    ON CONFLICT (platform, program_external_id, host)
                    DO UPDATE SET
                      last_seen_at=now(),
                      source_scope_identifier=EXCLUDED.source_scope_identifier
                    """,
                    (program_external_id, root.source_scope_identifier, h),
                )
                added += 1

            if SAVE_DISCOVERIES:
                # save both candidates and resolved as audit trail
                # candidates source=subfinder, resolved source=puredns, seed source=seed
                for h in candidates:
                    cur.execute(
                        """
                        INSERT INTO subdomain_discoveries(platform, program_external_id, root_domain, subdomain, source, first_seen_at, last_seen_at)
                        VALUES ('hackerone', %s, %s, %s, 'subfinder', now(), now())
                        ON CONFLICT (platform, program_external_id, subdomain)
                        DO UPDATE SET last_seen_at=now()
                        """,
                        (program_external_id, root.host, h),
                    )
                for h in resolved:
                    cur.execute(
                        """
                        INSERT INTO subdomain_discoveries(platform, program_external_id, root_domain, subdomain, source, first_seen_at, last_seen_at)
                        VALUES ('hackerone', %s, %s, %s, 'puredns', now(), now())
                        ON CONFLICT (platform, program_external_id, subdomain)
                        DO UPDATE SET last_seen_at=now()
                        """,
                        (program_external_id, root.host, h),
                    )
                if not resolved:
                    cur.execute(
                        """
                        INSERT INTO subdomain_discoveries(platform, program_external_id, root_domain, subdomain, source, first_seen_at, last_seen_at)
                        VALUES ('hackerone', %s, %s, %s, 'seed', now(), now())
                        ON CONFLICT (platform, program_external_id, subdomain)
                        DO UPDATE SET last_seen_at=now()
                        """,
                        (program_external_id, root.host, root.host),
                    )

        conn.commit()

    return added

def main():
    if not PROGRAM_HANDLE:
        print(f"[{ts()}] [FATAL] SUBDOMAINS_PROGRAM_HANDLE is required (set by workflow).", flush=True)
        sys.exit(2)

    print(f"[{ts()}] [INFO] program={PROGRAM_HANDLE} eligible_only={ONLY_BOUNTY} batch_roots={BATCH_ROOTS}", flush=True)
    print(f"[{ts()}] [INFO] resolvers_file={RESOLVERS_FILE}", flush=True)

    with psycopg.connect(DB_DSN) as conn:
        prog_ext = resolve_program_external_id(conn, PROGRAM_HANDLE)
        if not prog_ext:
            print(f"[{ts()}] [FATAL] program handle not found in DB: {PROGRAM_HANDLE}", flush=True)
            sys.exit(3)

        candidates = fetch_root_candidates(conn, prog_ext)
        roots, stats, rejected = build_roots(candidates)

    print(
        f"[{ts()}] [INFO] roots_total_scopes={stats['roots_total_scopes']} "
        f"roots_total_assets={stats['roots_total_assets']} "
        f"roots_after_filter={stats['roots_after_filter']}",
        flush=True,
    )
    if rejected:
        sample = rejected[:10]
        for host, reason in sample:
            print(f"[{ts()}] [INFO] root_rejected host={host} reason={reason}", flush=True)
    print(f"[{ts()}] [INFO] roots={len(roots)} program_external_id={prog_ext}", flush=True)
    if not roots:
        print(f"[{ts()}] [DONE] No roots after filtering (all filtered by domain regex/denylist).", flush=True)
        sys.exit(0)

    total_added = 0
    for root in roots:
        try:
            candidates = run_subfinder(root.host)
            resolved = run_puredns_resolve(candidates)
            added = upsert_targets_and_discoveries(prog_ext, root, resolved, candidates)
            total_added += added
            print(f"[{ts()}] [OK] root={root.host} candidates={len(candidates)} resolved={len(resolved)} targets_upserted={added}", flush=True)
        except SystemExit:
            raise
        except Exception as e:
            # keep going to next root
            print(f"[{ts()}] [WARN] root={root.host} error={type(e).__name__}: {e}", flush=True)

    print(f"[{ts()}] [DONE] targets_upserted={total_added}", flush=True)

if __name__ == "__main__":
    main()
