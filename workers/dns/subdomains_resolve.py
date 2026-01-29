#!/usr/bin/env python3
"""
workers/dns/subdomains_resolve.py

Subdomain discovery + resolution (program-scoped):
- Select roots from DNS scopes/assets only (v_scope_domains + v_dns_seeds domain/wildcard/url)
- Filter out non-DNS noise and known public portals
- subfinder (optional recursive)
- amass passive (optional)
- merge/dedupe candidates, resolve with puredns
- upsert targets + subdomain_discoveries

Notes:
- Idempotent by design.
- Root failures do not stop the run (warn and continue).
- Supports controlled recursion on subfinder seeds.

Env:
  DB_DSN (required)

Program filter:
  SUBDOMAINS_PROGRAM_HANDLE=bitmex   (required in workflow)
  SUBDOMAINS_BATCH_ROOTS=30

Tools:
  SUBFINDER_BIN=subfinder
  PUREDNS_BIN=puredns
  RESOLVERS_FILE=wordlists/resolvers_valid.txt
  SUBFINDER_TIMEOUT=120
  PUREDNS_TIMEOUT=180
  SUBFINDER_ALL=true
  SUBFINDER_RECURSIVE=false
  SUBFINDER_PROVIDER_CONFIG=~/.config/subfinder/provider-config.yaml
  USE_AMASS_PASSIVE=false
  RUN_AMASS=true/false
  AMASS_BIN=amass
  AMASS_TIMEOUT=240

Recursion controls (subfinder seeds):
  SUBFINDER_RECURSION=true/false (default false)
  SUBFINDER_RECURSION_DEPTH=1 (default 1, max 2)
  SUBFINDER_RECURSION_MAX_SEEDS=200 (default 200)

Behavior:
  SAVE_DISCOVERIES=true/false    (default true)
  ONLY_BOUNTY_PROGRAMS=false/true (default false)

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
SUBFINDER_PROVIDER_CONFIG = os.getenv("SUBFINDER_PROVIDER_CONFIG", "").strip()

RUN_AMASS_RAW = os.getenv("RUN_AMASS")
if RUN_AMASS_RAW is not None:
    USE_AMASS_PASSIVE = RUN_AMASS_RAW.strip().lower() == "true"
else:
    USE_AMASS_PASSIVE = os.getenv("USE_AMASS_PASSIVE", "false").strip().lower() == "true"

AMASS_BIN = os.getenv("AMASS_BIN", "amass").strip()
AMASS_TIMEOUT = int(os.getenv("AMASS_TIMEOUT", "240"))

SUBFINDER_RECURSION = os.getenv("SUBFINDER_RECURSION", "false").strip().lower() == "true"
SUBFINDER_RECURSION_DEPTH = int(os.getenv("SUBFINDER_RECURSION_DEPTH", "1"))
SUBFINDER_RECURSION_DEPTH = max(0, min(2, SUBFINDER_RECURSION_DEPTH))
SUBFINDER_RECURSION_MAX_SEEDS = int(os.getenv("SUBFINDER_RECURSION_MAX_SEEDS", "200"))

SAVE_DISCOVERIES = os.getenv("SAVE_DISCOVERIES", "true").strip().lower() == "true"

HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")

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


# --- helpers ---

def ts() -> str:
    return time.strftime("%H:%M:%S")


def norm(s: str) -> str:
    return (s or "").strip().lower().rstrip(".")


def which(binname: str) -> str | None:
    import shutil
    return shutil.which(binname)


def plausible_host(h: str) -> bool:
    h = norm(h)
    if not h or "." not in h or len(h) > 253:
        return False
    return HOST_RE.match(h) is not None


def split_labels(h: str) -> list[str]:
    return [p for p in norm(h).split(".") if p]


def base_domain_guess(host: str) -> str:
    parts = split_labels(host)
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def same_or_subdomain(candidate: str, root: str) -> bool:
    c = norm(candidate)
    r = norm(root)
    return c == r or c.endswith("." + r)


def is_under_allowed_base(candidate: str, allowed_bases: set[str]) -> bool:
    c = norm(candidate)
    if not c:
        return False
    for b in allowed_bases:
        if c == b or c.endswith("." + b):
            return True
    return False


@dataclass(frozen=True)
class Root:
    host: str
    source_scope_identifier: str


# --- DB helpers ---

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


def fetch_root_candidates(conn, program_external_id: str) -> list[tuple[str, str, str]]:
    """
    Returns rows of (source, host, scope_identifier) where:
    - source is "scope" or "asset"
    - scope_identifier is a stable provenance string for targets.source_scope_identifier

    Only include DNS-like scopes/assets (domain/wildcard/url) to avoid app ids & non-DNS data.
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


# --- root filters ---

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
    for d in DENY_HOSTS:
        if h.endswith("." + d):
            return False, "denylist_suffix"
    for suf in DENY_SUFFIXES:
        if h.endswith(suf):
            return False, "denylist_suffix"
    if DOMAIN_RE.match(h) is None:
        return False, "domain_regex"
    if HOST_RE.match(h) is None:
        return False, "host_regex"
    return True, "ok"


def build_roots(candidates: list[tuple[str, str, str]]) -> tuple[list[Root], dict, list[tuple[str, str]]]:
    roots_total_scopes = sum(1 for src, _, _ in candidates if src == "scope")
    roots_total_assets = sum(1 for src, _, _ in candidates if src == "asset")

    filtered: list[tuple[str, str, str]] = []
    rejected: list[tuple[str, str]] = []
    reject_counts: dict[str, int] = {}

    for src, raw_host, scope_ident in candidates:
        host = normalize_root_host(raw_host)
        ok, reason = is_quality_root(host)
        if not ok:
            reject_counts[reason] = reject_counts.get(reason, 0) + 1
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
        "roots_rejected": len(rejected),
        "reject_counts": reject_counts,
    }
    return final, stats, rejected


# --- discovery tools ---

def resolve_subfinder_config(repo_subfinder: str, user_subfinder: str) -> str | None:
    if SUBFINDER_PROVIDER_CONFIG and os.path.isfile(SUBFINDER_PROVIDER_CONFIG):
        return SUBFINDER_PROVIDER_CONFIG
    if os.path.isfile(repo_subfinder):
        return repo_subfinder
    if os.path.isfile(user_subfinder):
        return user_subfinder
    return None


def log_tool_config_status():
    repo_subfinder = os.path.join("config", "tools", "subfinder-provider-config.yaml")
    repo_amass = os.path.join("config", "tools", "amass-config.ini")
    user_subfinder = os.path.join(os.path.expanduser("~"), ".config", "subfinder", "provider-config.yaml")
    user_amass = os.path.join(os.path.expanduser("~"), ".config", "amass", "config.ini")

    subfinder_cfg = resolve_subfinder_config(repo_subfinder, user_subfinder)
    if subfinder_cfg:
        print(f"[{ts()}] [INFO] subfinder providers: present", flush=True)
    else:
        print(f"[{ts()}] [INFO] subfinder providers: absent (running limited)", flush=True)

    if os.path.isfile(repo_amass) or os.path.isfile(user_amass):
        print(f"[{ts()}] [OK] amass config found", flush=True)
    else:
        print(f"[{ts()}] [WARN] amass config missing; running without API sources", flush=True)


def run_subfinder(root_domain: str) -> tuple[list[str], str]:
    cmd = [SUBFINDER_BIN, "-silent", "-d", root_domain]
    if SUBFINDER_ALL:
        cmd.append("-all")
    if SUBFINDER_RECURSIVE:
        cmd.append("-recursive")
    subfinder_cfg = resolve_subfinder_config(
        os.path.join("config", "tools", "subfinder-provider-config.yaml"),
        os.path.join(os.path.expanduser("~"), ".config", "subfinder", "provider-config.yaml"),
    )
    if subfinder_cfg:
        cmd += ["-pc", subfinder_cfg]

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
    source = "subfinder_recursive" if SUBFINDER_RECURSIVE else "subfinder"
    return uniq, source


def run_amass_passive(root_domain: str) -> list[str]:
    if not USE_AMASS_PASSIVE:
        return []
    if not which(AMASS_BIN):
        print(f"[{ts()}] [WARN] amass not found; skipping passive enumeration", flush=True)
        return []

    cmd = [AMASS_BIN, "enum", "-passive", "-d", root_domain]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=AMASS_TIMEOUT)
    out = []
    for line in (p.stdout or "").splitlines():
        d = norm(line)
        if plausible_host(d) and (d == root_domain or d.endswith("." + root_domain) or d.endswith(root_domain)):
            out.append(d)
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


def run_subfinder_with_controlled_recursion(root_domain: str, allowed_bases: set[str]):
    """
    Controlled recursion on subfinder seeds:
    - depth is capped (max 2)
    - max total seeds per root
    - seeds must remain under allowed base domains
    - dedup and avoid re-processing
    """
    seed_total = 0
    seed_recursive = 0
    processed = set()
    all_candidates: list[str] = []

    # initial seed = root domain
    current_seeds = [root_domain]
    seed_total += len(current_seeds)

    max_depth = SUBFINDER_RECURSION_DEPTH if SUBFINDER_RECURSION else 0

    for depth in range(0, max_depth + 1):
        next_seeds = []
        print(f"[{ts()}] [INFO] recursion depth={depth} seeds={len(current_seeds)}", flush=True)

        for seed in current_seeds:
            seed_n = norm(seed)
            if seed_n in processed:
                continue
            processed.add(seed_n)

            # Safety: keep seeds under allowed bases
            if not is_under_allowed_base(seed_n, allowed_bases):
                continue

            try:
                candidates, _ = run_subfinder(seed_n)
            except Exception as e:
                print(f"[{ts()}] [WARN] subfinder seed={seed_n} error={type(e).__name__}: {e}", flush=True)
                continue

            for c in candidates:
                c = norm(c)
                if not c:
                    continue
                if not is_under_allowed_base(c, allowed_bases):
                    continue
                if c not in processed and c not in next_seeds:
                    next_seeds.append(c)
                if c not in all_candidates:
                    all_candidates.append(c)

            if len(all_candidates) >= SUBFINDER_RECURSION_MAX_SEEDS:
                break

        # prepare next depth seeds
        if depth < max_depth:
            # cap next_seeds
            if len(next_seeds) > SUBFINDER_RECURSION_MAX_SEEDS:
                next_seeds = next_seeds[:SUBFINDER_RECURSION_MAX_SEEDS]
            seed_recursive += len(next_seeds)
            current_seeds = next_seeds
        else:
            break

    return all_candidates, seed_total, seed_recursive


# --- persistence ---

def upsert_targets_and_discoveries(
    program_external_id: str,
    root: Root,
    resolved: list[str],
    subfinder_candidates: list[str],
    subfinder_source: str,
    amass_candidates: list[str],
) -> int:
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
                # candidates source=subfinder/subfinder_recursive, amass source=amass_passive
                for h in subfinder_candidates:
                    cur.execute(
                        """
                        INSERT INTO subdomain_discoveries(platform, program_external_id, root_domain, subdomain, source, first_seen_at, last_seen_at)
                        VALUES ('hackerone', %s, %s, %s, %s, now(), now())
                        ON CONFLICT (platform, program_external_id, subdomain)
                        DO UPDATE SET last_seen_at=now(), source=EXCLUDED.source
                        """,
                        (program_external_id, root.host, h, subfinder_source),
                    )
                for h in amass_candidates:
                    cur.execute(
                        """
                        INSERT INTO subdomain_discoveries(platform, program_external_id, root_domain, subdomain, source, first_seen_at, last_seen_at)
                        VALUES ('hackerone', %s, %s, %s, 'amass_passive', now(), now())
                        ON CONFLICT (platform, program_external_id, subdomain)
                        DO UPDATE SET last_seen_at=now(), source=EXCLUDED.source
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


# --- main ---

def main():
    if not PROGRAM_HANDLE:
        print(f"[{ts()}] [FATAL] SUBDOMAINS_PROGRAM_HANDLE is required (set by workflow).", flush=True)
        sys.exit(2)

    print(f"[{ts()}] [INFO] program={PROGRAM_HANDLE} eligible_only={ONLY_BOUNTY} batch_roots={BATCH_ROOTS}", flush=True)
    print(f"[{ts()}] [INFO] resolvers_file={RESOLVERS_FILE}", flush=True)
    print(f"[{ts()}] [INFO] subfinder_recursive={SUBFINDER_RECURSIVE} use_amass_passive={USE_AMASS_PASSIVE}", flush=True)
    print(
        f"[{ts()}] [INFO] subfinder_recursion={SUBFINDER_RECURSION} depth={SUBFINDER_RECURSION_DEPTH} max_seeds={SUBFINDER_RECURSION_MAX_SEEDS}",
        flush=True,
    )
    log_tool_config_status()

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
        f"roots_after_filter={stats['roots_after_filter']} "
        f"roots_rejected={stats['roots_rejected']}",
        flush=True,
    )
    if stats["reject_counts"]:
        parts = [f"{k}={v}" for k, v in sorted(stats["reject_counts"].items(), key=lambda kv: (-kv[1], kv[0]))]
        print(f"[{ts()}] [INFO] root_reject_reasons " + " ".join(parts), flush=True)
    if rejected:
        sample = rejected[:10]
        for host, reason in sample:
            print(f"[{ts()}] [INFO] root_rejected host={host} reason={reason}", flush=True)
    print(f"[{ts()}] [INFO] roots={len(roots)} program_external_id={prog_ext}", flush=True)
    if not roots:
        print(f"[{ts()}] [DONE] No roots after filtering (all filtered by domain regex/denylist).", flush=True)
        sys.exit(0)

    allowed_bases = {base_domain_guess(r.host) for r in roots}

    total_added = 0
    for root in roots:
        try:
            # subfinder candidates (with controlled recursion if enabled)
            if SUBFINDER_RECURSION and SUBFINDER_RECURSION_DEPTH > 0:
                subfinder_candidates, seed_total, seed_recursive = run_subfinder_with_controlled_recursion(
                    root.host, allowed_bases
                )
                subfinder_source = "subfinder_recursive" if SUBFINDER_RECURSIVE else "subfinder"
                print(
                    f"[{ts()}] [INFO] root={root.host} subfinder_seeds={seed_total} recursive_added={seed_recursive}",
                    flush=True,
                )
            else:
                subfinder_candidates, subfinder_source = run_subfinder(root.host)
                seed_total = 1
                seed_recursive = 0

            amass_candidates = run_amass_passive(root.host)

            combined = []
            seen = set()
            for h in subfinder_candidates + amass_candidates:
                h = norm(h)
                if h and h not in seen:
                    seen.add(h)
                    combined.append(h)

            resolved = run_puredns_resolve(combined)
            added = upsert_targets_and_discoveries(
                prog_ext,
                root,
                resolved,
                subfinder_candidates,
                subfinder_source,
                amass_candidates,
            )
            total_added += added
            print(
                f"[{ts()}] [OK] root={root.host} "
                f"subfinder={len(subfinder_candidates)} amass={len(amass_candidates)} "
                f"candidates={len(combined)} resolved={len(resolved)} targets_upserted={added}",
                flush=True,
            )
        except SystemExit:
            raise
        except Exception as e:
            print(f"[{ts()}] [WARN] root={root.host} error={type(e).__name__}: {e}", flush=True)

    print(f"[{ts()}] [DONE] targets_upserted={total_added}", flush=True)


if __name__ == "__main__":
    main()
