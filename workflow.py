#!/usr/bin/env python3
"""
workflow.py

Program-scoped workflow runner:
- purge derived data per program (clean tests, never touches schema, never touches programs/scopes/assets)
- checkpoint/resume on step failure
- deterministic ordered execution of ALL workers
- safe parallel runs across N programs via flock for learning-file writers

Usage:
  bash scripts/run_logged.sh python workflow.py adobe --purge
  bash scripts/run_logged.sh python workflow.py adobe --purge --resume
  bash scripts/run_logged.sh python workflow.py adobe --purge --resume --force-purge
  bash scripts/run_logged.sh python workflow.py adobe --purge --from-step http_reinject

Notes:
- After a real purge, we ALWAYS start from step 0, unless you explicitly use --from-step.
- If --force-purge is set, checkpoint is ignored even if --resume is also set.

Env:
  DB_DSN required
  MAX_ROUNDS=5
  SLEEP_BETWEEN_ROUNDS=1

Toggles:
  RUN_SUB_BRUTE=true/false        (default true)
  RUN_CRAWL_LIGHT=true/false      (default true)
  RUN_WAYBACK=true/false          (default true)
  RUN_EDGE_FP=true/false          (default true)
  RUN_PARAMS=true/false           (default true)
  RUN_TLS=true/false              (default true)
  RUN_SAN=true/false              (default false)
  RUN_SAN_LEARN=true/false        (default true)
  RUN_DIRFUZZ=true/false          (default false)
  RUN_IP=true/false               (default true)
  RUN_IP_SEEDS=true/false         (default false)

Locking:
  LEARN_LOCK_ENABLED=true/false   (default true)
  LEARN_LOCK_FILE=runtime/workflow_state/learn.lock
"""

import os
import sys
import json
import time
import argparse
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.types.json import Json
import yaml
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

MAX_ROUNDS = int(os.getenv("MAX_ROUNDS", "5"))
SLEEP_BETWEEN_ROUNDS = float(os.getenv("SLEEP_BETWEEN_ROUNDS", "1"))

RUN_SUB_BRUTE = True
RUN_CRAWL_LIGHT = True
RUN_WAYBACK = True
RUN_EDGE_FP = True
RUN_PARAMS = True
RUN_TLS = True
RUN_SAN = False
RUN_SAN_LEARN = True
RUN_DIRFUZZ = False
RUN_IP = True
RUN_IP_SEEDS = False
RUN_SURFACE = True
RUN_ENGINE = False
TASK_MODE = False

JOB_QUEUE_TAKE = int(os.getenv("JOB_QUEUE_TAKE", "10"))
JOB_BUDGET_DEFAULT = int(os.getenv("JOB_BUDGET_DEFAULT", "1"))
SAN_EVENT_LIMIT = int(os.getenv("SAN_EVENT_LIMIT", "200"))
IP_EVENT_LIMIT = int(os.getenv("IP_EVENT_LIMIT", "200"))

BUDGET_PORT_TARGETS_PER_ROUND = int(os.getenv("BUDGET_PORT_TARGETS_PER_ROUND", "50"))
BUDGET_TLS_TARGETS_PER_ROUND = int(os.getenv("BUDGET_TLS_TARGETS_PER_ROUND", "50"))
BUDGET_CRAWL_TARGETS_PER_ROUND = int(os.getenv("BUDGET_CRAWL_TARGETS_PER_ROUND", "20"))
TASK_TAKE = int(os.getenv("TASK_TAKE", "10"))

LEARN_LOCK_ENABLED = os.getenv("LEARN_LOCK_ENABLED", "true").strip().lower() == "true"
LEARN_LOCK_FILE = os.getenv("LEARN_LOCK_FILE", "runtime/workflow_state/learn.lock").strip()

STATE_DIR = Path("runtime/workflow_state")
CONFIG_DIR = Path("config")


def load_yaml_config(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        log(f"[WARN] failed to load config {path}: {exc}")
        return {}


def deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def normalize_env_key(key: str) -> str:
    return key.strip().upper().replace("-", "_").replace(" ", "_")


def coerce_env_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    if value is None:
        return ""
    return str(value)


def config_to_env(config: dict, base_env: dict) -> dict:
    env_out: dict[str, str] = {}
    if not isinstance(config, dict):
        return env_out

    merged_env: dict = {}
    env_block = config.get("env")
    if isinstance(env_block, dict):
        merged_env.update(env_block)

    for key, value in config.items():
        if str(key).lower() in ("env", "job_budget", "job_budgets"):
            continue
        merged_env[key] = value

    job_budget = config.get("job_budget") or config.get("job_budgets")
    if isinstance(job_budget, dict):
        for key, value in job_budget.items():
            merged_env[f"JOB_BUDGET_{key}"] = value

    for key, value in merged_env.items():
        env_key = normalize_env_key(str(key))
        if env_key in base_env:
            continue  # respect explicit environment overrides
        env_out[env_key] = coerce_env_value(value)

    return env_out


JOB_BUDGET_ALIASES = {
    "dns": ["JOB_BUDGET_DNS", "JOB_BUDGET_SUBDOMAINS_RESOLVE"],
    "http": ["JOB_BUDGET_HTTP", "JOB_BUDGET_HTTP_REINJECT"],
    "tls": ["JOB_BUDGET_TLS", "JOB_BUDGET_TLS_MINER"],
    "ip": ["JOB_BUDGET_IP", "JOB_BUDGET_IP_DISCOVERY"],
}


def get_job_budget(job_type: str, default: int) -> int:
    for key in JOB_BUDGET_ALIASES.get(job_type, []):
        raw = os.getenv(key)
        if raw is not None:
            try:
                return max(0, int(raw))
            except Exception:
                continue
    return max(0, int(default))


def enqueue_job(
    conn,
    job_type: str,
    platform: str,
    program_external_id: str,
    payload: dict | None = None,
    priority: int = 0,
    run_after: str | None = None,
) -> bool:
    payload = payload or {}
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO job_queue(
              job_type, platform, program_external_id,
              priority, run_after, status, tries, last_error, payload, first_seen_at, last_seen_at
            )
            VALUES (%s,%s,%s,%s,COALESCE(%s::timestamptz, now()),'new',0,NULL,%s,now(),now())
            ON CONFLICT (job_type, platform, program_external_id, payload)
            DO UPDATE SET
              last_seen_at=now(),
              priority=GREATEST(job_queue.priority, EXCLUDED.priority),
              run_after=LEAST(job_queue.run_after, EXCLUDED.run_after),
              status=CASE
                WHEN job_queue.status='failed' THEN 'new'
                ELSE job_queue.status
              END
            RETURNING (xmax = 0) AS inserted;
            """,
            (job_type, platform, program_external_id, int(priority), run_after, Json(payload)),
        )
        return bool(cur.fetchone()[0])


def fetch_due_jobs(conn, platform: str, program_external_id: str, limit: int):
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, job_type, payload, priority
                FROM job_queue
                WHERE status='new'
                  AND platform=%s
                  AND program_external_id=%s
                  AND run_after <= now()
                ORDER BY priority DESC, run_after ASC, id ASC
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (platform, program_external_id, limit),
            )
            rows = cur.fetchall()
            if rows:
                ids = [r[0] for r in rows]
                cur.execute(
                    """
                    UPDATE job_queue
                    SET status='running', last_seen_at=now()
                    WHERE id = ANY(%s)
                    """,
                    (ids,),
                )
            return rows


def mark_job_done(conn, job_id: int):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE job_queue
            SET status='done', last_error=NULL, last_seen_at=now()
            WHERE id=%s
            """,
            (job_id,),
        )


def mark_job_failed(conn, job_id: int, err: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE job_queue
            SET status='failed', tries=tries+1, last_error=%s, last_seen_at=now()
            WHERE id=%s
            """,
            (err, job_id),
        )


def schedule_periodic_jobs(conn, platform: str, program_external_id: str) -> dict:
    counts = {"dns": 0, "http": 0, "tls": 0, "ip": 0}
    budgets = {
        "dns": get_job_budget("dns", JOB_BUDGET_DEFAULT),
        "http": get_job_budget("http", JOB_BUDGET_DEFAULT),
        "tls": get_job_budget("tls", JOB_BUDGET_DEFAULT),
        "ip": get_job_budget("ip", JOB_BUDGET_DEFAULT),
    }
    for job_type, budget in budgets.items():
        for slot in range(budget):
            payload = {"kind": "maintenance", "slot": slot}
            if enqueue_job(conn, job_type, platform, program_external_id, payload=payload, priority=0):
                counts[job_type] += 1
    return counts


def schedule_event_jobs(conn, platform: str, program_external_id: str) -> dict:
    counts = {
        "san_candidates": 0,
        "ip_assets": 0,
        "dns_jobs": 0,
        "http_jobs": 0,
        "tls_jobs": 0,
    }
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT san_domain
            FROM san_candidates
            WHERE platform=%s
              AND program_external_id=%s
              AND status='new'
              AND first_seen_at = last_seen_at
            ORDER BY first_seen_at DESC
            LIMIT %s
            """,
            (platform, program_external_id, SAN_EVENT_LIMIT),
        )
        san_rows = [str(r[0]) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT ip::TEXT
            FROM ip_assets_latest
            WHERE platform=%s
              AND program_external_id=%s
              AND first_seen_at = last_seen_at
            ORDER BY first_seen_at DESC
            LIMIT %s
            """,
            (platform, program_external_id, IP_EVENT_LIMIT),
        )
        ip_rows = [str(r[0]) for r in cur.fetchall()]

    counts["san_candidates"] = len(san_rows)
    counts["ip_assets"] = len(ip_rows)

    for sd in san_rows:
        payload = {"trigger": "san_correlate", "san_domain": sd}
        if enqueue_job(conn, "dns", platform, program_external_id, payload=payload, priority=10):
            counts["dns_jobs"] += 1
        if enqueue_job(conn, "http", platform, program_external_id, payload=payload, priority=10):
            counts["http_jobs"] += 1

    for ip in ip_rows:
        payload = {"trigger": "ip_discovery", "ip": ip}
        if enqueue_job(conn, "http", platform, program_external_id, payload=payload, priority=10):
            counts["http_jobs"] += 1
        if enqueue_job(conn, "tls", platform, program_external_id, payload=payload, priority=10):
            counts["tls_jobs"] += 1

    return counts


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str):
    print(f"[{ts()}] {msg}", flush=True)


def file_exists(path: str) -> bool:
    return os.path.exists(path) and os.path.isfile(path)


def which(binname: str) -> str | None:
    import shutil
    return shutil.which(binname)


def resolve_program_external_id(handle: str) -> str | None:
    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT external_id FROM programs WHERE platform='hackerone' AND handle=%s LIMIT 1",
                (handle,),
            )
            r = cur.fetchone()
            return str(r[0]) if r else None


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() == "true"


def start_run(conn, program_external_id: str, mode: str, config: dict) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO runs(platform, program_external_id, mode, status, config_json, started_at)
            VALUES ('hackerone', %s, %s, 'running', %s, now())
            RETURNING id;
            """,
            (program_external_id, mode, config),
        )
        run_id = int(cur.fetchone()[0])
    conn.commit()
    return run_id


def set_run_status(conn, run_id: int, status: str, error: str | None = None):
    with conn.cursor() as cur:
        if error:
            cur.execute(
                "UPDATE runs SET status=%s, finished_at=now(), note=%s WHERE id=%s;",
                (status, error, run_id),
            )
        else:
            cur.execute(
                "UPDATE runs SET status=%s, finished_at=now() WHERE id=%s;",
                (status, run_id),
            )
    conn.commit()


def set_run_step_running(conn, run_id: int, step_name: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO run_steps(run_id, step_name, status, started_at)
            VALUES (%s, %s, 'running', now())
            ON CONFLICT (run_id, step_name)
            DO UPDATE SET
              status='running',
              started_at=COALESCE(run_steps.started_at, EXCLUDED.started_at),
              finished_at=NULL,
              error=NULL;
            """,
            (run_id, step_name),
        )
    conn.commit()


def set_run_step_done(conn, run_id: int, step_name: str, status: str, error: str | None = None):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE run_steps
            SET status=%s, finished_at=now(), error=%s
            WHERE run_id=%s AND step_name=%s;
            """,
            (status, error, run_id, step_name),
        )
        if cur.rowcount == 0:
            cur.execute(
                """
                INSERT INTO run_steps(run_id, step_name, status, started_at, finished_at, error)
                VALUES (%s, %s, %s, now(), now(), %s);
                """,
                (run_id, step_name, status, error),
            )
    conn.commit()


@dataclass(frozen=True)
class Counts:
    http_pending: int
    port_pending: int
    targets_total: int
    js_pending: int

    def empty(self) -> bool:
        return self.http_pending == 0 and self.port_pending == 0 and self.js_pending == 0

    def key(self):
        return (self.http_pending, self.port_pending, self.targets_total, self.js_pending)


def get_counts(program_external_id: str) -> Counts:
    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM targets WHERE platform='hackerone' AND program_external_id=%s AND http_scanned_at IS NULL;",
                (program_external_id,),
            )
            http_pending = int(cur.fetchone()[0])

            cur.execute(
                "SELECT count(*) FROM targets WHERE platform='hackerone' AND program_external_id=%s AND port_scanned_at IS NULL;",
                (program_external_id,),
            )
            port_pending = int(cur.fetchone()[0])

            cur.execute(
                "SELECT count(*) FROM targets WHERE platform='hackerone' AND program_external_id=%s;",
                (program_external_id,),
            )
            targets_total = int(cur.fetchone()[0])

            js_pending = 0
            try:
                cur.execute(
                    """
                    SELECT count(*)
                    FROM js_assets j
                    JOIN targets t ON t.id=j.target_id
                    WHERE t.platform='hackerone' AND t.program_external_id=%s
                      AND j.status='new';
                    """,
                    (program_external_id,),
                )
                js_pending = int(cur.fetchone()[0])
            except Exception:
                js_pending = 0

    return Counts(http_pending=http_pending, port_pending=port_pending, targets_total=targets_total, js_pending=js_pending)


def purge_program(program_external_id: str):
    """
    Delete ONLY derived/program-scoped data.
    Must NEVER crash if some optional tables do not exist (schema drift).
    """
    def table_exists(cur, name: str) -> bool:
        cur.execute(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema='public' AND table_name=%s
            LIMIT 1;
            """,
            (name,),
        )
        return cur.fetchone() is not None

    def safe_exec(cur, sql: str, params: tuple, table_name: str):
        if table_exists(cur, table_name):
            cur.execute(sql, params)

    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM targets WHERE platform='hackerone' AND program_external_id=%s;",
                (program_external_id,),
            )
            tids = [r[0] for r in cur.fetchall()]
            if not tids:
                conn.commit()
                return

            # target-scoped derived tables (optional: may not exist)
            safe_exec(cur, "DELETE FROM http_observations WHERE target_id = ANY(%s);", (tids,), "http_observations")
            safe_exec(cur, "DELETE FROM ports_latest WHERE target_id = ANY(%s);", (tids,), "ports_latest")
            safe_exec(cur, "DELETE FROM nmap_services_latest WHERE target_id = ANY(%s);", (tids,), "nmap_services_latest")
            safe_exec(cur, "DELETE FROM tls_certs_latest WHERE target_id = ANY(%s);", (tids,), "tls_certs_latest")
            safe_exec(cur, "DELETE FROM edge_fingerprint_latest WHERE target_id = ANY(%s);", (tids,), "edge_fingerprint_latest")
            safe_exec(cur, "DELETE FROM dns_asn_latest WHERE target_id = ANY(%s);", (tids,), "dns_asn_latest")
            safe_exec(cur, "DELETE FROM url_observations WHERE target_id = ANY(%s);", (tids,), "url_observations")
            safe_exec(cur, "DELETE FROM param_observations WHERE target_id = ANY(%s);", (tids,), "param_observations")
            safe_exec(cur, "DELETE FROM js_assets WHERE target_id = ANY(%s);", (tids,), "js_assets")

            # program-scoped derived tables (optional)
            safe_exec(cur, "DELETE FROM san_candidates WHERE program_external_id=%s;", (program_external_id,), "san_candidates")
            safe_exec(cur, "DELETE FROM san_promotions WHERE candidate_id IN (SELECT id FROM san_candidates WHERE program_external_id=%s);", (program_external_id,), "san_promotions")
            safe_exec(cur, "DELETE FROM subdomain_discoveries WHERE program_external_id=%s;", (program_external_id,), "subdomain_discoveries")

            # finally delete targets
            cur.execute(
                "DELETE FROM targets WHERE platform='hackerone' AND program_external_id=%s;",
                (program_external_id,),
            )

        conn.commit()



def state_path(handle: str) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return STATE_DIR / f"{handle}.json"


def load_state(handle: str) -> dict | None:
    p = state_path(handle)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_state(handle: str, state: dict):
    p = state_path(handle)
    p.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def clear_state(handle: str):
    p = state_path(handle)
    if p.exists():
        p.unlink()


def build_env_filters(handle: str) -> dict:
    return {
        "PROGRAM_HANDLE": handle,
        "IP_PROGRAM_HANDLE": handle,
        "SUBDOMAINS_PROGRAM_HANDLE": handle,
        "WAYBACK_PROGRAM_HANDLE": handle,
        "PARAM_PROGRAM_HANDLE": handle,
        "EDGEFP_PROGRAM_HANDLE": handle,
        "DIRFUZZ_PROGRAM_HANDLE": handle,
        "CRAWL_PROGRAM_HANDLE": handle,
        "SAN_PROGRAM_HANDLE": handle,   # IMPORTANT: you were missing this (program=-)
    }


def run_cmd(cmd: list[str], env: dict, use_lock: bool) -> int:
    if use_lock and LEARN_LOCK_ENABLED:
        if not which("flock"):
            log("[WARN] flock not found; running without lock (install util-linux)")
            return subprocess.run(cmd, env=env).returncode

        lock_path = Path(LEARN_LOCK_FILE)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.touch(exist_ok=True)

        # IMPORTANT: don't use "--" separator; some flock builds reject it.
        wrapped = ["flock", "-x", str(lock_path)] + cmd
        return subprocess.run(wrapped, env=env).returncode

    return subprocess.run(cmd, env=env).returncode



def run_step(step_name: str, cmd: list[str], env_extra: dict, must_exist: str | None, lock: bool, run_conn, run_id: int | None):
    if must_exist and not file_exists(must_exist):
        log(f"[SKIP] {step_name} (missing {must_exist})")
        return

    env = os.environ.copy()
    env.update(env_extra)

    if run_conn is not None and run_id is not None:
        set_run_step_running(run_conn, run_id, step_name)

    log(f"[RUN] {step_name}: {' '.join(cmd)}" + (" (locked)" if (lock and LEARN_LOCK_ENABLED) else ""))
    rc = run_cmd(cmd, env=env, use_lock=lock)
    if rc != 0:
        if run_conn is not None and run_id is not None:
            set_run_step_done(run_conn, run_id, step_name, "fail", f"exit={rc}")
        raise RuntimeError(f"step_failed name={step_name} exit={rc}")
    if run_conn is not None and run_id is not None:
        set_run_step_done(run_conn, run_id, step_name, "ok", None)
    log(f"[OK ] {step_name}")


def ordered_steps():
    # lock=True => may write to shared learning files (wordlists/custom/*)
    return [
        ("ip_enqueue",            ["python", "workers/ip/ip_enqueue.py"],            "workers/ip/ip_enqueue.py",            False),
        ("ip_discovery",          ["python", "workers/ip/ip_discovery.py"],          "workers/ip/ip_discovery.py",          False),
        ("subdomains_resolve",     ["python", "workers/dns/subdomains_resolve.py"],     "workers/dns/subdomains_resolve.py",     True),
        ("ip_seed_queue",          ["python", "workers/ip/ip_seed_queue.py"],          "workers/ip/ip_seed_queue.py",          False),
        ("subdomains_bruteforce",  ["python", "workers/dns/subdomains_bruteforce.py"],  "workers/dns/subdomains_bruteforce.py",  True),

        ("ct_crtsh",               ["python", "workers/dns/ct_crtsh.py"],               "workers/dns/ct_crtsh.py",               False),
        ("http_reinject",          ["python", "workers/meta/http_reinject.py"],          "workers/meta/http_reinject.py",          False),
        ("crawl_light",            ["python", "workers/web/crawl_light.py"],            "workers/web/crawl_light.py",            True),
        ("wayback_urls",           ["python", "workers/dns/wayback_urls.py"],           "workers/dns/wayback_urls.py",           True),

        ("edge_fingerprint",       ["python", "workers/infra/edge_fingerprint.py"],       "workers/infra/edge_fingerprint.py",       True),
        ("enrich_dns_asn",          ["python", "workers/infra/enrich_dns_asn.py"],          "workers/infra/enrich_dns_asn.py",          False),

        ("port_reinject",          ["python", "workers/infra/port_reinject.py"],          "workers/infra/port_reinject.py",          False),
        ("nmap_services",          ["python", "workers/infra/nmap_services.py"],          "workers/infra/nmap_services.py",          False),

        ("tls_miner",              ["python", "workers/tls/tls_miner.py"],              "workers/tls/tls_miner.py",              False),
        ("san_correlate",          ["python", "workers/tls/san_correlate.py"],          "workers/tls/san_correlate.py",          False),
        ("san_learn",              ["python", "workers/dns/learn_from_san.py"],         "workers/dns/learn_from_san.py",         True),

        ("param_mine_html",        ["python", "workers/web/param_mine_html.py"],        "workers/web/param_mine_html.py",        True),
        ("param_mine_js",          ["python", "workers/web/param_mine_js.py"],          "workers/web/param_mine_js.py",          True),
        ("surface_detector_v1",    ["python", "workers/analysis/surface_detector_v1.py"],    "workers/analysis/surface_detector_v1.py",    False),
        ("surface_detector",       ["python", "workers/analysis/surface_detector.py"],       "workers/analysis/surface_detector.py",       False),

        ("dir_fuzz",               ["python", "workers/web/dir_fuzz.py"],               "workers/web/dir_fuzz.py",               True),
    ]


def job_steps(job_type: str):
    job_type = (job_type or "").strip().lower()
    if job_type == "dns":
        return [
            ("subdomains_resolve", ["python", "workers/dns/subdomains_resolve.py"], "workers/dns/subdomains_resolve.py", True),
            ("subdomains_bruteforce", ["python", "workers/dns/subdomains_bruteforce.py"], "workers/dns/subdomains_bruteforce.py", True),
        ]
    if job_type == "http":
        return [
            ("http_reinject", ["python", "workers/meta/http_reinject.py"], "workers/meta/http_reinject.py", False),
        ]
    if job_type == "tls":
        return [
            ("tls_miner", ["python", "workers/tls/tls_miner.py"], "workers/tls/tls_miner.py", False),
        ]
    if job_type == "ip":
        return [
            ("ip_enqueue", ["python", "workers/ip/ip_enqueue.py"], "workers/ip/ip_enqueue.py", False),
            ("ip_discovery", ["python", "workers/ip/ip_discovery.py"], "workers/ip/ip_discovery.py", False),
            ("ip_seed_queue", ["python", "workers/ip/ip_seed_queue.py"], "workers/ip/ip_seed_queue.py", False),
        ]
    return []


def task_steps(task_type: str):
    task_type = (task_type or "").strip().lower()
    mapping = {
        "http_reinject": ["python", "workers/meta/http_reinject.py"],
        "nmap_services": ["python", "workers/infra/nmap_services.py"],
        "crawl_light": ["python", "workers/web/crawl_light.py"],
        "san_correlate": ["python", "workers/tls/san_correlate.py"],
    }
    cmd = mapping.get(task_type)
    if not cmd:
        return None
    return (f"task:{task_type}", cmd, cmd[1], False)


def fetch_due_tasks(conn, platform: str, program_external_id: str, limit: int):
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, task_type, tries
                FROM task_queue
                WHERE status='new'
                  AND platform=%s
                  AND program_external_id=%s
                  AND run_after <= now()
                ORDER BY priority DESC, run_after ASC, id ASC
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (platform, program_external_id, limit),
            )
            rows = cur.fetchall()
            if rows:
                ids = [r[0] for r in rows]
                cur.execute(
                    """
                    UPDATE task_queue
                    SET status='running', last_seen_at=now()
                    WHERE id = ANY(%s)
                    """,
                    (ids,),
                )
            return rows


def mark_task_done(conn, task_id: int):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE task_queue
            SET status='done', last_error=NULL, last_seen_at=now()
            WHERE id=%s
            """,
            (task_id,),
        )


def mark_task_failed(conn, task_id: int, tries: int, err: str):
    next_tries = int(tries) + 1
    delay_sec = min(3600, 30 * (2 ** max(0, next_tries - 1)))
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE task_queue
            SET status='failed',
                tries=%s,
                last_error=%s,
                run_after=now() + (%s || ' seconds')::interval,
                last_seen_at=now()
            WHERE id=%s
            """,
            (next_tries, err, int(delay_sec), task_id),
        )


def run_task_engine(handle: str, program_external_id: str, env_filter: dict):
    platform = "hackerone"
    run_status = "ok"
    run_error = None
    exit_code = 0

    with psycopg.connect(DB_DSN) as conn:
        config = {
            "engine": "task",
            "toggles": {
                "TASK_MODE": True,
            },
        }
        run_id = start_run(conn, program_external_id, "task", config)

        tasks = fetch_due_tasks(conn, platform, program_external_id, TASK_TAKE)
        if not tasks:
            log("[DONE] task queue empty (no due tasks)")
            set_run_status(conn, run_id, "ok", None)
            return

        for task_id, task_type, tries in tasks:
            step = task_steps(task_type)
            if not step:
                mark_task_failed(conn, task_id, int(tries), f"unknown_task_type:{task_type}")
                conn.commit()
                continue

            step_name, cmd, must_exist, lock = step
            log(f"[INFO] task start id={task_id} type={task_type}")
            try:
                run_step(step_name, cmd, env_filter, must_exist=must_exist, lock=lock, run_conn=conn, run_id=run_id)
                mark_task_done(conn, task_id)
                conn.commit()
            except Exception as e:
                mark_task_failed(conn, task_id, int(tries), str(e))
                conn.commit()
                run_status = "fail"
                run_error = str(e)
                exit_code = 10
                log(f"[FAIL] task id={task_id} type={task_type}: {e}")

        if run_status == "fail":
            set_run_status(conn, run_id, "fail", run_error)
        else:
            set_run_status(conn, run_id, "ok", None)

    sys.exit(exit_code)


def should_run(step_name: str, counts: Counts) -> bool:
    if step_name == "subdomains_bruteforce":
        return RUN_SUB_BRUTE
    if step_name == "http_reinject":
        return counts.http_pending > 0
    if step_name == "port_reinject":
        return counts.port_pending > 0
    if step_name == "crawl_light":
        return RUN_CRAWL_LIGHT
    if step_name == "wayback_urls":
        return RUN_WAYBACK
    if step_name == "edge_fingerprint":
        return RUN_EDGE_FP
    if step_name in ("param_mine_html", "param_mine_js"):
        return RUN_PARAMS
    if step_name == "tls_miner":
        return RUN_TLS
    if step_name == "san_correlate":
        return RUN_SAN
    if step_name == "san_learn":
        return RUN_SAN_LEARN
    if step_name == "dir_fuzz":
        return RUN_DIRFUZZ
    if step_name in ("surface_detector", "surface_detector_v1"):
        return RUN_SURFACE
    if step_name in ("ip_enqueue", "ip_discovery"):
        return RUN_IP
    if step_name == "ip_seed_queue":
        return RUN_IP_SEEDS
    return True


def run_queue_engine(handle: str, program_external_id: str, env_filter: dict):
    platform = "hackerone"
    run_status = "ok"
    run_error = None
    exit_code = 0

    with psycopg.connect(DB_DSN) as conn:
        config = {
            "engine": "queue",
            "toggles": {
                "RUN_ENGINE": True,
                "RUN_SURFACE": RUN_SURFACE,
            },
        }
        run_id = start_run(conn, program_external_id, "queue", config)

        periodic = schedule_periodic_jobs(conn, platform, program_external_id)
        events = schedule_event_jobs(conn, platform, program_external_id)
        conn.commit()

        log(
            "[INFO] queue schedule "
            f"periodic_dns={periodic['dns']} periodic_http={periodic['http']} "
            f"periodic_tls={periodic['tls']} periodic_ip={periodic['ip']} "
            f"san_candidates={events['san_candidates']} ip_assets={events['ip_assets']} "
            f"dns_jobs={events['dns_jobs']} http_jobs={events['http_jobs']} tls_jobs={events['tls_jobs']}"
        )

        jobs = fetch_due_jobs(conn, platform, program_external_id, JOB_QUEUE_TAKE)
        if not jobs:
            log("[DONE] queue empty (no due jobs)")
            set_run_status(conn, run_id, "ok", None)
            return

        for job_id, job_type, payload, _priority in jobs:
            payload = payload if isinstance(payload, dict) else {}
            steps = job_steps(job_type)
            if not steps:
                mark_job_failed(conn, job_id, f"unknown_job_type:{job_type}")
                conn.commit()
                continue

            log(f"[INFO] job start id={job_id} type={job_type} payload={payload}")
            try:
                for step_name, cmd, must_exist, lock in steps:
                    env_extra = dict(env_filter)
                    env_extra["JOB_TYPE"] = job_type
                    env_extra["JOB_PAYLOAD"] = json.dumps(payload, sort_keys=True)
                    run_step(
                        f"job:{job_type}:{step_name}",
                        cmd,
                        env_extra,
                        must_exist=must_exist,
                        lock=lock,
                        run_conn=conn,
                        run_id=run_id,
                    )
                mark_job_done(conn, job_id)
                conn.commit()
            except Exception as e:
                mark_job_failed(conn, job_id, str(e))
                conn.commit()
                run_status = "fail"
                run_error = str(e)
                exit_code = 10
                log(f"[FAIL] job id={job_id} type={job_type}: {e}")

        if run_status == "fail":
            set_run_status(conn, run_id, "fail", run_error)
        else:
            set_run_status(conn, run_id, "ok", None)

    sys.exit(exit_code)


def main():
    ap = argparse.ArgumentParser()
    default_engine = "queue" if env_bool("RUN_ENGINE", False) else "linear"
    ap.add_argument("program_handle")
    ap.add_argument("--engine", choices=["linear", "queue"], default=default_engine)
    ap.add_argument("--mode", choices=["discovery", "monitor"], default="discovery")
    ap.add_argument("--purge", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--force-purge", action="store_true")
    ap.add_argument("--from-step", default="")
    ap.add_argument("--max-rounds", type=int, default=MAX_ROUNDS)
    args = ap.parse_args()

    handle = args.program_handle.strip()
    if not handle:
        log("[FATAL] missing program handle")
        sys.exit(2)

    config_global = load_yaml_config(CONFIG_DIR / "global.yaml")
    config_program = load_yaml_config(CONFIG_DIR / "programs" / f"{handle}.yaml")
    merged_config = deep_merge(config_global, config_program)
    config_env = config_to_env(merged_config, os.environ)
    if config_env:
        log(f"[INFO] config env overrides: {', '.join(sorted(config_env.keys()))}")

    global RUN_SUB_BRUTE, RUN_CRAWL_LIGHT, RUN_WAYBACK, RUN_EDGE_FP, RUN_PARAMS, RUN_TLS, RUN_SAN, RUN_SAN_LEARN, RUN_DIRFUZZ, RUN_IP, RUN_IP_SEEDS, RUN_SURFACE, RUN_ENGINE, TASK_MODE
    if args.mode == "monitor":
        RUN_SUB_BRUTE = env_bool("RUN_SUB_BRUTE", False)
        RUN_CRAWL_LIGHT = env_bool("RUN_CRAWL_LIGHT", False)
        RUN_WAYBACK = env_bool("RUN_WAYBACK", False)
    else:
        RUN_SUB_BRUTE = env_bool("RUN_SUB_BRUTE", True)
        RUN_CRAWL_LIGHT = env_bool("RUN_CRAWL_LIGHT", True)
        RUN_WAYBACK = env_bool("RUN_WAYBACK", True)

    RUN_EDGE_FP = env_bool("RUN_EDGE_FP", True)
    RUN_PARAMS = env_bool("RUN_PARAMS", True)
    RUN_TLS = env_bool("RUN_TLS", True)
    RUN_SAN = env_bool("RUN_SAN", False)
    RUN_SAN_LEARN = env_bool("RUN_SAN_LEARN", True)
    RUN_DIRFUZZ = env_bool("RUN_DIRFUZZ", False)
    RUN_IP = env_bool("RUN_IP", True)
    RUN_IP_SEEDS = env_bool("RUN_IP_SEEDS", False)
    RUN_SURFACE = env_bool("RUN_SURFACE", True)
    RUN_ENGINE = args.engine == "queue"
    TASK_MODE = env_bool("TASK_MODE", False)

    prog_ext = resolve_program_external_id(handle)
    if not prog_ext:
        log(f"[FATAL] program handle not found in DB: {handle}. Run sync_h1.py once.")
        sys.exit(3)

    env_filter = build_env_filters(handle)
    if config_env:
        env_filter.update(config_env)
    steps = ordered_steps()
    step_names = [s[0] for s in steps]

    if TASK_MODE:
        log(f"[INFO] task mode enabled (take={TASK_TAKE})")
        run_task_engine(handle, prog_ext, env_filter)
        return

    if RUN_ENGINE:
        log(f"[INFO] queue engine enabled (take={JOB_QUEUE_TAKE})")
        run_queue_engine(handle, prog_ext, env_filter)
        return

    # Start defaults
    start_round = 1
    start_step_idx = 0

    # Explicit start overrides checkpoint
    if args.from_step:
        if args.from_step not in step_names:
            log(f"[FATAL] unknown step: {args.from_step}. Known: {', '.join(step_names)}")
            sys.exit(4)
        start_step_idx = step_names.index(args.from_step)
        args.resume = False

    # If force-purge is requested, we will ignore checkpoint completely.
    if args.force_purge:
        args.resume = False  # blunt and correct

    # PURGE (if requested)
    if args.purge:
        log(f"[INFO] purge derived data for program={handle} (external_id={prog_ext})")
        purge_program(prog_ext)
        clear_state(handle)  # always clear checkpoint on purge
        log("[OK ] purge done")
        # after a real purge, start from scratch
        start_round = 1
        start_step_idx = 0

    # RESUME (only if allowed and no from-step and no force-purge and no fresh purge)
    state = load_state(handle) if args.resume else None
    checkpoint_exists = state is not None and "round" in state and "step" in state

    if checkpoint_exists and not args.from_step and not args.purge:
        start_round = int(state.get("round", 1))
        step = str(state.get("step", step_names[0]))
        if step in step_names:
            start_step_idx = step_names.index(step)
        log(f"[INFO] resuming from checkpoint: round={start_round} step={step}")

    log(f"[INFO] workflow start program={handle} mode={args.mode} max_rounds={args.max_rounds}")
    log(f"[INFO] toggles sub_brute={RUN_SUB_BRUTE} crawl={RUN_CRAWL_LIGHT} wayback={RUN_WAYBACK} edge_fp={RUN_EDGE_FP} params={RUN_PARAMS} tls={RUN_TLS} san={RUN_SAN} san_learn={RUN_SAN_LEARN} dirfuzz={RUN_DIRFUZZ} ip={RUN_IP} ip_seeds={RUN_IP_SEEDS} surface={RUN_SURFACE}")
    log(f"[INFO] budgets port={BUDGET_PORT_TARGETS_PER_ROUND} tls={BUDGET_TLS_TARGETS_PER_ROUND} crawl={BUDGET_CRAWL_TARGETS_PER_ROUND}")
    log(f"[INFO] learn_lock enabled={LEARN_LOCK_ENABLED} file={LEARN_LOCK_FILE}")

    initial = get_counts(prog_ext)
    log(f"[INFO] initial counts: {initial}")

    config = {
        "mode": args.mode,
        "toggles": {
            "RUN_SUB_BRUTE": RUN_SUB_BRUTE,
            "RUN_CRAWL_LIGHT": RUN_CRAWL_LIGHT,
            "RUN_WAYBACK": RUN_WAYBACK,
            "RUN_EDGE_FP": RUN_EDGE_FP,
            "RUN_PARAMS": RUN_PARAMS,
            "RUN_TLS": RUN_TLS,
            "RUN_SAN": RUN_SAN,
            "RUN_SAN_LEARN": RUN_SAN_LEARN,
            "RUN_DIRFUZZ": RUN_DIRFUZZ,
            "RUN_IP": RUN_IP,
            "RUN_IP_SEEDS": RUN_IP_SEEDS,
            "RUN_SURFACE": RUN_SURFACE,
        },
    }

    run_status = "ok"
    run_error = None
    exit_code = 0
    stop = False

    with psycopg.connect(DB_DSN) as run_conn:
        run_id = start_run(run_conn, prog_ext, args.mode, config)

        for round_i in range(start_round, args.max_rounds + 1):
            log(f"[INFO] ROUND {round_i}/{args.max_rounds}")

            before = get_counts(prog_ext)
            log(f"[INFO] before round counts: {before}")

            step_i0 = start_step_idx if round_i == start_round else 0

            for idx in range(step_i0, len(steps)):
                step_name, cmd, must_exist, lock = steps[idx]
                now = get_counts(prog_ext)

                if not should_run(step_name, now):
                    log(f"[SKIP] {step_name} (gated; counts={now})")
                    continue

                save_state(handle, {
                    "program_handle": handle,
                    "program_external_id": prog_ext,
                    "round": round_i,
                    "step": step_name,
                    "ts": datetime.now(timezone.utc).isoformat(),
                })

                try:
                    env_extra = dict(env_filter)
                    if step_name == "port_reinject":
                        env_extra["PORT_BATCH"] = str(BUDGET_PORT_TARGETS_PER_ROUND)
                    if step_name == "nmap_services":
                        env_extra["NMAP_BATCH"] = str(BUDGET_PORT_TARGETS_PER_ROUND)
                    if step_name == "tls_miner":
                        env_extra["TLS_BATCH"] = str(BUDGET_TLS_TARGETS_PER_ROUND)
                    if step_name == "crawl_light":
                        env_extra["CRAWL_BATCH"] = str(BUDGET_CRAWL_TARGETS_PER_ROUND)

                    run_step(step_name, cmd, env_extra, must_exist=must_exist, lock=lock, run_conn=run_conn, run_id=run_id)
                except Exception as e:
                    log(f"[FAIL] {step_name}: {e}")
                    log(f"[INFO] checkpoint saved. Fix worker and rerun: python workflow.py {handle} --purge --resume")
                    run_status = "fail"
                    run_error = str(e)
                    exit_code = 10
                    stop = True
                    break

            if stop:
                break

            after = get_counts(prog_ext)
            log(f"[INFO] after round counts: {after}")

            if after.empty():
                log("[DONE] queues empty (http_pending=0, port_pending=0, js_pending=0)")
                clear_state(handle)
                stop = True
                break

            if after.key() == before.key():
                log("[DONE] no progress in this round (stopping)")
                clear_state(handle)
                stop = True
                break

            time.sleep(SLEEP_BETWEEN_ROUNDS)

        if not stop and exit_code == 0:
            log("[DONE] max rounds reached")
            clear_state(handle)

        if run_status == "fail":
            set_run_status(run_conn, run_id, "fail", run_error)
        else:
            set_run_status(run_conn, run_id, "ok", None)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
