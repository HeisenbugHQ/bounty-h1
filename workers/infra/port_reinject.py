#!/usr/bin/env python3
"""
workers/worker_port_reinject.py

Robust port scan reinject:
- fetch targets where port_scanned_at is NULL
- run naabu on hosts (chunked to avoid whole-batch timeout)
- upsert into ports_latest
- mark targets.port_scanned_at only for chunks that completed

IMPORTANT: targets.source column has been removed.

Env (.env):
  DB_DSN=postgresql://bounty:bounty@127.0.0.1:5432/bountydb

Optional:
  PORT_BATCH=200

  NAABU_BIN=naabu
  NAABU_MODE=top            # top|full
  NAABU_TOP_PORTS=1000
  NAABU_RATE=2000
  NAABU_TIMEOUT=600         # seconds, per chunk
  NAABU_CHUNK=50            # number of hosts per naabu run
  NAABU_RETRIES=1           # retries on timeout
  NAABU_MARK_ON_TIMEOUT=false  # if true, marks scanned even if timeout (not recommended)

Output parsing expects "host:port" lines (naabu -silent).
"""

import os
import re
import subprocess
import tempfile
from datetime import datetime
from typing import List, Tuple

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PORT_BATCH = int(os.getenv("PORT_BATCH", "200"))

NAABU_BIN = os.getenv("NAABU_BIN", "naabu")
NAABU_MODE = os.getenv("NAABU_MODE", "top").strip().lower()
NAABU_TOP_PORTS = int(os.getenv("NAABU_TOP_PORTS", "1000"))
NAABU_RATE = int(os.getenv("NAABU_RATE", "2000"))
NAABU_TIMEOUT = int(os.getenv("NAABU_TIMEOUT", "600"))
NAABU_CHUNK = int(os.getenv("NAABU_CHUNK", "50"))
NAABU_RETRIES = int(os.getenv("NAABU_RETRIES", "1"))
NAABU_MARK_ON_TIMEOUT = os.getenv("NAABU_MARK_ON_TIMEOUT", "false").strip().lower() == "true"

LINE_RE = re.compile(r"^(?P<host>[a-zA-Z0-9\.\-]+):(?P<port>\d+)$")


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def norm(s: str) -> str:
    return (s or "").strip().lower().rstrip(".")


def chunked(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def fetch_targets(conn, limit: int) -> List[Tuple[int, str]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, host
            FROM targets
            WHERE port_scanned_at IS NULL
            ORDER BY id
            LIMIT %s
            """,
            (limit,),
        )
        return [(int(r[0]), norm(r[1])) for r in cur.fetchall()]


def build_naabu_cmd(input_file: str) -> List[str]:
    cmd = [
        NAABU_BIN,
        "-l", input_file,
        "-silent",
        "-rate", str(NAABU_RATE),
    ]
    if NAABU_MODE == "top":
        cmd += ["-top-ports", str(NAABU_TOP_PORTS)]
    elif NAABU_MODE == "full":
        # "all ports" varies by naabu version; keep top as sane default if unsupported
        cmd += ["-p", "-"]
    else:
        cmd += ["-top-ports", str(NAABU_TOP_PORTS)]
    return cmd


def parse_naabu_output(stdout: str) -> List[Tuple[str, int]]:
    open_ports = []
    for line in stdout.splitlines():
        line = line.strip()
        m = LINE_RE.match(line)
        if not m:
            continue
        open_ports.append((norm(m.group("host")), int(m.group("port"))))
    return sorted(set(open_ports))


def run_naabu_once(hosts: List[str]) -> Tuple[bool, List[Tuple[str, int]], str]:
    """
    Returns:
      (completed_ok, open_ports, stderr_preview)
    """
    if not hosts:
        return True, [], ""

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        for h in hosts:
            f.write(h + "\n")
        f.flush()
        in_path = f.name

    cmd = build_naabu_cmd(in_path)

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=NAABU_TIMEOUT)
        open_ports = parse_naabu_output(p.stdout or "")
        stderr_preview = (p.stderr or "").strip()[:2000]
        return True, open_ports, stderr_preview
    except subprocess.TimeoutExpired as e:
        stderr_preview = ""
        if e.stderr:
            try:
                stderr_preview = e.stderr.decode("utf-8", errors="ignore")[:2000]
            except Exception:
                stderr_preview = str(e.stderr)[:2000]
        return False, [], stderr_preview


def upsert_ports(conn, target_by_host: dict, open_ports: List[Tuple[str, int]]) -> int:
    rows = 0
    with conn.cursor() as cur:
        for host, port in open_ports:
            tid = target_by_host.get(host)
            if not tid:
                continue
            cur.execute(
                """
                INSERT INTO ports_latest(target_id, proto, port, state, first_seen_at, last_seen_at)
                VALUES (%s, 'tcp', %s, 'open', now(), now())
                ON CONFLICT (target_id, proto, port)
                DO UPDATE SET last_seen_at=now(), state='open'
                """,
                (tid, port),
            )
            rows += 1
    return rows


def mark_scanned(conn, target_ids: List[int]) -> int:
    if not target_ids:
        return 0
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE targets SET port_scanned_at=now() WHERE id = ANY(%s)",
            (target_ids,),
        )
        return cur.rowcount


def main():
    with psycopg.connect(DB_DSN) as conn:
        batch = fetch_targets(conn, PORT_BATCH)
        if not batch:
            print(f"[{ts()}] [DONE] Port reinject: no pending targets")
            return

        # map host -> target_id
        target_by_host = {host: tid for tid, host in batch}

        total_ports_upserted = 0
        total_marked = 0
        total_timeouts = 0
        total_hosts = len(batch)

        print(f"[{ts()}] [INFO] Port reinject batch: {total_hosts} targets (engine=naabu, mode={NAABU_MODE})")
        print(f"[{ts()}] [INFO] Settings: top_ports={NAABU_TOP_PORTS} rate={NAABU_RATE} timeout={NAABU_TIMEOUT}s chunk={NAABU_CHUNK} retries={NAABU_RETRIES}")

        for chunk_i, chunk in enumerate(list(chunked(batch, NAABU_CHUNK)), start=1):
            chunk_hosts = [h for _, h in chunk]
            chunk_ids = [tid for tid, _ in chunk]

            print(f"[{ts()}] [INFO] Chunk {chunk_i}: hosts={len(chunk_hosts)} running naabu...")

            completed = False
            open_ports: List[Tuple[str, int]] = []
            stderr_preview = ""

            for attempt in range(1, NAABU_RETRIES + 2):  # 1 try + retries
                ok, ports, serr = run_naabu_once(chunk_hosts)
                if ok:
                    completed = True
                    open_ports = ports
                    stderr_preview = serr
                    break
                else:
                    stderr_preview = serr
                    print(f"[{ts()}] [WARN] Chunk {chunk_i} timeout attempt {attempt}/{NAABU_RETRIES+1}")
                    if attempt <= NAABU_RETRIES:
                        print(f"[{ts()}] [INFO] Retrying chunk {chunk_i}...")

            if not completed:
                total_timeouts += 1
                print(f"[{ts()}] [ERROR] Chunk {chunk_i} timed out after {NAABU_TIMEOUT}s.")
                if stderr_preview:
                    print(f"[{ts()}] [ERROR] naabu stderr (preview): {stderr_preview}")
                if NAABU_MARK_ON_TIMEOUT:
                    marked = mark_scanned(conn, chunk_ids)
                    conn.commit()
                    total_marked += marked
                    print(f"[{ts()}] [WARN] Marked scanned despite timeout (NAABU_MARK_ON_TIMEOUT=true): {marked}")
                continue

            if stderr_preview:
                # Not fatal, but helpful for debugging
                print(f"[{ts()}] [INFO] naabu stderr (preview): {stderr_preview}")

            rows = upsert_ports(conn, target_by_host, open_ports)
            marked = mark_scanned(conn, chunk_ids)
            conn.commit()

            total_ports_upserted += rows
            total_marked += marked

            print(f"[{ts()}] [OK] Chunk {chunk_i} done: open_ports={len(open_ports)} ports_upserted={rows} marked={marked}")

        print(f"[{ts()}] [DONE] Port reinject processed={total_hosts} ports_upserted={total_ports_upserted} marked_port_scanned={total_marked} timeouts={total_timeouts}")


if __name__ == "__main__":
    main()
