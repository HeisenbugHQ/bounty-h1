#!/usr/bin/env python3
"""
workers/worker_http_reinject.py

HTTP probing with rich ingestion (httpx -> http_observations).

Input:
- targets where http_scanned_at IS NULL (pending)

Output:
- http_observations (upsert new rows)
- targets.http_scanned_at marked

Env (.env) optional:
  HTTP_BATCH_SIZE=500
  HTTPX_BIN=httpx
  HTTPX_PORTS=80,443,8080,8443,8000,8888
  HTTPX_TIMEOUT=10
  HTTPX_THREADS=50
"""

import os
import json
import subprocess
from typing import Dict, Any, Optional

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

BATCH = int(os.getenv("HTTP_BATCH_SIZE", "500"))
HTTPX_BIN = os.getenv("HTTPX_BIN", "httpx")
HTTPX_PORTS = os.getenv("HTTPX_PORTS", "80,443,8080,8443,8000,8888")
HTTPX_TIMEOUT = os.getenv("HTTPX_TIMEOUT", "10")
HTTPX_THREADS = os.getenv("HTTPX_THREADS", "50")

HEADER_ALLOWLIST = {
    "content-security-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "set-cookie",
    "location",
    "server",
    "via",
    "x-cache",
    "cf-ray",
    "cf-cache-status",
    "x-amz-cf-id",
    "x-iinfo",
}


def fetch_pending(cur):
    cur.execute(
        """
        SELECT id, host
        FROM targets
        WHERE platform='hackerone'
          AND http_scanned_at IS NULL
        ORDER BY first_seen_at ASC
        LIMIT %s
        """,
        (BATCH,),
    )
    return cur.fetchall()


def run_httpx(hosts):
    # Flags are intentionally rich. Some fields may or may not appear depending on httpx version.
    cmd = [
        HTTPX_BIN,
        "-silent",
        "-json",
        "-threads", str(HTTPX_THREADS),
        "-ports", HTTPX_PORTS,
        "-timeout", str(HTTPX_TIMEOUT),
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-content-type",
        "-content-length",
        "-location",
        "-ip",
        "-cname",
        "-cdn",
        "-favicon",
        # Include response headers if supported by your httpx build
        "-include-response-header",
    ]

    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert p.stdin and p.stdout
    p.stdin.write("\n".join(hosts))
    p.stdin.close()
    return p


def pick_headers(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    httpx may emit headers under keys like:
      - "header" (string)
      - "headers" (map)
      - "response_headers" (map)
    We'll try multiple, keep allowlist only.
    Also for set-cookie we store only cookie names.
    """
    headers = None
    for k in ("headers", "response_headers"):
        if isinstance(obj.get(k), dict):
            headers = obj.get(k)
            break

    # Some versions provide a raw header string. We won't parse it here.
    if headers is None:
        return {}

    out = {}
    for k, v in headers.items():
        lk = str(k).lower()
        if lk not in HEADER_ALLOWLIST:
            continue

        # Normalize set-cookie: keep cookie names only (avoid values)
        if lk == "set-cookie":
            names = []
            if isinstance(v, list):
                items = v
            else:
                items = [v]
            for item in items:
                try:
                    part = str(item).split(";", 1)[0]
                    cname = part.split("=", 1)[0].strip()
                    if cname:
                        names.append(cname)
                except Exception:
                    continue
            out["set-cookie-names"] = sorted(set(names))
            continue

        out[lk] = v

    return out


def main():
    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            rows = fetch_pending(cur)

        if not rows:
            print("[INFO] No HTTP pending targets.")
            return

        host_to_id = {host: tid for tid, host in rows}
        hosts = list(host_to_id.keys())

        print(f"[INFO] httpx batch={len(hosts)}")
        p = run_httpx(hosts)

        inserted = 0
        with conn.cursor() as cur:
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue

                host = (o.get("host") or o.get("input") or "").strip().lower()
                if host not in host_to_id:
                    # Some httpx versions output full URL in input; try best effort
                    inp = (o.get("input") or "").strip().lower()
                    if inp in host_to_id:
                        host = inp
                    else:
                        continue

                target_id = host_to_id[host]

                url = o.get("url")
                final_url = o.get("final_url") or o.get("final-url") or o.get("url")
                scheme = o.get("scheme")
                port = o.get("port")

                status_code = o.get("status_code") or o.get("status-code")
                title = o.get("title")
                server = o.get("webserver") or o.get("server") or o.get("web-server")

                tech = o.get("tech") or o.get("technologies") or {}
                content_type = o.get("content_type") or o.get("content-type")
                content_length = o.get("content_length") or o.get("content-length")
                location = o.get("location")

                ip = o.get("ip")
                cname = o.get("cname")
                cdn = o.get("cdn")
                favicon = o.get("favicon") or o.get("favicon_mmh3") or o.get("favicon-hash")

                headers_selected = pick_headers(o)

                # redirect chain: httpx doesn't always provide it; keep location trail if present
                redirect_chain = None
                if isinstance(o.get("chain"), list):
                    redirect_chain = o.get("chain")

                cur.execute(
                    """
                    INSERT INTO http_observations(
                      target_id, scheme, port, url,
                      status_code, title, server_header, tech_json,
                      content_type, content_length, final_url, redirect_chain,
                      ip, cname, cdn, favicon_mmh3, headers_selected
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        target_id, scheme, port, url,
                        status_code, title, server, json.dumps(tech),
                        content_type, content_length, final_url, redirect_chain,
                        ip, cname, cdn, favicon, json.dumps(headers_selected),
                    ),
                )
                inserted += 1

            # mark processed even if no httpx hit; otherwise you'll loop forever
            cur.execute(
                """
                UPDATE targets
                SET http_scanned_at = now()
                WHERE id = ANY(%s)
                """,
                ([tid for tid, _ in rows],),
            )

            conn.commit()

        err = ""
        if p.stderr:
            err = p.stderr.read().strip()
        if err:
            print("[WARN] httpx stderr (truncated):", err[:300])

        print(f"[DONE] httpx inserted_rows={inserted} marked_http_scanned={len(rows)}")


if __name__ == "__main__":
    main()
