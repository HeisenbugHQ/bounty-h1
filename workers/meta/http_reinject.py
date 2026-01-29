#!/usr/bin/env python3
"""
workers/meta/http_reinject.py

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
from typing import Dict, Any, List, Tuple

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

# Whitelisted headers only (lowercase)
HEADER_WHITELIST = {
    "content-security-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "set-cookie",
    "location",
    "via",
    "x-forwarded-for",
    "x-real-ip",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cf-ray",
    "cf-cache-status",
    "server-timing",
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


def extract_headers(obj: Dict[str, Any]) -> Dict[str, List[str]]:
    headers = None
    for k in ("headers", "response_headers"):
        if isinstance(obj.get(k), dict):
            headers = obj.get(k)
            break
    if headers is None:
        return {}

    out: Dict[str, List[str]] = {}
    for k, v in headers.items():
        lk = str(k).lower()
        if lk not in HEADER_WHITELIST:
            continue
        if isinstance(v, list):
            vals = [str(x) for x in v if x is not None]
        else:
            vals = [str(v)] if v is not None else []
        if not vals:
            continue
        out.setdefault(lk, []).extend(vals)
    return out


def normalize_header_values(values: List[str]) -> Any:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return values


def parse_set_cookie(values: List[str]) -> Dict[str, Any]:
    count = 0
    flags_set = set()
    domains = set()
    paths = set()

    for item in values:
        try:
            count += 1
            parts = [p.strip() for p in str(item).split(";") if p.strip()]
            for flag in parts[1:]:
                f = flag.strip()
                fl = f.lower()
                if fl == "secure":
                    flags_set.add("Secure")
                elif fl == "httponly":
                    flags_set.add("HttpOnly")
                elif fl.startswith("samesite"):
                    val = f.split("=", 1)[1].strip() if "=" in f else ""
                    if val:
                        flags_set.add(f"SameSite={val}")
                elif fl.startswith("domain="):
                    dom = f.split("=", 1)[1].strip()
                    if dom:
                        domains.add(dom)
                elif fl.startswith("path="):
                    pth = f.split("=", 1)[1].strip()
                    if pth:
                        paths.add(pth)
        except Exception:
            continue

    return {
        "count": count,
        "flags": sorted(flags_set),
        "domains": sorted(domains),
        "paths": sorted(paths),
    }


def build_headers_selected(obj: Dict[str, Any]) -> Dict[str, Any]:
    headers = extract_headers(obj)
    selected: Dict[str, Any] = {}

    for k, v in headers.items():
        if k == "set-cookie":
            selected["set-cookie"] = parse_set_cookie(v)
        else:
            selected[k] = normalize_header_values(v)

    return selected


def build_tech_hints(headers_selected: Dict[str, Any]) -> Dict[str, Any]:
    """
    Example:
    tech_json->hints = {
      "cdn": null,
      "waf": null,
      "proxy": null,
      "signals": ["cloudflare", "varnish", "cdn-cache"]
    }
    """
    signals = set()
    cdn = None
    waf = None
    proxy = None

    def sget(key: str) -> str:
        v = headers_selected.get(key)
        if isinstance(v, list):
            return " ".join([str(x) for x in v if x is not None]).lower()
        return str(v).lower() if v is not None else ""

    if "cf-ray" in headers_selected or "cf-cache-status" in headers_selected:
        signals.add("cloudflare")
    if "cloudflare" in sget("server"):
        signals.add("cloudflare")
    if "varnish" in sget("via"):
        signals.add("varnish")
        proxy = proxy or "varnish"
    if "cdn-cache" in sget("server-timing") or "cache" in sget("server-timing"):
        signals.add("cdn-cache")

    return {
        "cdn": cdn,
        "waf": waf,
        "proxy": proxy,
        "signals": sorted(signals),
    }


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
        header_key_counts: Dict[str, int] = {}

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

                ip = o.get("ip")
                cname = o.get("cname")
                cdn = o.get("cdn")
                favicon = o.get("favicon") or o.get("favicon_mmh3") or o.get("favicon-hash")

                headers_selected = build_headers_selected(o) or {}
                hints = build_tech_hints(headers_selected)
                if isinstance(tech, dict):
                    tech = dict(tech)
                    tech["hints"] = hints
                else:
                    tech = {"hints": hints}
                for k in headers_selected.keys():
                    header_key_counts[k] = header_key_counts.get(k, 0) + 1

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

        if header_key_counts:
            keys_sorted = sorted(header_key_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            keys_summary = ", ".join([f"{k}" for k, _ in keys_sorted])
            print(f"[INFO] headers_selected_keys=[{keys_summary}]")

        print(f"[DONE] httpx inserted_rows={inserted} marked_http_scanned={len(rows)}")


if __name__ == "__main__":
    main()
