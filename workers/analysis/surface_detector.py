#!/usr/bin/env python3
"""
workers/analysis/surface_detector.py

Surface detector:
- reads url_observations + v_latest_http_by_target
- uses param_observations for object-model hints
- writes findings to surface_findings (idempotent)

Patterns (simple):
  auth/login: /login /signin /oauth /sso /auth /oidc
  openapi/swagger: /swagger /openapi /api-docs /graphql
  upload/import: /upload /import /csv /bulk /file
  admin: /admin /dashboard /manage
  object model hints: param names id, uuid, objectId, accountId, tenantId

Env:
  DB_DSN (required)
  SURFACE_BATCH=500
"""

import json
import os
import re
from urllib.parse import urlparse

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

BATCH = int(os.getenv("SURFACE_BATCH", "500"))

AUTH_RE = re.compile(r"/(login|signin|sign-in|sign_in|oauth|sso|auth|oidc)\b", re.IGNORECASE)
OPENAPI_RE = re.compile(r"/(swagger|openapi|api-docs|graphql)\b", re.IGNORECASE)
UPLOAD_RE = re.compile(r"/(upload|import|csv|bulk|file)\b", re.IGNORECASE)
ADMIN_RE = re.compile(r"/(admin|dashboard|manage)\b", re.IGNORECASE)

PARAM_HINTS = {
    "id",
    "uuid",
    "objectid",
    "accountid",
    "tenantid",
}


def ts() -> str:
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")


def normalize_path(u: str) -> str:
    try:
        p = urlparse(u)
        path = p.path or "/"
    except Exception:
        path = u or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def uniq(seq):
    seen = set()
    out = []
    for x in seq:
        if x is None:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def fetch_targets(cur):
    cur.execute(
        """
        SELECT
          t.id,
          h.final_url,
          h.status_code,
          h.title,
          h.content_type
        FROM targets t
        JOIN v_latest_http_by_target h ON h.target_id=t.id
        WHERE t.platform='hackerone'
        ORDER BY h.observed_at DESC
        LIMIT %s
        """,
        (BATCH,),
    )
    return cur.fetchall()


def fetch_urls(cur, target_id: int):
    cur.execute(
        """
        SELECT url
        FROM url_observations
        WHERE target_id=%s
        """,
        (target_id,),
    )
    return [r[0] for r in cur.fetchall()]


def fetch_params(cur, target_id: int):
    cur.execute(
        """
        SELECT param_name
        FROM param_observations
        WHERE target_id=%s
        """,
        (target_id,),
    )
    return [r[0] for r in cur.fetchall()]


def match_findings(paths, params, http_info):
    findings = []

    for p in paths:
        if AUTH_RE.search(p):
            findings.append(("auth", p, 70, {"match": "path", "pattern": "auth"}))
        if OPENAPI_RE.search(p):
            findings.append(("openapi", p, 70, {"match": "path", "pattern": "openapi"}))
        if UPLOAD_RE.search(p):
            findings.append(("upload", p, 70, {"match": "path", "pattern": "upload"}))
        if ADMIN_RE.search(p):
            findings.append(("admin", p, 70, {"match": "path", "pattern": "admin"}))

    # HTTP hints from final_url/title/content_type (lightweight)
    final_url = (http_info.get("final_url") or "").lower()
    title = (http_info.get("title") or "").lower()
    content_type = (http_info.get("content_type") or "").lower()

    if any(x in final_url for x in ["/login", "/signin", "/auth", "/oauth", "/sso", "/oidc"]):
        findings.append(("auth", final_url, 50, {"match": "final_url"}))
    if any(x in final_url for x in ["/swagger", "/openapi", "/api-docs", "/graphql"]):
        findings.append(("openapi", final_url, 50, {"match": "final_url"}))
    if "swagger" in title or "openapi" in title:
        findings.append(("openapi", final_url or "title", 50, {"match": "title"}))
    if "graphql" in content_type:
        findings.append(("openapi", final_url or "content_type", 40, {"match": "content_type"}))

    # Object model hints from params
    for p in params:
        if not p:
            continue
        k = p.strip().lower()
        if k in PARAM_HINTS:
            findings.append(("object_model", k, 60, {"match": "param", "param": k}))

    return findings


def main():
    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            targets = fetch_targets(cur)

        if not targets:
            print(f"[{ts()}] [INFO] no surface candidates")
            return

        counts = {}
        top = []
        total = 0

        for target_id, final_url, status_code, title, content_type in targets:
            with conn.cursor() as cur:
                urls = fetch_urls(cur, target_id)
                params = fetch_params(cur, target_id)

            paths = uniq([normalize_path(u) for u in urls if u])
            params = uniq([p for p in params if p])

            http_info = {
                "final_url": final_url,
                "status_code": status_code,
                "title": title,
                "content_type": content_type,
            }

            findings = match_findings(paths, params, http_info)
            if not findings:
                continue

            with conn.cursor() as cur:
                for finding_type, url, confidence, reasons in findings:
                    cur.execute(
                        """
                        INSERT INTO surface_findings(
                          target_id, finding_type, url, confidence, reasons, first_seen_at, last_seen_at
                        )
                        VALUES (%s,%s,%s,%s,%s,now(),now())
                        ON CONFLICT (target_id, finding_type, url)
                        DO UPDATE SET
                          confidence=GREATEST(surface_findings.confidence, EXCLUDED.confidence),
                          reasons=surface_findings.reasons || EXCLUDED.reasons,
                          last_seen_at=now()
                        """,
                        (target_id, finding_type, url, int(confidence), json.dumps(reasons)),
                    )
                    counts[finding_type] = counts.get(finding_type, 0) + 1
                    total += 1
                    if len(top) < 20:
                        top.append((finding_type, url, confidence, target_id))

        conn.commit()

        print(f"[{ts()}] [DONE] findings_total={total} " + " ".join([f"{k}={v}" for k, v in sorted(counts.items())]))
        if top:
            print(f"[{ts()}] [INFO] top_findings:")
            for finding_type, url, confidence, target_id in top[:20]:
                print(f"  - type={finding_type} url={url} conf={confidence} target_id={target_id}")


if __name__ == "__main__":
    main()
