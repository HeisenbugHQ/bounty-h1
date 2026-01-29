#!/usr/bin/env python3
"""
workers/analysis/surface_detector_v1.py

Surface Detector v1 (rule-based):
- Uses existing DB data only (url_observations, param_observations, v_latest_http_by_target)
- Idempotent upsert into surface_findings

Env:
  DB_DSN (required)
  PROGRAM_HANDLE (optional)
  PROGRAM_EXTERNAL_ID (optional)
  SURFACE_BATCH_URLS=2000
  SURFACE_SINCE_HOURS=168
  SURFACE_MIN_CONF=50
"""

import json
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PROGRAM_HANDLE = os.getenv("PROGRAM_HANDLE", "").strip()
PROGRAM_EXTERNAL_ID = os.getenv("PROGRAM_EXTERNAL_ID", "").strip()

BATCH_URLS = int(os.getenv("SURFACE_BATCH_URLS", "2000"))
SINCE_HOURS = int(os.getenv("SURFACE_SINCE_HOURS", "168"))
MIN_CONF = int(os.getenv("SURFACE_MIN_CONF", "50"))

CATEGORY_SEVERITY = {
    "auth": 60,
    "openapi": 50,
    "graphql": 55,
    "admin": 65,
    "upload": 55,
    "import": 50,
    "reset": 50,
    "invite": 45,
    "webhook": 40,
    "callback": 40,
    "api": 40,
    "storage": 70,
    "other": 30,
}

RULES = [
    {
        "category": "auth",
        "rule_id": "auth:path",
        "path": [r"/login", r"/signin", r"/auth", r"/oauth", r"/sso", r"/session", r"/token", r"/logout"],
    },
    {
        "category": "reset",
        "rule_id": "reset:path",
        "path": [r"/reset", r"/forgot", r"/recover", r"/password-reset", r"/password_reset", r"/activate", r"/verify"],
    },
    {
        "category": "invite",
        "rule_id": "invite:path",
        "path": [r"/invite", r"/invitation"],
    },
    {
        "category": "openapi",
        "rule_id": "openapi:path",
        "path": [r"/swagger", r"/openapi", r"/api-docs", r"/swagger.json", r"/openapi.json", r"/redoc"],
    },
    {
        "category": "graphql",
        "rule_id": "graphql:path",
        "path": [r"/graphql"],
    },
    {
        "category": "admin",
        "rule_id": "admin:path",
        "path": [r"/admin", r"/administrator", r"/wp-admin", r"/console", r"/manage", r"/dashboard"],
    },
    {
        "category": "upload",
        "rule_id": "upload:path",
        "path": [r"/upload", r"/file", r"/files", r"/attachments", r"/media"],
    },
    {
        "category": "import",
        "rule_id": "import:path",
        "path": [r"/import", r"/imports", r"/csv", r"/bulk"],
    },
    {
        "category": "webhook",
        "rule_id": "webhook:path",
        "path": [r"/webhook", r"/hooks"],
    },
    {
        "category": "callback",
        "rule_id": "callback:path",
        "path": [r"/callback", r"/cb", r"/return", r"/redirect_uri"],
    },
    {
        "category": "api",
        "rule_id": "api:path",
        "path": [r"/api/", r"/v1/", r"/v2/", r"/rest/"],
    },
]

PARAM_AUTH = {"username", "user", "email", "password", "passwd", "token", "code", "otp", "mfa", "saml", "relaystate"}
PARAM_RESET_INVITE = {"reset", "invite", "activation", "verification"}
PARAM_UPLOAD = {"file", "filename", "upload", "attachment", "import"}
PARAM_GRAPHQL = {"query", "operationname", "variables"}

STORAGE_HOST_PATTERNS = [
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "digitaloceanspaces",
    "r2.cloudflarestorage",
]
STORAGE_EXTENSIONS = [".map", ".env", ".bak", ".old", ".zip", ".tar.gz"]


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    try:
        p = urlparse(u)
    except Exception:
        return u

    scheme = (p.scheme or "http").lower()
    netloc = (p.netloc or p.path).lower()
    path = p.path if p.netloc else ""
    path = path or "/"
    cleaned = urlunparse((scheme, netloc, path, "", p.query, ""))
    return cleaned


def url_path(u: str) -> str:
    try:
        p = urlparse(u)
        return p.path or "/"
    except Exception:
        return "/"


def host_from_url(u: str) -> str:
    try:
        p = urlparse(u)
        return (p.netloc or "").lower()
    except Exception:
        return ""


def match_path(patterns, path: str) -> list[str]:
    matched = []
    for pat in patterns:
        if re.search(pat, path, re.IGNORECASE):
            matched.append(pat)
    return matched


def merge_unique(seq):
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


def fetch_targets_for_program(cur, program_external_id: str):
    cur.execute(
        """
        SELECT id, host
        FROM targets
        WHERE platform='hackerone' AND program_external_id=%s
        """,
        (program_external_id,),
    )
    return cur.fetchall()


def fetch_urls(cur, target_ids: list[int], since_dt):
    cur.execute(
        """
        SELECT target_id, url, source, last_seen_at
        FROM url_observations
        WHERE target_id = ANY(%s)
          AND last_seen_at >= %s
        ORDER BY last_seen_at DESC
        LIMIT %s
        """,
        (target_ids, since_dt, BATCH_URLS),
    )
    return cur.fetchall()


def fetch_params(cur, target_ids: list[int], since_dt):
    cur.execute(
        """
        SELECT url, param_name
        FROM param_observations
        WHERE target_id = ANY(%s)
          AND last_seen_at >= %s
        """,
        (target_ids, since_dt),
    )
    return cur.fetchall()


def fetch_latest_http(cur, target_ids: list[int]):
    cur.execute(
        """
        SELECT target_id, status_code, title, content_type, final_url, headers_selected
        FROM v_latest_http_by_target
        WHERE target_id = ANY(%s)
        """,
        (target_ids,),
    )
    return cur.fetchall()


def build_findings(url: str, path: str, params: list[str], http_info: dict, sources: list[str]):
    findings = []
    matched_all = []

    status_code = http_info.get("status_code")
    title = (http_info.get("title") or "").lower()
    content_type = (http_info.get("content_type") or "").lower()
    headers = http_info.get("headers_selected") or {}

    # Base rules (path)
    for rule in RULES:
        pats = match_path(rule["path"], path)
        if not pats:
            continue
        category = rule["category"]
        rule_id = rule["rule_id"]
        confidence = 60
        severity = CATEGORY_SEVERITY.get(category, 30)
        matched = [f"path:{p}" for p in pats]

        if category == "admin" and status_code == 404:
            continue

        if category == "auth":
            if status_code in (200, 302, 401, 403):
                confidence += 10
            if "login" in title or "sign in" in title or "signin" in title:
                confidence += 10
            if headers.get("set-cookie"):
                sc_flags = (headers.get("set-cookie") or {}).get("flags", [])
                if "Secure" not in sc_flags or "HttpOnly" not in sc_flags:
                    confidence += 10
                    severity += 10
            if headers.get("access-control-allow-origin") == "*":
                confidence += 5

        if category == "openapi":
            if content_type.startswith("application/json"):
                confidence += 10

        if category == "graphql":
            if content_type.startswith("application/json"):
                confidence += 10

        if category == "upload" or category == "import":
            if status_code in (200, 201, 302, 401, 403):
                confidence += 5

        findings.append((category, rule_id, confidence, severity, matched))
        matched_all.extend(matched)

    # Param-based rules
    params_l = {p.lower() for p in params}
    if params_l & PARAM_AUTH:
        findings.append(("auth", "auth:param", 60, CATEGORY_SEVERITY["auth"], ["param:auth"]))
    if params_l & PARAM_RESET_INVITE:
        findings.append(("reset", "reset:param", 55, CATEGORY_SEVERITY["reset"], ["param:reset"]))
    if params_l & PARAM_UPLOAD:
        findings.append(("upload", "upload:param", 55, CATEGORY_SEVERITY["upload"], ["param:upload"]))
    if params_l & PARAM_GRAPHQL:
        findings.append(("graphql", "graphql:param", 55, CATEGORY_SEVERITY["graphql"], ["param:graphql"]))

    # Storage/Static patterns
    url_l = url.lower()
    if any(h in url_l for h in STORAGE_HOST_PATTERNS):
        findings.append(("storage", "storage:host", 80, CATEGORY_SEVERITY["storage"], ["host:storage"]))
    if any(url_l.endswith(ext) or ("/static/" in url_l) or ("/assets/" in url_l) for ext in STORAGE_EXTENSIONS):
        findings.append(("storage", "storage:path", 70, CATEGORY_SEVERITY["storage"], ["path:static_asset"]))

    # API category (if not already matched by openapi/graphql)
    if re.search(r"/api/|/v[0-9]+/|/rest/", path, re.IGNORECASE):
        findings.append(("api", "api:path", 50, CATEGORY_SEVERITY["api"], ["path:api"]))

    # Filter by MIN_CONF and build evidence
    out = []
    for category, rule_id, confidence, severity, matched in findings:
        if confidence < MIN_CONF:
            continue
        evidence = {
            "matched": merge_unique(matched),
            "params": merge_unique(params)[:30],
            "headers": {
                "csp": headers.get("content-security-policy"),
                "acao": headers.get("access-control-allow-origin"),
                "set_cookie_flags": (headers.get("set-cookie") or {}).get("flags", []),
            },
            "title": http_info.get("title"),
            "status": status_code,
            "content_type": http_info.get("content_type"),
            "final_url": http_info.get("final_url"),
            "source": merge_unique(sources),
        }
        out.append((category, rule_id, confidence, severity, evidence))

    return out


def main():
    since_dt = datetime.now() - timedelta(hours=SINCE_HOURS)

    with psycopg.connect(DB_DSN) as conn:
        conn.autocommit = False

        if PROGRAM_HANDLE:
            prog_ext = resolve_program_external_id(conn, PROGRAM_HANDLE)
            if not prog_ext:
                print(f"[{ts()}] [WARN] PROGRAM_HANDLE not found: {PROGRAM_HANDLE}")
                return
        else:
            prog_ext = PROGRAM_EXTERNAL_ID

        if not prog_ext:
            print(f"[{ts()}] [WARN] program_external_id missing; set PROGRAM_HANDLE or PROGRAM_EXTERNAL_ID")
            return

        with conn.cursor() as cur:
            targets = fetch_targets_for_program(cur, prog_ext)

        target_ids = [int(t[0]) for t in targets]
        if not target_ids:
            print(f"[{ts()}] [INFO] no targets for program")
            return

        url_map = {}
        url_sources = {}
        url_target = {}

        with conn.cursor() as cur:
            rows = fetch_urls(cur, target_ids, since_dt)

        for target_id, url, source, _ts in rows:
            nu = normalize_url(url)
            if not nu:
                continue
            url_map[nu] = url
            url_sources.setdefault(nu, set()).add(source)
            url_target.setdefault(nu, int(target_id))

        # include latest http urls
        with conn.cursor() as cur:
            http_rows = fetch_latest_http(cur, target_ids)

        http_info_map = {}
        for target_id, status_code, title, content_type, final_url, headers_selected in http_rows:
            http_info_map[int(target_id)] = {
                "status_code": status_code,
                "title": title,
                "content_type": content_type,
                "final_url": final_url,
                "headers_selected": headers_selected if isinstance(headers_selected, dict) else (headers_selected or {}),
            }
            for u in [final_url]:
                if not u:
                    continue
                nu = normalize_url(u)
                if not nu:
                    continue
                url_map[nu] = u
                url_sources.setdefault(nu, set()).add("http")
                url_target.setdefault(nu, int(target_id))

        # params per url
        param_map = {}
        with conn.cursor() as cur:
            param_rows = fetch_params(cur, target_ids, since_dt)
        for url, param_name in param_rows:
            nu = normalize_url(url)
            if not nu:
                continue
            param_map.setdefault(nu, set()).add(param_name)

        findings_upserts = 0
        category_counts = {}

        for nu, original_url in list(url_map.items())[:BATCH_URLS]:
            target_id = url_target.get(nu)
            params = sorted(param_map.get(nu, []))
            sources = sorted(url_sources.get(nu, []))
            http_info = http_info_map.get(target_id, {}) if target_id else {}

            path = url_path(nu)
            findings = build_findings(nu, path, params, http_info, sources)
            if not findings:
                continue

            with conn.cursor() as cur:
                for category, rule_id, confidence, severity, evidence in findings:
                    cur.execute(
                        """
                        INSERT INTO surface_findings(
                          platform, program_external_id, target_id, url,
                          category, rule_id, confidence, severity, evidence, status,
                          first_seen_at, last_seen_at
                        )
                        VALUES ('hackerone', %s, %s, %s, %s, %s, %s, %s, %s, 'new', now(), now())
                        ON CONFLICT (platform, program_external_id, url, category, rule_id)
                        DO UPDATE SET
                          confidence = GREATEST(surface_findings.confidence, EXCLUDED.confidence),
                          severity = GREATEST(surface_findings.severity, EXCLUDED.severity),
                          evidence = COALESCE(surface_findings.evidence, '{}'::jsonb) || EXCLUDED.evidence,
                          last_seen_at = now();
                        """,
                        (prog_ext, target_id, nu, category, rule_id, int(confidence), int(severity), Json(evidence)),
                    )
                    findings_upserts += 1
                    category_counts[category] = category_counts.get(category, 0) + 1

        conn.commit()

        top = ", ".join([f"{k}={v}" for k, v in sorted(category_counts.items(), key=lambda kv: (-kv[1], kv[0]))])
        print(f"[{ts()}] [INFO] scanned_urls={len(url_map)} findings_upserts={findings_upserts} top_categories={top}")


if __name__ == "__main__":
    main()
