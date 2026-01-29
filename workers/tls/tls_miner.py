#!/usr/bin/env python3
"""
Worker: TLS certificate SAN mining (latest-only)

Input:
- targets (scoped by PROGRAM_HANDLE if set)

Output:
- tls_certs_latest (PK: target_id, port)

Notes:
- Passive TLS handshake only (openssl)
- No HTTP
- Idempotent latest-only
"""

import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Optional, Tuple, List

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

PROGRAM_HANDLE = (os.getenv("PROGRAM_HANDLE") or "").strip()  # injected by workflow.py

TLS_PORTS = [443, 8443]
TIMEOUT_SEC = int(os.getenv("TLS_TIMEOUT_SEC", "10"))
TLS_BATCH = int(os.getenv("TLS_BATCH", "0"))

# Extract SANs from x509 -text output
SAN_BLOCK_RE = re.compile(r"X509v3 Subject Alternative Name:\s*\n\s*(.*)", re.IGNORECASE)
DNS_RE = re.compile(r"DNS:([^,\s]+)", re.IGNORECASE)

# For parsing openssl dates like: "Jan  5 12:34:56 2026 GMT"
OPENSSL_DT_FMT = "%b %d %H:%M:%S %Y %Z"


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def resolve_program_external_id(conn, handle: str) -> Optional[str]:
    if not handle:
        return None
    with conn.cursor() as cur:
        cur.execute(
            "SELECT external_id FROM programs WHERE platform='hackerone' AND handle=%s LIMIT 1",
            (handle,),
        )
        r = cur.fetchone()
        return str(r[0]) if r else None


def fetch_targets(conn, program_external_id: Optional[str], limit: int = 0) -> List[Tuple[int, str]]:
    with conn.cursor() as cur:
        if program_external_id:
            if limit and limit > 0:
                cur.execute(
                    """
                    SELECT id, host
                    FROM targets
                    WHERE platform='hackerone' AND program_external_id=%s
                    ORDER BY last_seen_at DESC
                    LIMIT %s
                    """,
                    (program_external_id, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT id, host
                    FROM targets
                    WHERE platform='hackerone' AND program_external_id=%s
                    ORDER BY last_seen_at DESC
                    """,
                    (program_external_id,),
                )
        else:
            if limit and limit > 0:
                cur.execute(
                    """
                    SELECT id, host
                    FROM targets
                    ORDER BY last_seen_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
            else:
                cur.execute(
                    """
                    SELECT id, host
                    FROM targets
                    ORDER BY last_seen_at DESC
                    """
                )
        return cur.fetchall()


def run_openssl_s_client(host: str, port: int) -> Optional[str]:
    # -servername => SNI
    # -showcerts  => include cert chain
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-showcerts",
        "-verify_return_error",
    ]
    try:
        p = subprocess.run(
            cmd,
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC,
        )
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        # We still may get useful cert even if verify fails; don't hard-reject by returncode.
        return out if out.strip() else None
    except Exception:
        return None


def extract_leaf_pem(s_client_out: str) -> Optional[str]:
    # Leaf cert is typically the first PEM block.
    m = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        s_client_out,
        re.DOTALL,
    )
    if not m:
        return None
    return "-----BEGIN CERTIFICATE-----" + m.group(1) + "-----END CERTIFICATE-----"


def run_openssl_x509_text(pem: str) -> Optional[str]:
    cmd = ["openssl", "x509", "-noout", "-text", "-fingerprint", "-sha256"]
    try:
        p = subprocess.run(
            cmd,
            input=pem,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC,
        )
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        return out if out.strip() else None
    except Exception:
        return None


def parse_x509_text(x509_out: str) -> Tuple[Optional[str], Optional[str], Optional[datetime], Optional[datetime], Optional[str], List[str]]:
    issuer = None
    subject_cn = None
    not_before = None
    not_after = None
    fp_sha256 = None
    sans: List[str] = []

    for line in x509_out.splitlines():
        line = line.strip()

        # Issuer:
        if line.startswith("Issuer:"):
            issuer = line.replace("Issuer:", "", 1).strip()

        # Subject: CN = ...
        if line.startswith("Subject:"):
            # Try to extract CN=
            subj = line.replace("Subject:", "", 1).strip()
            mcn = re.search(r"CN\s*=\s*([^,\/]+)", subj)
            if mcn:
                subject_cn = mcn.group(1).strip()

        # Validity
        if line.startswith("Not Before:"):
            s = line.replace("Not Before:", "", 1).strip()
            try:
                not_before = datetime.strptime(s, OPENSSL_DT_FMT)
            except Exception:
                not_before = None

        if line.startswith("Not After :"):
            s = line.replace("Not After :", "", 1).strip()
            try:
                not_after = datetime.strptime(s, OPENSSL_DT_FMT)
            except Exception:
                not_after = None

        # Fingerprint
        if line.startswith("SHA256 Fingerprint="):
            fp_sha256 = line.replace("SHA256 Fingerprint=", "", 1).strip().replace(":", "").lower()

    # SAN extraction (block-based)
    m = SAN_BLOCK_RE.search(x509_out)
    if m:
        san_line = m.group(1).strip()
        sans = DNS_RE.findall(san_line) or []
    else:
        # fallback: scan all lines
        sans = DNS_RE.findall(x509_out) or []

    # normalize/dedup
    sans = sorted({d.lower().strip().rstrip(".") for d in sans if d and d.strip()})

    return issuer, subject_cn, not_before, not_after, fp_sha256, sans


def upsert_tls(cur, target_id: int, port: int, issuer: Optional[str], subject_cn: Optional[str],
              nb: Optional[datetime], na: Optional[datetime], fp_sha256: Optional[str], sans: List[str]):
    cur.execute(
        """
        INSERT INTO tls_certs_latest(
          target_id, port, subject_cn, issuer, not_before, not_after, fingerprint_sha256, san_domains, first_seen_at, last_seen_at
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
        ON CONFLICT (target_id, port) DO UPDATE SET
          subject_cn=EXCLUDED.subject_cn,
          issuer=EXCLUDED.issuer,
          not_before=EXCLUDED.not_before,
          not_after=EXCLUDED.not_after,
          fingerprint_sha256=EXCLUDED.fingerprint_sha256,
          san_domains=EXCLUDED.san_domains,
          last_seen_at=now()
        """,
        (target_id, port, subject_cn, issuer, nb, na, fp_sha256, sans),
    )


def main():
    with psycopg.connect(DB_DSN) as conn:
        conn.autocommit = False

        prog_ext = resolve_program_external_id(conn, PROGRAM_HANDLE) if PROGRAM_HANDLE else None
        if PROGRAM_HANDLE and not prog_ext:
            log(f"[WARN] PROGRAM_HANDLE={PROGRAM_HANDLE} not found in programs; scanning all targets")

        targets = fetch_targets(conn, prog_ext, TLS_BATCH)
        log(f"[INFO] tls_miner targets={len(targets)} program={PROGRAM_HANDLE or '-'} batch={TLS_BATCH or 'all'}")

        done = 0
        with conn.cursor() as cur:
            for tid, host in targets:
                for port in TLS_PORTS:
                    s_out = run_openssl_s_client(host, port)
                    if not s_out:
                        continue

                    pem = extract_leaf_pem(s_out)
                    if not pem:
                        continue

                    x509_out = run_openssl_x509_text(pem)
                    if not x509_out:
                        continue

                    issuer, subject_cn, nb, na, fp_sha256, sans = parse_x509_text(x509_out)
                    if not sans:
                        continue

                    upsert_tls(cur, tid, port, issuer, subject_cn, nb, na, fp_sha256, sans)
                    done += 1

                    if done % 50 == 0:
                        conn.commit()
                        log(f"[PROGRESS] tls enriched={done}")

            conn.commit()

    log(f"[DONE] TLS mining completed ({done})")


if __name__ == "__main__":
    main()
