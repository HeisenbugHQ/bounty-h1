#!/usr/bin/env python3
"""
workers/dns/learn_from_san.py

Learn subdomain labels from TLS SAN domains -> subdomains_custom.txt
(no DB changes, only file learning)

Env:
  DB_DSN=...
  RUN_SAN_LEARN=true/false
  SAN_LEARN_BATCH=2000
  SUBDOMAINS_CUSTOM_FILE=wordlists/custom/subdomains_custom.txt
  ANEW_BIN=anew
"""

import os
import re
from datetime import datetime

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN in .env")

RUN = os.getenv("RUN_SAN_LEARN", "true").strip().lower() == "true"
BATCH = int(os.getenv("SAN_LEARN_BATCH", "2000"))
OUTFILE = os.getenv("SUBDOMAINS_CUSTOM_FILE", "wordlists/custom/subdomains_custom.txt").strip()
ANEW_BIN = os.getenv("ANEW_BIN", "anew").strip()

LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,38}[a-z0-9]$", re.IGNORECASE)


def ts():
    return datetime.now().strftime("%H:%M:%S")


def which(binname: str) -> str | None:
    import shutil
    return shutil.which(binname)


def ensure_file(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        open(path, "a", encoding="utf-8").close()


def append_with_anew(lines: list[str], path: str) -> int:
    if not lines:
        return 0
    ensure_file(path)

    # uniq
    seen = set()
    uniq = []
    for x in lines:
        x = (x or "").strip().lower()
        if x and x not in seen:
            seen.add(x)
            uniq.append(x)

    if which(ANEW_BIN):
        import subprocess
        p = subprocess.run([ANEW_BIN, path], input="\n".join(uniq) + "\n", text=True, capture_output=True)
        new_lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
        return len(new_lines)

    existing = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            existing.add(ln.strip().lower())
    new = [x for x in uniq if x not in existing]
    if new:
        with open(path, "a", encoding="utf-8") as f:
            for x in new:
                f.write(x + "\n")
    return len(new)


def main():
    if not RUN:
        print(f"[{ts()}] [SKIP] RUN_SAN_LEARN=false")
        return

    ensure_file(OUTFILE)

    labels = []
    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT unnest(san_domains) AS d
                FROM tls_certs_latest
                WHERE san_domains IS NOT NULL
                LIMIT %s
                """,
                (BATCH,),
            )
            for (d,) in cur.fetchall():
                d = (d or "").strip().lower().rstrip(".")
                if not d or "." not in d:
                    continue
                left = d.split(".", 1)[0]
                if LABEL_RE.match(left):
                    labels.append(left)

    learned = append_with_anew(labels, OUTFILE)
    print(f"[{ts()}] [DONE] san_learn scanned={len(labels)} learned_new={learned} out={OUTFILE}")


if __name__ == "__main__":
    main()
