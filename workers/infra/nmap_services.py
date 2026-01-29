#!/usr/bin/env python3
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime

import psycopg
from dotenv import load_dotenv

load_dotenv(".env")

DB_DSN = os.getenv("DB_DSN")
if not DB_DSN:
    raise RuntimeError("Missing DB_DSN")

BATCH = int(os.getenv("NMAP_BATCH", "100"))
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "900"))
NMAP_ARGS = os.getenv("NMAP_ARGS", "-sV -Pn --version-light --open").split()

def fetch_targets_and_ports(conn, limit: int):
    with conn.cursor() as cur:
        cur.execute("""
          SELECT t.id, t.host, array_agg(p.port ORDER BY p.port) AS ports
          FROM targets t
          JOIN ports_latest p ON p.target_id = t.id
          LEFT JOIN nmap_services_latest n
            ON n.target_id = t.id AND n.port = p.port AND n.proto = p.proto
          WHERE t.platform='hackerone'
          GROUP BY t.id, t.host
          HAVING count(n.port) < count(p.port)
          ORDER BY t.id
          LIMIT %s;
        """, (limit,))
        return cur.fetchall()

def run_nmap(host: str, ports: list[int]) -> str:
    ports_str = ",".join(str(p) for p in ports)
    with tempfile.NamedTemporaryFile(prefix="nmap_", suffix=".xml", delete=False) as tmp:
        outpath = tmp.name
    cmd = ["nmap", "-oX", outpath, "-p", ports_str] + NMAP_ARGS + [host]
    subprocess.run(cmd, check=False, timeout=NMAP_TIMEOUT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return outpath

def parse_nmap_xml(xml_path: str):
    rows = []
    try:
        root = ET.parse(xml_path).getroot()
        for host_el in root.findall("host"):
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                proto = port_el.attrib.get("protocol", "tcp")
                portid = int(port_el.attrib.get("portid", "0"))
                state_el = port_el.find("state")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue
                svc = port_el.find("service")
                service_name = svc.attrib.get("name") if svc is not None else None
                product = svc.attrib.get("product") if svc is not None else None
                version = svc.attrib.get("version") if svc is not None else None
                extra = svc.attrib.get("extrainfo") if svc is not None else None
                cpes = []
                if svc is not None:
                    for cpe in svc.findall("cpe"):
                        if cpe.text:
                            cpes.append(cpe.text.strip())
                rows.append({
                    "port": portid,
                    "proto": proto,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "extra_info": extra,
                    "cpe": cpes or None,
                })
    except Exception:
        return []
    return rows

def upsert(conn, target_id: int, rows: list[dict]) -> int:
    if not rows:
        return 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute("""
              INSERT INTO nmap_services_latest
                (target_id, port, proto, service_name, product, version, extra_info, cpe, first_seen_at, last_seen_at)
              VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, now(), now())
              ON CONFLICT (target_id, proto, port)
              DO UPDATE SET
                service_name = EXCLUDED.service_name,
                product = EXCLUDED.product,
                version = EXCLUDED.version,
                extra_info = EXCLUDED.extra_info,
                cpe = EXCLUDED.cpe,
                last_seen_at = now();
            """, (target_id, r["port"], r["proto"], r["service_name"], r["product"], r["version"], r["extra_info"], r["cpe"]))
    return len(rows)

def main():
    started = datetime.now().isoformat()
    processed = 0
    rows_upserted = 0

    with psycopg.connect(DB_DSN) as conn:
        conn.autocommit = False
        batch = fetch_targets_and_ports(conn, BATCH)
        if not batch:
            print("[INFO] nmap_services: nothing to do")
            return
        for target_id, host, ports in batch:
            xml_path = run_nmap(host, ports)
            rows = parse_nmap_xml(xml_path)
            rows_upserted += upsert(conn, target_id, rows)
            processed += 1
        conn.commit()

    print(f"[DONE] nmap_services processed={processed} rows_upserted={rows_upserted} started={started}")

if __name__ == "__main__":
    main()
