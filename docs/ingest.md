# Ingest & Monitoring

This project ingests assets into the `assets` table and fans them into two pipelines:
- **DNS pipeline**: domain/wildcard/url → `v_dns_seeds` → subdomain discovery, HTTP, etc.
- **IP pipeline**: ip/cidr/asn → `v_ip_seeds` → `ip_discovery_queue` → `ip_assets_latest` (+ optional RDNS → `targets`)

## Insert assets (ip/cidr/asn/url/wildcard/domain)

Recommended: use the helper script (idempotent upsert).

```bash
# example: add a CIDR
python scripts/add_asset.py --program bitmex --type cidr --value "203.0.113.0/24"

# example: add a single IP
python scripts/add_asset.py --program bitmex --type ip --value "203.0.113.10"

# example: add an ASN (accepts AS123 or 123)
python scripts/add_asset.py --program bitmex --type asn --value "AS13335"

# example: add a root domain
python scripts/add_asset.py --program bitmex --type domain --value "bitmex.com"

# example: add a wildcard
python scripts/add_asset.py --program bitmex --type wildcard --value "*.bitmex.com"

# example: add a URL
python scripts/add_asset.py --program bitmex --type url --value "https://api.bitmex.com"
```

Notes:
- `--program` resolves `program_external_id` via `programs` (platform `hackerone`).
- All inserts are upserts; repeated runs are safe.

## What goes to DNS vs IP pipeline

**DNS pipeline inputs** (from assets):
- `domain`, `wildcard`, `url` → normalized into `v_dns_seeds.host`

**IP pipeline inputs** (from assets):
- `ip`, `cidr`, `asn` → `v_ip_seeds`
- `worker_ip_enqueue.py` takes `v_ip_seeds` and enqueues into `ip_discovery_queue`
- `worker_ip_discovery.py` processes queue items:
  - `ip` → upsert `ip_assets_latest` (`source='seed_ip'`), optional RDNS → `targets`
  - `cidr` → expand (guarded) → upsert `ip_assets_latest` (`source='cidr'`), optional RDNS → `targets`
  - `asn` → fetch prefixes → enqueue `cidr` items (no immediate expansion)

## Continuous monitoring (simple cron)

The workflow is designed to be run repeatedly. A minimal cron job can re-run it on a schedule.

Example (every 30 minutes):

```cron
*/30 * * * * cd /home/heisenbug/bounty-h1 && /usr/bin/env bash -lc 'source .venv/bin/activate && python workflow.py bitmex --mode monitor' >> logs/cron_workflow_bitmex.log 2>&1
```

Notes:
- `--mode monitor` makes the workflow more conservative and uses env toggles (see `workflow.py`).
- Use `RUN_IP=true` if you want IP steps always on in monitoring mode.

## Example: insert AS13335 and run workflow for bitmex

```bash
# enqueue ASN into assets
python scripts/add_asset.py --program bitmex --type asn --value "AS13335"

# run one workflow pass (discovery mode)
python workflow.py bitmex

# or run as monitor (safe for cron)
python workflow.py bitmex --mode monitor
```
