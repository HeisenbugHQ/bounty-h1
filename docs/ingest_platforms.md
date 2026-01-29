# Ingest platforms (Bugcrowd, Intigriti, YesWeHack)

This repo provides basic sync connectors that normalize **programs**, **scopes**, and **assets** across platforms.
Each sync writes to:
- `programs` (platform-specific)
- `scopes` (platform-specific)
- `assets` (platform-specific, normalized asset types)

## Prerequisites

- `DB_DSN` in `.env`
- API access for each platform (URL + auth)

The scripts are intentionally generic: you must provide the platform API URLs (or a local JSON export).

## Bugcrowd

Env:
- `BUGCROWD_PROGRAMS_URL` (required unless `BUGCROWD_JSON_FILE`)
- `BUGCROWD_SCOPES_URL_TEMPLATE` (optional, format with `{program_id}`)
- `BUGCROWD_TOKEN` (optional)
- `BUGCROWD_AUTH_HEADER` (optional, e.g. `Authorization: Bearer <token>`)
- `BUGCROWD_JSON_FILE` (optional local JSON file)

Run:
```bash
python scripts/sync_bugcrowd.py
```

## Intigriti

Env:
- `INTIGRITI_PROGRAMS_URL` (required unless `INTIGRITI_JSON_FILE`)
- `INTIGRITI_SCOPES_URL_TEMPLATE` (optional, format with `{program_id}`)
- `INTIGRITI_TOKEN` (optional)
- `INTIGRITI_AUTH_HEADER` (optional)
- `INTIGRITI_JSON_FILE` (optional local JSON file)

Run:
```bash
python scripts/sync_intigriti.py
```

## YesWeHack

Env:
- `YESWEHACK_PROGRAMS_URL` (required unless `YESWEHACK_JSON_FILE`)
- `YESWEHACK_SCOPES_URL_TEMPLATE` (optional, format with `{program_id}`)
- `YESWEHACK_TOKEN` (optional)
- `YESWEHACK_AUTH_HEADER` (optional)
- `YESWEHACK_JSON_FILE` (optional local JSON file)

Run:
```bash
python scripts/sync_yeswehack.py
```

## Asset type normalization

Scopes/assets are normalized to one of:
`domain`, `wildcard`, `url`, `ip`, `cidr`, `asn`, `other`.

The normalizer uses both `asset_type` and the identifier pattern (e.g., `*.example.com` → `wildcard`, `https://` → `url`, `1.2.3.4/24` → `cidr`).
