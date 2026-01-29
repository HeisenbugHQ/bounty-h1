# bounty-h1

## Config YAML (optional)

The workflow can load optional YAML files and export values as standardized env vars for workers.

Load order and precedence:
1) `config/global.yaml` (if present)
2) `config/programs/<handle>.yaml` (if present, overrides global)

Environment variables already set in your shell take precedence over YAML values.

### Structure

You can define env vars directly at the top level or under an `env` block.

```yaml
env:
  SUBFINDER_RECURSIVE: false
  AMASS_PASSIVE: true
  HTTP_HEADERS_MODE: capture
  RESOLVERS_FILE: wordlists/resolvers_valid.txt
  TRUSTED_RESOLVERS_FILE: wordlists/resolvers_trusted.txt
  WILDCARD_TESTS: true

job_budget:
  http_reinject: 2500
  port_reinject: 1500
```

`job_budget` expands to `JOB_BUDGET_*` env vars (e.g., `JOB_BUDGET_HTTP_REINJECT=2500`).

### Examples

BitMEX (program handle `bitmex`), override subfinder and budgets:

```yaml
env:
  SUBFINDER_RECURSIVE: true
  HTTP_HEADERS_MODE: capture

job_budget:
  http_reinject: 5000
  crawl_light: 500
```

Shopify (program handle `shopify`), keep subfinder non-recursive and tune budgets:

```yaml
env:
  SUBFINDER_RECURSIVE: false
  AMASS_PASSIVE: true
  HTTP_HEADERS_MODE: capture
  WILDCARD_TESTS: true

job_budget:
  http_reinject: 3000
  port_reinject: 2000
  wayback_urls: 400
```

Example files are provided in:
- `config/global.yaml.example`
- `config/programs/bitmex.yaml.example`
- `config/programs/shopify.yaml.example`

## Metabase

Metabase accepts plain SQL only (no `psql` wrapper). See `docs/metabase_queries.md` for ready-to-use queries.
