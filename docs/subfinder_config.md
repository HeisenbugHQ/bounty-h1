# Subfinder provider config

This repo supports Subfinder API providers via a generated config file.
The worker reads `SUBFINDER_PROVIDER_CONFIG` if set, otherwise uses the default Subfinder path.

## .env variables

Set any of these in `.env` (only the ones you need):

- `SUBFINDER_SECURITYTRAILS_KEY`
- `SUBFINDER_SHODAN_KEY`
- `SUBFINDER_CENSYS_UID`
- `SUBFINDER_CENSYS_SECRET`
- `SUBFINDER_GITHUB_TOKEN`
- `SUBFINDER_VIRUSTOTAL_KEY`
- `SUBFINDER_PASSIVE_KEY`

Optional:
- `SUBFINDER_PROVIDER_CONFIG` (override path for provider-config.yaml)
- `SUBFINDER_RECURSIVE` (true/false, default false)
- `SUBFINDER_ALL` (true/false, default true)

## Where the config file lives

Default (Linux):
`~/.config/subfinder/provider-config.yaml`

Override:
set `SUBFINDER_PROVIDER_CONFIG` to a custom path.

## Generate the config

```bash
python scripts/setup_subfinder_config.py
```

This reads `.env` and writes the provider config without printing secrets.
If no keys are set, it prints `subfinder config: absent` and exits without writing.
Use `--force` to overwrite an existing file.

## Test subfinder

```bash
subfinder -d example.com -silent -pc ~/.config/subfinder/provider-config.yaml
```

If you set `SUBFINDER_RECURSIVE=true`, the worker will add `-recursive` automatically.

Quick manual check (no secrets shown):

```bash
subfinder -d example.com -silent -pc ~/.config/subfinder/provider-config.yaml -v | head -n 5
```

## Security notes

- Never commit `provider-config.yaml` with real keys.
- Keep `.env` local and out of version control.
- The generator never prints secrets to stdout.
