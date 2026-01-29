#!/usr/bin/env python3
"""
Generate subfinder provider-config.yaml from .env / environment.
Does not print secrets in logs.
"""

import os
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv(".env")

PROVIDERS = [
    ("securitytrails", "SUBFINDER_SECURITYTRAILS_KEY", None),
    ("shodan", "SUBFINDER_SHODAN_KEY", None),
    ("censys", "SUBFINDER_CENSYS_UID", "SUBFINDER_CENSYS_SECRET"),
    ("github", "SUBFINDER_GITHUB_TOKEN", None),
    ("virustotal", "SUBFINDER_VIRUSTOTAL_KEY", None),
    ("passive", "SUBFINDER_PASSIVE_KEY", None),
]


def build_provider_list():
    providers = []
    for name, key_env, secret_env in PROVIDERS:
        key = os.getenv(key_env, "").strip()
        secret = os.getenv(secret_env, "").strip() if secret_env else ""
        if not key:
            continue
        entry = {"name": name, "apikey": key}
        if secret:
            if name == "censys":
                entry = {"name": name, "uid": key, "secret": secret}
            else:
                entry["secret"] = secret
        providers.append(entry)
    return providers


def target_path() -> Path:
    override = os.getenv("SUBFINDER_PROVIDER_CONFIG", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "subfinder" / "provider-config.yaml"


def main():
    force = "--force" in sys.argv
    providers = build_provider_list()
    out_path = target_path()
    if not providers:
        print("[INFO] subfinder config: absent")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)

    data = {"providers": providers}
    new_content = yaml.safe_dump(data, sort_keys=False)

    if out_path.exists():
        try:
            existing = out_path.read_text(encoding="utf-8")
        except Exception:
            existing = ""
        if existing == new_content:
            print(f"[INFO] subfinder provider-config unchanged: {out_path}")
            return 0
        if not force:
            print(f"[INFO] subfinder provider-config updating: {out_path}")

    out_path.write_text(new_content, encoding="utf-8")

    if providers:
        names = ", ".join(p["name"] for p in providers)
        print(f"[OK] subfinder provider-config generated: {out_path} (providers: {names})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
