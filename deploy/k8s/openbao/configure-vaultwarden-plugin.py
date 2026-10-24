#!/usr/bin/env python3
"""Write Vaultwarden connection settings to stdin for `bao write ... -`."""

import getpass
import json
import os
import sys


email = os.environ.get("VAULTWARDEN_EMAIL") or input("Existing Vaultwarden account email: ").strip()
if not email:
    sys.exit("Vaultwarden account email is required.")

password = getpass.getpass("Vaultwarden master password (hidden; stored encrypted in OpenBao): ")
if not password:
    sys.exit("Vaultwarden master password is required.")

organization_id = input("Vaultwarden organization ID (leave empty for this account's personal vault): ").strip()

payload = {
    "url": "https://bitwarden.heusser.local",
    "email": email,
    "password": password,
    "bao_addr": "https://openbao-active.openbao.svc.cluster.local:8200",
    "bao_token": os.environ["BITWARDEN_SYNC_TOKEN"],
    "sync_interval": "10m",
}
if organization_id:
    payload["organization_id"] = organization_id

sys.stdout.write(json.dumps(payload, separators=(",", ":")))
