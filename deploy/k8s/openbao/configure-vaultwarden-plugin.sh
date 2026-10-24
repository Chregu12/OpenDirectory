#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

for command in bao python3; do
  command -v "${command}" >/dev/null || {
    echo "Required command not found: ${command}" >&2
    exit 1
  }
done

: "${BAO_ADDR:?Set BAO_ADDR to the OpenBao API URL}"

if [[ "$(bao status -format=json | python3 -c 'import json,sys; print("true" if json.load(sys.stdin)["sealed"] else "false")')" != false ]]; then
  echo "OpenBao must be unsealed before configuring Vaultwarden." >&2
  exit 1
fi

if ! bao secrets list -format=json | python3 -c 'import json,sys; sys.exit(0 if "bitwarden/" in json.load(sys.stdin) else 1)'; then
  bao secrets enable -path=bitwarden bitwarden
fi

export BITWARDEN_SYNC_TOKEN="$(bao token create \
  -role=bitwarden-sync \
  -field=token)"

python3 "${SCRIPT_DIR}/configure-vaultwarden-plugin.py" \
  | bao write bitwarden/config -

unset BITWARDEN_SYNC_TOKEN
echo "Vaultwarden connection stored in OpenBao. Check it with: bao read bitwarden/status"
