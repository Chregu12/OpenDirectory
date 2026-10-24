#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

kubectl create configmap openbao-bitwarden-token-renewer -n openbao \
  --from-file=bitwarden-token-renewer.py="${SCRIPT_DIR}/bitwarden-token-renewer.py" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${SCRIPT_DIR}/bitwarden-token-renewer.yaml"

echo "Installed the scheduled least-privilege Vaultwarden sync-token rotation."
