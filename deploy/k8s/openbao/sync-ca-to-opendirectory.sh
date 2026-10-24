#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:-opendirectory}"
CA_FILE="$(mktemp)"
trap 'rm -f "${CA_FILE}"' EXIT

kubectl get secret openbao-server-tls -n openbao -o jsonpath='{.data.ca\.crt}' | base64 --decode > "${CA_FILE}"
kubectl create configmap openbao-ca \
  --namespace "${NAMESPACE}" \
  --from-file=ca.crt="${CA_FILE}" \
  --dry-run=client -o yaml | kubectl apply -f -
