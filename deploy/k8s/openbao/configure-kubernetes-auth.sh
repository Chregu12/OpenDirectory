#!/usr/bin/env bash
set -euo pipefail

export BAO_ADDR="${BAO_ADDR:-https://openbao-0.openbao-internal.openbao.svc.cluster.local:8200}"
export BAO_CACERT="${BAO_CACERT:-/openbao/tls/ca.crt}"
KUBERNETES_HOST="${KUBERNETES_HOST:-https://kubernetes.default.svc}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

bao token lookup >/dev/null

if ! bao secrets list -format=json | grep -q '"secret/"'; then
  bao secrets enable -version=2 kv
fi

if ! bao auth list -format=json | grep -q '"kubernetes/"'; then
  bao auth enable kubernetes
fi

# OpenBao runs in-cluster and uses its short-lived pod token for TokenReview.
bao write auth/kubernetes/config \
  kubernetes_host="${KUBERNETES_HOST}" \
  disable_iss_validation=true

bao policy write opendirectory-eso "${SCRIPT_DIR}/opendirectory-eso.hcl"
bao policy write opendirectory-postgres-admin "${SCRIPT_DIR}/opendirectory-postgres-admin.hcl"
bao policy write opendirectory-operator "${SCRIPT_DIR}/opendirectory-operator.hcl"
bao policy write opendirectory-harbor-rotation "${SCRIPT_DIR}/harbor-rotation.hcl"
bao policy write opendirectory-harbor-api-read "${SCRIPT_DIR}/harbor-api-read.hcl"
bao policy write bitwarden-sync-read "${SCRIPT_DIR}/bitwarden-sync-read.hcl"
bao policy write bitwarden-token-renewer "${SCRIPT_DIR}/bitwarden-token-renewer.hcl"

bao write auth/token/roles/bitwarden-sync \
  allowed_policies=bitwarden-sync-read \
  token_policies=bitwarden-sync-read \
  token_explicit_max_ttl=720h \
  token_no_default_policy=true \
  token_type=service \
  orphan=true \
  renewable=false
bao write auth/kubernetes/role/opendirectory-eso \
  bound_service_account_names=opendirectory-secret-reader \
  bound_service_account_namespaces=opendirectory \
  audience=openbao \
  token_policies=opendirectory-eso \
  token_ttl=15m \
  token_max_ttl=1h

bao write auth/kubernetes/role/opendirectory-postgres-admin \
  bound_service_account_names=opendirectory-postgres-admin-reader \
  bound_service_account_namespaces=opendirectory \
  audience=openbao \
  token_policies=opendirectory-postgres-admin \
  token_ttl=15m \
  token_max_ttl=1h

bao write auth/kubernetes/role/opendirectory-harbor-rotator \
  bound_service_account_names=opendirectory-harbor-rotator \
  bound_service_account_namespaces=opendirectory \
  audience=openbao \
  token_policies=opendirectory-harbor-rotation \
  token_ttl=15m \
  token_max_ttl=1h

bao write auth/kubernetes/role/opendirectory-harbor-api-reader \
  bound_service_account_names=opendirectory-harbor-api-reader \
  bound_service_account_namespaces=opendirectory \
  audience=openbao \
  token_policies=opendirectory-harbor-api-read \
  token_ttl=15m \
  token_max_ttl=1h

bao write auth/kubernetes/role/openbao-bitwarden-token-renewer \
  bound_service_account_names=openbao-bitwarden-token-renewer \
  bound_service_account_namespaces=openbao \
  audience=openbao \
  token_policies=bitwarden-token-renewer \
  token_no_default_policy=true \
  token_ttl=5m \
  token_max_ttl=15m
