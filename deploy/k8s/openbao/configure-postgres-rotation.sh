#!/usr/bin/env bash
set -euo pipefail

export BAO_ADDR="${BAO_ADDR:-https://openbao-0.openbao-internal.openbao.svc.cluster.local:8200}"
export BAO_CACERT="${BAO_CACERT:-/openbao/tls/ca.crt}"
ROTATION_PERIOD="${ROTATION_PERIOD:-720h}"

bao token lookup >/dev/null

if ! bao secrets list -format=json | grep -q '"database/"'; then
  bao secrets enable -path=database database
fi

admin_password="$(bao kv get -field=postgres-admin-password secret/opendirectory/postgres-admin)"
trap 'unset admin_password' EXIT
printf '%s' "$admin_password" | bao write database/config/opendirectory \
  plugin_name=postgresql-database-plugin \
  allowed_roles=opendirectory \
  connection_url='postgresql://{{username}}:{{password}}@opendirectory-postgres.opendirectory.svc.cluster.local:5432/postgres?sslmode=disable' \
  username=bao_rotator \
  password=- >/dev/null

rotation_statement="ALTER ROLE \"{{name}}\" WITH PASSWORD '{{password}}';"
bao write database/static-roles/opendirectory \
  db_name=opendirectory \
  username=opendirectory \
  rotation_period="$ROTATION_PERIOD" \
  rotation_statements="$rotation_statement" >/dev/null

printf 'OpenBao PostgreSQL static role configured; ESO can now sync the rotated app password.\n'
