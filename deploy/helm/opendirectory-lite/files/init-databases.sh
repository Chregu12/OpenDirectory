#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 -v app_password="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname postgres <<'EOSQL'
  SELECT format('CREATE ROLE opendirectory LOGIN PASSWORD %L', :'app_password')
  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'opendirectory')\gexec
EOSQL

for db in identity auth policy audit integration printers network api devices api_gateway app_store oauth certs mdm samba least_privilege monitoring license_fulfillment license_capacity; do
  psql -v ON_ERROR_STOP=1 -v db="$db" --username "$POSTGRES_USER" --dbname postgres <<'EOSQL'
    SELECT format('CREATE DATABASE %I OWNER opendirectory', :'db')
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'db')\gexec
EOSQL
done
