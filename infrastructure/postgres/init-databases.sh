#!/bin/bash
set -e

# Single source of truth for DB-per-service provisioning: every physical
# database referenced by a deployed service's DB_NAME/DATABASE_URL in
# docker-compose.yml / docker-compose.lite.yml must be listed here.
# (docker-compose*.yml no longer sets POSTGRES_MULTIPLE_DATABASES — this
# script doesn't read that variable, so keeping it around was misleading.)
for db in identity auth policy audit integration printers network api devices api_gateway app_store oauth certs mdm samba least_privilege; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    SELECT 'CREATE DATABASE $db' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$db')\gexec
EOSQL
done
