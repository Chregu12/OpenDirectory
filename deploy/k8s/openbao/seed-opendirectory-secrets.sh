#!/usr/bin/env bash
set -euo pipefail

: "${BAO_ADDR:?Set BAO_ADDR to the initialized OpenBao API}"
: "${BAO_CACERT:?Set BAO_CACERT to the OpenBao CA certificate}"
: "${BAO_TLS_SERVER_NAME:?Set BAO_TLS_SERVER_NAME to the certificate DNS name}"
export BAO_ADDR BAO_CACERT BAO_TLS_SERVER_NAME
bao token lookup >/dev/null

for path in secret/opendirectory/runtime secret/opendirectory/files secret/opendirectory/postgres-admin; do
  if bao kv get -format=json "$path" >/dev/null 2>&1; then
    printf 'Refusing to overwrite existing OpenBao data at %s.\n' "$path" >&2
    exit 1
  fi
done

python3 - <<'PY' | bao kv put -cas=0 secret/opendirectory/runtime - >/dev/null
import json, secrets
app = secrets.token_hex(32)
redis = secrets.token_hex(32)
host = "opendirectory-postgres.opendirectory.svc.cluster.local:5432"
databases = ("identity", "auth", "policy", "oauth", "api", "license_fulfillment", "license_capacity")
data = {
    "postgres-app-initial-password": app,
    "redis-password": redis,
    "redis-url": f"redis://:{redis}@opendirectory-redis.opendirectory.svc.cluster.local:6379",
    "lldap-jwt-secret": secrets.token_hex(32),
    "lldap-admin-password": secrets.token_hex(32),
    "jwt-secret": secrets.token_hex(32),
}
data.update({f"{db.replace('_', '-')}-database-url": f"postgresql://opendirectory:{app}@{host}/{db}" for db in databases})
json.dump(data, __import__("sys").stdout)
PY

python3 - <<'PY' | bao kv put -cas=0 secret/opendirectory/postgres-admin - >/dev/null
import json, secrets, sys
json.dump({"postgres-admin-password": secrets.token_hex(32)}, sys.stdout)
PY

python3 - <<'PY' | bao kv put -cas=0 secret/opendirectory/files - >/dev/null
import json, secrets, string, subprocess, sys
pem = subprocess.run(
    ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
    check=True, capture_output=True, text=True,
).stdout
client_secret = secrets.token_hex(32)
cookie_key = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
json.dump({
    "oauth-signing.pem": pem,
    "mfa-encryption.key": secrets.token_hex(32),
    "oauth-verification.jwks.json": '{"keys":[]}',
    "oauth-web-client.secret": client_secret,
    "browser-client.secret": client_secret,
    "browser-cookie.key": cookie_key,
}, sys.stdout)
PY

printf 'OpenDirectory credentials and signing keys are stored in OpenBao at the expected paths.\n'
