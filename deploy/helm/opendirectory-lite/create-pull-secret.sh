#!/usr/bin/env bash
set -euo pipefail

registry="${HARBOR_REGISTRY:-harbor.heusser.local}"
namespace="${K8S_NAMESPACE:-opendirectory}"
secret_name="${K8S_IMAGE_PULL_SECRET:-harbor-opendirectory}"
: "${HARBOR_USERNAME:?Set HARBOR_USERNAME through your Secret Manager}"
: "${HARBOR_PASSWORD:?Set HARBOR_PASSWORD through your Secret Manager}"

kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
python3 - "$registry" "$secret_name" "$namespace" <<'PY' | kubectl apply -f -
import base64, json, os, sys
registry, name, namespace = sys.argv[1:]
username, password = os.environ['HARBOR_USERNAME'], os.environ['HARBOR_PASSWORD']
auth = base64.b64encode(f'{username}:{password}'.encode()).decode()
config = json.dumps({'auths': {registry: {'username': username, 'password': password, 'auth': auth}}}, separators=(',', ':')).encode()
secret = {
  'apiVersion': 'v1',
  'kind': 'Secret',
  'metadata': {'name': name, 'namespace': namespace},
  'type': 'kubernetes.io/dockerconfigjson',
  'data': {'.dockerconfigjson': base64.b64encode(config).decode()},
}
print(json.dumps(secret))
PY
