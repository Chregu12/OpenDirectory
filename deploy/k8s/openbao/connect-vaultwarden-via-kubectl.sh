#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="openbao"
POD="openbao-0"
REMOTE_ADDR="https://openbao-active.openbao.svc.cluster.local:8200"
REMOTE_CA="/openbao/tls/ca.crt"

for command in kubectl python3; do
  command -v "${command}" >/dev/null || {
    echo "Required command not found: ${command}" >&2
    exit 1
  }
done

kubectl get pod "${POD}" -n "${NAMESPACE}" -o name >/dev/null
if ! kubectl exec -n "${NAMESPACE}" "${POD}" -- \
  env BAO_ADDR="${REMOTE_ADDR}" BAO_CACERT="${REMOTE_CA}" \
    bao status -format=json \
  | python3 -c 'import json,sys; sys.exit(0 if not json.load(sys.stdin)["sealed"] else 1)'; then
  echo "OpenBao is sealed or unreachable. Unseal it before continuing." >&2
  exit 1
fi
REMOTE_HOME="$(kubectl exec -n "${NAMESPACE}" "${POD}" -- mktemp -d /tmp/bao-vaultwarden.XXXXXX)"

cleanup() {
  if [[ -n "${REMOTE_HOME:-}" ]]; then
    kubectl exec -n "${NAMESPACE}" "${POD}" -- rm -rf -- "${REMOTE_HOME}" >/dev/null 2>&1 || true
    REMOTE_HOME=""
  fi
  unset BITWARDEN_SYNC_TOKEN
}
trap cleanup EXIT

remote_bao() {
  local with_stdin="$1"
  shift
  local -a exec_flags=()
  if [[ "${with_stdin}" == true ]]; then
    exec_flags=(-i)
  fi
  kubectl exec "${exec_flags[@]}" -n "${NAMESPACE}" "${POD}" -- \
    env HOME="${REMOTE_HOME}" \
      BAO_ADDR="${REMOTE_ADDR}" \
      BAO_CACERT="${REMOTE_CA}" \
      bao "$@"
}

bao() {
  local argument last_argument=""
  if [[ "${1:-}" == policy && "${2:-}" == write && -f "${4:-}" ]]; then
    cat -- "$4" | remote_bao true policy write "$3" -
    return
  fi

  for argument in "$@"; do
    last_argument="${argument}"
  done
  if [[ "${last_argument}" == - ]]; then
    remote_bao true "$@"
  else
    remote_bao false "$@"
  fi
}

export REMOTE_HOME REMOTE_ADDR REMOTE_CA NAMESPACE POD
export -f remote_bao bao

echo "OpenBao is reachable. Enter its initial root token; input stays hidden."
read -r -s -p "OpenBao initial root token: " INITIAL_TOKEN
printf '\n'
if ! printf '%s' "${INITIAL_TOKEN}" | kubectl exec -i -n "${NAMESPACE}" "${POD}" -- \
  env HOME="${REMOTE_HOME}" \
    BAO_ADDR="${REMOTE_ADDR}" \
    BAO_CACERT="${REMOTE_CA}" \
    bao login -no-print -; then
  unset INITIAL_TOKEN
  echo "OpenBao login failed; no credentials were stored." >&2
  exit 1
fi
unset INITIAL_TOKEN

BAO_ADDR="${REMOTE_ADDR}" BAO_CACERT="${REMOTE_CA}" \
  bash "${SCRIPT_DIR}/configure-kubernetes-auth.sh"
BAO_ADDR="${REMOTE_ADDR}" BAO_CACERT="${REMOTE_CA}" \
  bash "${SCRIPT_DIR}/configure-vaultwarden-plugin.sh"

echo "Vaultwarden connection and PostgreSQL password sync are configured."
echo "The temporary OpenBao CLI token cache is removed when this script exits."
