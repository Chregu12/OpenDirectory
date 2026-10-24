#!/usr/bin/env bash
set -euo pipefail

OPENBAO_NAMESPACE="${OPENBAO_NAMESPACE:-openbao}"
BITWARDEN_NAMESPACE="${BITWARDEN_NAMESPACE:-bitwarden}"
BITWARDEN_INGRESS="${BITWARDEN_INGRESS:-vaultwarden}"
CERT_NAME="${BITWARDEN_CERT_NAME:-bitwarden-tls}"
CA_NAMESPACE="${HOMELAB_CA_NAMESPACE:-cert-manager}"
CA_SECRET="${HOMELAB_CA_SECRET:-homelab-ca-key-pair}"
CA_ISSUER="${HOMELAB_CA_ISSUER:-homelab-ca-issuer}"
CA_CONFIGMAP="${OPENBAO_CA_CONFIGMAP:-openbao-trust-ca}"

for command in kubectl openssl python3; do
  command -v "${command}" >/dev/null || {
    echo "Required command not found: ${command}" >&2
    exit 1
  }
done

issuer="$(kubectl get ingress "${BITWARDEN_INGRESS}" -n "${BITWARDEN_NAMESPACE}" -o json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["metadata"]["annotations"].get("cert-manager.io/cluster-issuer", ""))')"
if [[ "${issuer}" != "${CA_ISSUER}" ]]; then
  kubectl patch ingress "${BITWARDEN_INGRESS}" -n "${BITWARDEN_NAMESPACE}" \
    --type=merge \
    --patch "{\"metadata\":{\"annotations\":{\"cert-manager.io/cluster-issuer\":\"${CA_ISSUER}\"}}}"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

ready=false
for _ in $(seq 1 60); do
  state="$(kubectl get certificate "${CERT_NAME}" -n "${BITWARDEN_NAMESPACE}" \
    -o jsonpath='{.metadata.generation}{" "}{.status.conditions[?(@.type=="Ready")].observedGeneration}{" "}{.status.conditions[?(@.type=="Ready")].status}')"
  read -r generation observed_generation condition <<<"${state}"
  if [[ "${condition:-}" == "True" && "${generation:-}" == "${observed_generation:-}" ]]; then
    kubectl get secret "${CERT_NAME}" -n "${BITWARDEN_NAMESPACE}" \
      -o jsonpath='{.data.tls\.crt}' \
      | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read()))' \
      > "${tmpdir}/bitwarden.crt"
    if openssl x509 -in "${tmpdir}/bitwarden.crt" -noout -issuer | grep -Fq 'CN=Heusser Homelab CA'; then
      ready=true
      break
    fi
  fi
  sleep 5
done

if [[ "${ready}" != true ]]; then
  echo "Certificate ${BITWARDEN_NAMESPACE}/${CERT_NAME} is not ready from ${CA_ISSUER}." >&2
  exit 1
fi

kubectl get secret "${CA_SECRET}" -n "${CA_NAMESPACE}" \
  -o jsonpath='{.data.tls\.crt}' \
  | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read()))' \
  > "${tmpdir}/homelab-ca.crt"

kubectl create configmap "${CA_CONFIGMAP}" -n "${OPENBAO_NAMESPACE}" \
  --from-file=homelab-ca.crt="${tmpdir}/homelab-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Synced the public homelab CA certificate to ${OPENBAO_NAMESPACE}/${CA_CONFIGMAP}."
