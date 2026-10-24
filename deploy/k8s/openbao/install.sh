#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

kubectl create namespace openbao --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${DEPLOY_DIR}/k8s/openbao/certificate.yaml"
kubectl apply -f "${DEPLOY_DIR}/k8s/openbao/auth-rbac.yaml"
kubectl wait --for=condition=Ready certificate/openbao-server -n openbao --timeout=180s
"${DEPLOY_DIR}/k8s/openbao/prepare-vaultwarden-tls.sh"

helm repo add openbao https://openbao.github.io/openbao-helm --force-update
helm repo update openbao
helm upgrade --install openbao openbao/openbao \
  --version 0.30.4 \
  --namespace openbao \
  --create-namespace \
  --values "${DEPLOY_DIR}/helm/openbao/values.k3s.yaml"

kubectl get pods,pvc,svc -n openbao
