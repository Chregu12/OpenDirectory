#!/usr/bin/env bash
set -euo pipefail

registry="${1:-harbor.heusser.local/opendirectory}"
tag="${2:-1.0.0}"
platform="${TARGET_PLATFORM:-linux/amd64}"
registry_host="${registry%%/*}"
: "${HARBOR_USERNAME:?Set HARBOR_USERNAME through your Secret Manager}"
: "${HARBOR_PASSWORD:?Set HARBOR_PASSWORD through your Secret Manager}"

docker_config="$(mktemp -d)"
chmod 700 "$docker_config"
cleanup() {
  DOCKER_CONFIG="$docker_config" docker logout "$registry_host" >/dev/null 2>&1 || true
  rm -rf "$docker_config"
}
trap cleanup EXIT

printf '%s' "$HARBOR_PASSWORD" | DOCKER_CONFIG="$docker_config" docker login "$registry_host" \
  --username "$HARBOR_USERNAME" --password-stdin >/dev/null

build_push() {
  local name="$1" dockerfile="$2" context="$3"
  local image="$registry/$name:$tag"
  DOCKER_CONFIG="$docker_config" docker buildx build --platform "$platform" --file "$dockerfile" \
    --tag "$image" --load "$context"
  DOCKER_CONFIG="$docker_config" docker push "$image"
}

build_push identity-service services/core/identity-service/Dockerfile .
build_push auth-service services/core/authentication-service/Dockerfile .
build_push device-service services/core/device-service/Dockerfile .
build_push policy-service services/core/policy-service/Dockerfile .
build_push oauth-provider services/core/oauth-provider/Dockerfile .
build_push integration-service services/platform/integration-service/Dockerfile services/platform/integration-service
build_push api-gateway services/platform/api-gateway/Dockerfile services/platform/api-gateway
build_push api-backend services/platform/api-backend/Dockerfile services/platform/api-backend
build_push license-management services/core/license-management/Dockerfile services/core/license-management
build_push web-app frontend/web-app/Dockerfile .

printf 'Published OpenDirectory images to %s with tag %s.\n' "$registry" "$tag"
