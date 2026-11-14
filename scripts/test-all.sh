#!/usr/bin/env bash
#
# Root test runner for OpenDirectory.
#
# This is intentionally NOT a fake "echo green" — it actually delegates to the
# per-service and frontend test suites and fails (non-zero exit) if any of the
# GATING suites fail. It mirrors the gating set enforced by the
# `service-tests` job in .github/workflows/ci.yml.
#
# GATING suites (must pass): these are verified green. As of the 2026-08-03
#   wiring pass every suite that is wired up at all is gating — NON_GATING is
#   currently empty. It is kept as an array (not deleted) because it is the
#   documented escape hatch for a future suite that verifies red/flaky: such
#   a suite goes here with a comment explaining why, never silently omitted.
# NON-GATING suites (reported but do not fail the run): would be red/fragile
#   suites, see the CI workflow comments for the reason each is quarantined.
#
# Usage:
#   npm test                 # run gating suites (fails on any gating failure)
#   INCLUDE_NON_GATING=1 npm test   # also run the quarantined suites (reported)
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# service_dir | invocation
GATING=(
  "packages/grpc-event-bus|npm test -- --runInBand"
  "services/core/device-service|npm test -- --forceExit"
  "services/core/conditional-access|npm test -- --forceExit"
  "services/core/api-gateway|npm test -- --forceExit"
  "services/core/printer-service|npm test -- --forceExit"
  "services/core/samba-ad-dc|npm test"
  "services/platform/api-backend|npm test -- --forceExit"
  "services/platform/api-gateway|npm test -- --forceExit"
  "services/core/apple-mdm|npm test"
  "services/core/certificate-authority|npm test -- --forceExit"
  "services/core/identity-service|npm test -- --forceExit"
  "services/core/identity-service|npm run test:groups:integration"
  "services/core/kerberos-kdc|npm test"
  "services/core/least-privilege|npm test -- --forceExit"
  "services/core/network-infrastructure|npm test -- --forceExit"
  "services/core/oauth-provider|npm test -- --forceExit"
  "services/core/oauth-provider|npm run test:revocations:integration"
  "frontend/web-app|npm run test:browser-auth"
  "services/core/oauth-provider|npm run test:browser:integration"
  "services/platform/integration-service|npm test -- --forceExit"
  "services/enterprise/antivirus-protection|npm test -- --forceExit"
  "services/enterprise/app-store|npm test -- --forceExit"
  "services/enterprise/auto-remediation|npm test -- --forceExit"
  "services/enterprise/device-lifecycle|npm test -- --forceExit"
  "services/enterprise/graph-explorer|npm test -- --forceExit"
  "services/enterprise/policy-simulator|npm test -- --forceExit"
  "services/enterprise/security-scanner|npm test -- --forceExit"
  "services/enterprise/compliance-engine|npm test -- --forceExit"
  "services/core/monitoring-service|npm test -- --forceExit"
  "services/core/policy-service|npm test -- --forceExit"
  "services/core/license-management|npm test"
  "services/core/policy-service|npm run test:licenses:integration"
  "services/platform/quick-actions|npm test -- --forceExit"
  "services/core/authentication-service|npm test -- --forceExit"
  "frontend/web-app|npm test"
  "frontend/web-app|npm run test:e2e"
)

NON_GATING=(
)

export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}"
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD="${PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD:-1}"

failed=0
run_suite() {
  local spec="$1" gating="$2"
  local dir="${spec%%|*}"
  local cmd="${spec#*|}"
  echo ""
  echo "=================================================================="
  echo ">>> ($([ "$gating" = 1 ] && echo GATING || echo non-gating)) $dir : $cmd"
  echo "=================================================================="
  if [ ! -f "$dir/package.json" ]; then
    echo "::error:: missing $dir/package.json"
    [ "$gating" = 1 ] && failed=1
    return
  fi
  (
    cd "$dir" || exit 1
    if [ -f package-lock.json ]; then
      npm ci --ignore-scripts --no-audit --no-fund || exit 1
    else
      npm install --ignore-scripts --no-audit --no-fund --package-lock=false || exit 1
    fi
    eval "$cmd"
  )
  local rc=$?
  if [ $rc -ne 0 ]; then
    echo "RESULT: $dir FAILED (exit $rc)"
    [ "$gating" = 1 ] && failed=1
  else
    echo "RESULT: $dir passed"
  fi
}

npm run test:automation-client || failed=1
for s in "${GATING[@]}"; do run_suite "$s" 1; done

if [ "${INCLUDE_NON_GATING:-0}" = "1" ]; then
  for s in "${NON_GATING[@]}"; do run_suite "$s" 0; done
fi

echo ""
if [ "$failed" -ne 0 ]; then
  echo "TEST RUN FAILED: one or more gating suites failed."
  exit 1
fi
echo "TEST RUN PASSED: all gating suites green."
