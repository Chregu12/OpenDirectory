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
  "services/core/device-service|npm test -- --passWithNoTests --forceExit"
  "services/core/conditional-access|npm test -- --passWithNoTests --forceExit"
  "services/core/api-gateway|npm test -- --passWithNoTests --forceExit"
  "services/core/printer-service|npm test -- --passWithNoTests --forceExit"
  "services/core/samba-ad-dc|npm test"
  "services/platform/api-backend|npm test -- --passWithNoTests --forceExit"
  "services/platform/api-gateway|npm test -- --passWithNoTests --forceExit"
  "services/core/apple-mdm|npm test"
  "services/core/certificate-authority|npm test -- --passWithNoTests --forceExit"
  "services/core/identity-service|npm test -- --passWithNoTests --forceExit"
  "services/core/kerberos-kdc|npm test"
  "services/core/least-privilege|npm test -- --passWithNoTests --forceExit"
  "services/core/network-infrastructure|npm test -- --passWithNoTests --forceExit"
  "services/core/oauth-provider|npm test -- --passWithNoTests --forceExit"
  "services/platform/integration-service|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/antivirus-protection|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/app-store|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/auto-remediation|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/device-lifecycle|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/graph-explorer|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/policy-simulator|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/security-scanner|npm test -- --passWithNoTests --forceExit"
  "services/enterprise/compliance-engine|npm test -- --passWithNoTests --forceExit"
  "services/core/monitoring-service|npm test -- --passWithNoTests --forceExit"
  "services/core/policy-service|npm test -- --passWithNoTests --forceExit"
  "services/platform/quick-actions|npm test -- --passWithNoTests --forceExit"
  "services/core/authentication-service|npm test -- --passWithNoTests --forceExit"
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
  ( cd "$dir" && npm install --ignore-scripts >/dev/null 2>&1 || npm ci >/dev/null 2>&1; eval "$cmd" )
  local rc=$?
  if [ $rc -ne 0 ]; then
    echo "RESULT: $dir FAILED (exit $rc)"
    [ "$gating" = 1 ] && failed=1
  else
    echo "RESULT: $dir passed"
  fi
}

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
