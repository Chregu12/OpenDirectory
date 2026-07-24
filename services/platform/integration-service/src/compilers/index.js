'use strict';
// =============================================================================
// OpenDirectory — Policy Compiler (Dispatcher)
//
// Thin re-export shim: delegates to the shared @opendirectory/policy-compilers
// package (see packages/policy-compilers/src) instead of maintaining a local
// copy of the Windows/macOS/Linux/NetworkDrives/Printers compilers here.
//
// Same require-with-fallback pattern used by policy-service
// (services/core/policy-service/src/index.js) and enterprise-directory
// (services/core/enterprise-directory/src/policies/{groupPolicyEngine,printerPolicy}.js):
// prefer the workspace package resolution, fall back to a relative require so
// this still works in a service-only Docker build context where the package
// isn't installed as a node_modules dependency.
// =============================================================================
let policyCompilers;
try {
  policyCompilers = require('@opendirectory/policy-compilers');
} catch (_) {
  policyCompilers = require('../../../../../packages/policy-compilers/src');
}

const {
  compile,
  compileWindows,
  compileLinux,
  compileMacOS,
  compileNetworkDrives,
  compilePrinters,
} = policyCompilers;

module.exports = { compile, compileWindows, compileLinux, compileMacOS, compileNetworkDrives, compilePrinters };
